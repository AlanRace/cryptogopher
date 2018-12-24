package cryptogopher

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type S3Vault struct {
	BaseCryptomatorVault

	svc    *s3.S3
	bucket string
}

type S3Directory struct {
	BaseDirectory

	crypto *S3Vault
}

// GetRootDirectory returns the root directory of the vault
func (crypto S3Vault) GetRootDirectory() Directory {
	var dir S3Directory

	dir.crypto = &crypto
	dir.decryptedPath = ""
	dir.uuid = ""
	dir.encryptedPath = crypto.getFilePath(dir.uuid)

	dir.updateDirectory()

	return Directory(&dir)
}

func (dir S3Directory) ReadDir() ([]os.FileInfo, error) {
	return ioutil.ReadDir(dir.encryptedPath)
}

func (dir *S3Directory) updateDirectory() {

	log.Printf("Updating S3 directory %s \n", dir.encryptedPath)
	log.Printf("UUID %s\n", dir.uuid)

	files, err := ioutil.ReadDir(dir.encryptedPath)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if f.Name()[0] == '0' {
			var subDir S3Directory

			decrypted, err := dir.crypto.DecryptFilename(f.Name()[1:], dir.uuid)
			if err != nil {
				fmt.Println(err)
			}

			b, err := ioutil.ReadFile(filepath.Join(dir.encryptedPath, f.Name())) // just pass the file name
			if err != nil {
				fmt.Print(err)
			}

			subDir.crypto = dir.crypto
			subDir.decryptedPath = filepath.Join(dir.decryptedPath, decrypted)
			subDir.decryptedName = decrypted
			subDir.uuid = string(b) // convert content to a 'string'
			subDir.encryptedPath = dir.crypto.getFilePath(subDir.uuid)

			dir.dirs = append(dir.dirs, &subDir)
		} else {
			var file File

			decrypted, err := dir.crypto.DecryptFilename(f.Name(), dir.uuid)
			if err != nil {
				fmt.Println(err)
			}

			file.crypto = dir.crypto
			file.decryptedPath = filepath.Join(dir.decryptedPath, decrypted)
			file.decryptedName = decrypted
			file.encryptedPath = filepath.Join(dir.encryptedPath, f.Name())

			dir.files = append(dir.files, file)
		}
	}

	//return dir
}

func OpenS3(sess *session.Session, bucket string, vaultLocation string, password string) (*S3Vault, error) {
	var vault S3Vault
	//vault.svc = svc
	vault.bucket = bucket
	vault.vaultLocation = vaultLocation

	// Create a new instance of the service's client with a Session.
	// Optional aws.Config values can also be provided as variadic arguments
	// to the New function. This option allows you to provide service
	// specific configuration.
	svc := s3.New(sess)

	input := &s3.ListObjectsInput{
		Bucket:    aws.String(vault.bucket),
		Prefix:    aws.String(vaultLocation + "masterkey.cryptomator"),
		Delimiter: aws.String("/"),
	}

	result, err := svc.ListObjects(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchBucket:
				fmt.Println(s3.ErrCodeNoSuchBucket, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}

		return nil, err
	}

	fmt.Println(result.Contents[0].Key)

	file, err := os.Create("masterkey.cryptomator")
	if err != nil {
		fmt.Println("Unable to open file %q, %v", err)
	}

	defer file.Close()

	downloader := s3manager.NewDownloader(sess)

	numBytes, err := downloader.Download(file,
		&s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(*result.Contents[0].Key),
		})
	if err != nil {
		fmt.Println("Unable to download item %q, %v", result.Contents[0].Key, err)
	}

	fmt.Println("Downloaded", file.Name(), numBytes, "bytes")

	// Open our jsonFile
	jsonFile, err := os.Open("masterkey.cryptomator")
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var masterKey masterKeyFile
	json.Unmarshal([]byte(byteValue), &masterKey)

	vault.vaultLocation = vaultLocation
	vault.setMasterKeyFile(&masterKey, password)

	return &vault, nil
}

func (dir S3Directory) GetCryptomatorVault() CryptomatorVault {
	return CryptomatorVault(dir.crypto)
}

// CreateFile creates a file an empty file in the directory and writes out the header in Cryptomator's format.
func (dir *S3Directory) CreateFile(filename string) (*File, error) {
	encryptedFilename, err := dir.GetCryptomatorVault().EncryptFilename(filename, dir.uuid)
	if err != nil {
		return nil, err
	}

	//fmt.Printf("Encrypted filename: %s\n", encryptedFilename)
	//fmt.Printf("Encrypted path: %s\n", filepath.Join(dir.encryptedPath, encryptedFilename))

	var file File
	file.crypto = dir.crypto
	file.decryptedName = filename
	file.decryptedPath = filepath.Join(dir.decryptedPath, filename)
	file.encryptedPath = filepath.Join(dir.encryptedPath, encryptedFilename)

	file.nonce, err = GenerateRandomBytes(NonceSize)
	if err != nil {
		return nil, err
	}

	file.contentKey, err = GenerateRandomBytes(FileKeySize)
	if err != nil {
		return nil, err
	}

	file.writeHeader()

	dir.files = append(dir.files, file)

	return &file, nil
}
