package cryptogopher

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type S3Vault struct {
	CryptomatorVault

	svc    *s3.S3
	bucket string
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
