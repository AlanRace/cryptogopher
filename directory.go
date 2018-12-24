package cryptogopher

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Directory is a directory in a Cryptomator vault
type Directory interface {
	ReadDir() ([]os.FileInfo, error)
	GetSubDirectory(string) Directory
	GetDecryptedName() string
	GetCryptomatorVault() CryptomatorVault
	Print()
	CreateFile(filename string) (*File, error)

	updateDirectory()
}

type BaseDirectory struct {
	CryptomatorFile

	uuid  string
	dirs  []Directory
	files []File
}

type LocalDirectory struct {
	BaseDirectory

	crypto *LocalCryptomatorVault
}

func (dir LocalDirectory) GetCryptomatorVault() CryptomatorVault {
	return CryptomatorVault(dir.crypto)
}

func (dir BaseDirectory) GetDecryptedName() string {
	return dir.decryptedName
}

// GetSubDirectory returns a directory at the specified subpath
func (dir BaseDirectory) GetSubDirectory(path string) Directory {
	pathParts := strings.Split(path, string(os.PathSeparator))

	for index, subDir := range dir.dirs {
		if subDir.GetDecryptedName() == pathParts[0] {
			dir.dirs[index].updateDirectory()

			if len(pathParts) > 1 {
				return dir.dirs[index].GetSubDirectory(filepath.Join(pathParts[1:]...))
			}

			return dir.dirs[index]
		}
	}

	return nil
}

// Print prints the contents of the directory
func (dir BaseDirectory) Print() {
	//fmt.Println(dir.decryptedPath)

	for _, dir := range dir.dirs {
		fmt.Printf("D\t%s\n", dir.GetDecryptedName())
	}

	for _, file := range dir.files {
		fmt.Printf("F\t%s\n", file.decryptedName)
	}
}

// CreateFile creates a file an empty file in the directory and writes out the header in Cryptomator's format.
func (dir *LocalDirectory) CreateFile(filename string) (*File, error) {
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

func (dir LocalDirectory) ReadDir() ([]os.FileInfo, error) {
	return ioutil.ReadDir(dir.encryptedPath)
}

func (dir *LocalDirectory) updateDirectory() {

	log.Printf("Updating directory %s \n", dir.encryptedPath)
	log.Printf("UUID %s\n", dir.uuid)

	files, err := dir.ReadDir()
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if f.Name()[0] == '0' {
			var subDir LocalDirectory

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
