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
	GetFileNames() ([]string, error)
	GetSubDirectory(string) Directory
	GetDecryptedName() string
	GetCryptomatorVault() CryptomatorVault
	Print()
	CreateFile(filename string) (File, error)
	GetFile(index int) (File, error)

	updateDirectory()
}

type BaseDirectory struct {
	CryptomatorFileOrDir

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

func (dir BaseDirectory) GetFile(index int) (File, error) {
	return dir.files[index], nil
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
		fmt.Printf("F\t%s\n", file.GetDecryptedName())
	}
}

// CreateFile creates a file an empty file in the directory and writes out the header in Cryptomator's format.
func (dir *LocalDirectory) CreateFile(filename string) (File, error) {
	encryptedFilename, err := dir.GetCryptomatorVault().EncryptFilename(filename, dir.uuid)
	if err != nil {
		return nil, err
	}

	//fmt.Printf("Encrypted filename: %s\n", encryptedFilename)
	//fmt.Printf("Encrypted path: %s\n", filepath.Join(dir.encryptedPath, encryptedFilename))

	var file LocalFile
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

	return File(&file), nil
}

func (dir LocalDirectory) GetFileNames() ([]string, error) {
	var filenames []string
	files, err := ioutil.ReadDir(dir.encryptedPath)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		filenames = append(filenames, f.Name())
	}

	return filenames, nil
}

func (dir *LocalDirectory) updateDirectory() {

	log.Printf("Updating directory %s \n", dir.encryptedPath)
	log.Printf("UUID %s\n", dir.uuid)

	filenames, err := dir.GetFileNames()
	if err != nil {
		log.Fatal(err)
	}

	for _, filename := range filenames {
		if filename[0] == '0' {
			var subDir LocalDirectory

			decrypted, err := dir.crypto.DecryptFilename(filename[1:], dir.uuid)
			if err != nil {
				fmt.Println(err)
			}

			b, err := ioutil.ReadFile(filepath.Join(dir.encryptedPath, filename)) // just pass the file name
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
			var file LocalFile

			decrypted, err := dir.crypto.DecryptFilename(filename, dir.uuid)
			if err != nil {
				fmt.Println(err)
			}

			file.crypto = dir.crypto
			file.decryptedPath = filepath.Join(dir.decryptedPath, decrypted)
			file.decryptedName = decrypted
			file.encryptedPath = filepath.Join(dir.encryptedPath, filename)

			dir.files = append(dir.files, file)
		}
	}

	//return dir
}
