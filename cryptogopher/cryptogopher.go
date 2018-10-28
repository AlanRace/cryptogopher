package cryptogopher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	keywrap "github.com/NickBall/go-aes-key-wrap"
	miscreant "github.com/miscreant/miscreant-go"
	"golang.org/x/crypto/scrypt"
)

type MasterKeyFile struct {
	ScryptSalt       []byte `json:"scryptSalt"`
	ScryptCostParam  int    `json:"scryptCostParam"`
	ScryptBlockSize  int
	PrimaryMasterKey []byte
	HmacMasterKey    []byte
	VersionMac       []byte
	Version          int
}

type Cryptomator struct {
	vaultLocation string
	masterKeyFile *MasterKeyFile

	primaryKey []byte
	macKey     []byte
	aessiv     *miscreant.Cipher
}

// Random generation taken from https://blog.questionable.services/article/generating-secure-random-numbers-crypto-rand/

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString returns a URL-safe, base64 encoded
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

func Open(vaultLocation string, password string) (*Cryptomator, error) {
	masterKeyFilename := "masterkey.cryptomator"

	masterKeyFileLocation := filepath.Join(vaultLocation, masterKeyFilename)

	// Open our jsonFile
	jsonFile, err := os.Open(masterKeyFileLocation)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var masterKey MasterKeyFile
	json.Unmarshal([]byte(byteValue), &masterKey)

	var crypto Cryptomator
	crypto.masterKeyFile = &masterKey

	dk, err := scrypt.Key([]byte(password), masterKey.ScryptSalt, masterKey.ScryptCostParam, masterKey.ScryptBlockSize, 1, 32)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Println("KEK: " + base64.StdEncoding.EncodeToString(dk))

	cypher, err := aes.NewCipher(dk)
	if err != nil {
		fmt.Println(err)
	}

	primaryMasterKey, err := keywrap.Unwrap(cypher, masterKey.PrimaryMasterKey)
	if err != nil {
		fmt.Println(err)
	}

	macKey, err := keywrap.Unwrap(cypher, masterKey.HmacMasterKey)
	if err != nil {
		fmt.Println(err)
	}

	//fmt.Println("MAC: " + base64.StdEncoding.EncodeToString(macKey))
	//fmt.Println("ENC: " + base64.StdEncoding.EncodeToString(primaryMasterKey))

	//fmt.Println(len(macKey))

	// Create a new cipher.AEAD instance
	//c := miscreant.newAEAD("AES-SIV", primaryMasterKey, 16)
	aessiv, err := miscreant.NewAESCMACSIV(append(macKey, primaryMasterKey...))
	if err != nil {
		fmt.Println(err)
	}

	crypto.vaultLocation = vaultLocation
	crypto.primaryKey = primaryMasterKey
	crypto.macKey = macKey
	crypto.aessiv = aessiv

	return &crypto, nil
}

func (crypto Cryptomator) DecryptFilename(encrypted string, directory string) (string, error) {
	folderEncoded, err := base32.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	folderDecoded, err := crypto.aessiv.Open(nil, folderEncoded, []byte(directory))
	if err != nil {
		return "", err
	}

	return string(folderDecoded), nil
}

func (crypto Cryptomator) EncryptFilename(plaintext string, directory string) (string, error) {
	folderEncoded, err := crypto.aessiv.Seal(nil, []byte(plaintext), []byte(directory))
	if err != nil {
		return "", err
	}

	return base32.StdEncoding.EncodeToString(folderEncoded), nil
}

func (crypto Cryptomator) HashDirectoryId(directory string) string {
	decoded, err := crypto.aessiv.Seal(nil, []byte(directory))
	if err != nil {
		fmt.Println(err)
	}

	hashedBytes := sha1.Sum(decoded)

	return base32.StdEncoding.EncodeToString(hashedBytes[:])
}

func (crypto Cryptomator) getFilePath(directory string) string {
	hash := crypto.HashDirectoryId(directory)

	return filepath.Join(crypto.vaultLocation, "d", hash[:2], hash[2:])
}

type FileOrDirectory interface {
	GetEncryptedPath() string
}

type File struct {
	crypto        *Cryptomator
	encryptedPath string
	decryptedPath string
	decryptedName string

	nonce      []byte
	contentKey []byte
}

func (file *File) processHeader() error {
	// Open our jsonFile
	f, err := os.Open(file.encryptedPath)
	// if we os.Open returns an error then handle it
	if err != nil {
		return err
	}
	defer f.Close()

	headerBytes := make([]byte, 88)

	_, err = f.Read(headerBytes)
	if err != nil {
		return err
	}

	file.nonce = headerBytes[:16]
	encryptedPayload := headerBytes[16:56]
	//headerMAC := byteValue[56:88]

	block, err := aes.NewCipher(file.crypto.primaryKey)
	if err != nil {
		panic(err)
	}

	decryptedPayload := decrypt(block, encryptedPayload, file.nonce)
	file.contentKey = decryptedPayload[8:]

	fmt.Println(hex.EncodeToString(file.contentKey))

	return nil
}

const NonceSize = 16
const FileKeySize = 32
const MACSize = 32
const HeaderSize = 88
const ChunkSize = 32 * 1024
const EncryptedChunkSize int64 = ChunkSize + NonceSize + MACSize

func (file File) GetNumChunks() int64 {
	fileInfo, e := os.Stat(file.encryptedPath)
	if e != nil {
		// TODO: Handle error
		fmt.Println(e)
	}

	log.Printf("File size: %d\n", fileInfo.Size())
	payloadSize := fileInfo.Size() - HeaderSize

	numChunks := payloadSize / EncryptedChunkSize

	if numChunks*EncryptedChunkSize < payloadSize {
		numChunks++
	}

	return numChunks
}

func (file File) ReadChunk(chunkIndex int64) ([]byte, error) {
	if chunkIndex >= file.GetNumChunks() {
		return nil, errors.New("Invalid chunkIndex")
	}

	if file.contentKey == nil {
		file.processHeader()
	}

	// Save fileBlock as part of
	fileBlock, err := aes.NewCipher(file.contentKey)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(file.encryptedPath)
	// if we os.Open returns an error then handle it
	if err != nil {
		return nil, err
	}
	defer f.Close()

	chunkOffset := HeaderSize + chunkIndex*EncryptedChunkSize

	log.Printf("Chunk offset: %d\n", chunkOffset)

	_, err = f.Seek(chunkOffset, io.SeekStart)
	if err != nil {
		return nil, err
	}

	chunk := make([]byte, EncryptedChunkSize)
	numRead, err := f.Read(chunk)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Read %d\n", numRead)

	chunkNonce := chunk[:16]
	payload := chunk[16 : numRead-32]
	mac := chunk[numRead-32 : numRead]
	file.checkMAC(mac, chunkNonce, payload, chunkIndex)

	decryptedBlock := decrypt(fileBlock, payload, chunkNonce)

	return decryptedBlock, nil
}

func (file File) checkMAC(macBytes, nonce, payload []byte, chunkNumber int64) {
	mac := hmac.New(sha256.New, file.crypto.macKey)

	var macBuffer bytes.Buffer

	mac.Write(file.nonce)
	binary.Write(&macBuffer, binary.BigEndian, chunkNumber)
	mac.Write(macBuffer.Bytes())
	mac.Write(nonce)
	mac.Write(payload)
	//mac.Write(file.crypto.macKey)

	calculatedMAC := mac.Sum(nil)

	log.Printf("MAC Size: %d\n", len(macBytes))
	log.Printf("Expected:   %s\n", base64.StdEncoding.EncodeToString(macBytes))
	log.Printf("Calculated: %s\n", base64.StdEncoding.EncodeToString(calculatedMAC))

}

func (file File) GetEncryptedPath() string {
	return file.encryptedPath
}

type Directory struct {
	File
	uuid  string
	dirs  []Directory
	files []File
}

func (dir *Directory) GetSubDirectory(path string) *Directory {
	pathParts := strings.Split(path, string(os.PathSeparator))

	for index, subDir := range dir.dirs {
		if subDir.decryptedName == pathParts[0] {
			dir.dirs[index].updateDirectory()

			if len(pathParts) > 1 {
				return dir.dirs[index].GetSubDirectory(filepath.Join(pathParts[1:]...))
			} else {
				return &dir.dirs[index]
			}
		}
	}

	return nil
}

func (crypto Cryptomator) GetRootDirectory() Directory {
	var dir Directory

	dir.crypto = &crypto
	dir.decryptedPath = ""
	dir.uuid = ""
	dir.encryptedPath = crypto.getFilePath(dir.uuid)

	dir.updateDirectory()

	return dir
}

func (dir Directory) Print() {
	fmt.Println(dir.decryptedPath)

	for _, dir := range dir.dirs {
		fmt.Printf("D\t%s\n", dir.decryptedName)
	}

	for _, file := range dir.files {
		fmt.Printf("F\t%s\n", file.decryptedName)
	}
}

func (file *File) writeHeader() error {
	f, err := os.Create(file.encryptedPath)
	defer f.Close()
	if err != nil {
		return err
	}

	var header bytes.Buffer
	payloadBuffer := make([]byte, 40)

	binary.Write(&header, binary.LittleEndian, file.nonce)

	block, err := aes.NewCipher(file.crypto.primaryKey)
	if err != nil {
		panic(err)
	}

	for i := 0; i < 8; i++ {
		payloadBuffer[i] = 255
	}
	copy(payloadBuffer[8:], file.contentKey)

	fmt.Println(base64.StdEncoding.EncodeToString(payloadBuffer))

	encryptedPayload := encrypt(block, payloadBuffer, file.nonce)

	fmt.Println(base64.StdEncoding.EncodeToString(encryptedPayload))
	fmt.Printf("Encrypted payload size %d\n", len(encryptedPayload))

	binary.Write(&header, binary.LittleEndian, encryptedPayload)

	mac := hmac.New(sha256.New, file.crypto.macKey)
	mac.Write(header.Bytes())
	calculatedMAC := mac.Sum(nil)

	binary.Write(&header, binary.LittleEndian, calculatedMAC)

	_, err = f.Write(header.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

func (file File) WriteChunk(data []byte, chunkIndex int64) error {
	f, err := os.OpenFile(file.encryptedPath, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	defer f.Close()
	if err != nil {
		return err
	}

	// Save fileBlock as part of
	fileBlock, err := aes.NewCipher(file.contentKey)
	if err != nil {
		return err
	}

	nonce, err := GenerateRandomBytes(NonceSize)
	if err != nil {
		return err
	}

	var payload bytes.Buffer
	var macBuffer bytes.Buffer

	binary.Write(&payload, binary.LittleEndian, nonce)

	encryptedPayload := encrypt(fileBlock, []byte(data), nonce)

	binary.Write(&payload, binary.LittleEndian, encryptedPayload)

	mac := hmac.New(sha256.New, file.crypto.macKey)

	mac.Write(file.nonce)
	binary.Write(&macBuffer, binary.BigEndian, chunkIndex)
	mac.Write(macBuffer.Bytes())
	mac.Write(nonce)
	mac.Write(encryptedPayload)

	calculatedMAC := mac.Sum(nil)

	binary.Write(&payload, binary.LittleEndian, calculatedMAC)

	_, err = f.Write(payload.Bytes())
	if err != nil {
		return err
	}

	return nil
}

func (dir *Directory) CreateFile(filename string) (*File, error) {
	fmt.Printf("%s\n", filename)

	encryptedFilename, err := dir.crypto.EncryptFilename(filename, dir.uuid)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Encrypted filename: %s\n", encryptedFilename)
	fmt.Printf("Encrypted path: %s\n", filepath.Join(dir.encryptedPath, encryptedFilename))

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

func (dir *Directory) updateDirectory() {

	//log.Printf("Updating directory %s \n", dir.encryptedPath)
	//log.Printf("UUID %s\n", dir.uuid)

	files, err := ioutil.ReadDir(dir.encryptedPath)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if f.Name()[0] == '0' {
			var subDir Directory

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

			dir.dirs = append(dir.dirs, subDir)
			fmt.Println(subDir)
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
			fmt.Println(decrypted)
		}
	}

	//return dir
}

func (crypto Cryptomator) ListFiles(directory string) {
	// TODO: Split directory and read in files to find correct location

	files, err := ioutil.ReadDir(crypto.getFilePath(directory))
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if f.Name()[0] == '0' {
			decrypted, err := crypto.DecryptFilename(f.Name()[1:], directory)
			if err != nil {
				fmt.Println(err)
			}

			fmt.Println(decrypted + "/")
		} else {
			decrypted, err := crypto.DecryptFilename(f.Name(), directory)
			if err != nil {
				fmt.Println(err)
			}

			fmt.Println(decrypted)
		}
	}
}

// encrypt / decrypt taken from here https://stackoverflow.com/questions/7263928/decrypt-using-the-ctr-mode

func encrypt(block cipher.Block, value []byte, iv []byte) []byte {
	//encrypted := make([]byte, len(value)+block.BlockSize())
	//encrypted = append(encrypted, iv...)
	encrypted := make([]byte, len(value))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(encrypted, value)
	return encrypted
}

func decrypt(block cipher.Block, ciphertext []byte, iv []byte) []byte {
	stream := cipher.NewCTR(block, iv)
	plain := make([]byte, len(ciphertext))
	// XORKeyStream is used to decrypt too!
	stream.XORKeyStream(plain, ciphertext)
	return plain
}
