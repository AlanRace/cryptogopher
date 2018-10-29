package cryptogopher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	keywrap "github.com/NickBall/go-aes-key-wrap"
	miscreant "github.com/miscreant/miscreant-go"
	"golang.org/x/crypto/scrypt"
)

// NonceSize is the size of the nonces.
const NonceSize = 16

// FileKeySize is the size of the file content key.
const FileKeySize = 32

// MACSize is the size of the message authentication code
const MACSize = 32

// HeaderSize if the size of the header in each file
const HeaderSize = 88

// ChunkSize is the size of a file chunk in bytes
const ChunkSize = 32 * 1024

// EncryptedChunkSize is the size of the chunk after encryption (including nonce and message authentication code)
const EncryptedChunkSize int64 = ChunkSize + NonceSize + MACSize

// masterKeyFilename is the default filename for the masterkey file
const masterKeyFilename = "masterkey.cryptomator"

// Structure containing data imported from masterKeyFile
type masterKeyFile struct {
	ScryptSalt       []byte `json:"scryptSalt"`
	ScryptCostParam  int    `json:"scryptCostParam"`
	ScryptBlockSize  int
	PrimaryMasterKey []byte
	HmacMasterKey    []byte
	VersionMac       []byte
	Version          int
}

// CryptomatorFile is a file in a cryptomator vault. This could either be a real file, or a directory
type CryptomatorFile struct {
	crypto        *CryptomatorVault
	encryptedPath string
	decryptedPath string
	decryptedName string
}

// CryptomatorVault is a vault in the Cryptomator format
type CryptomatorVault struct {
	vaultLocation string
	masterKeyFile *masterKeyFile

	primaryKey []byte
	macKey     []byte
	aessiv     *miscreant.Cipher
}

// Open opens a Cryptomator vault
func Open(vaultLocation string, password string) (*CryptomatorVault, error) {
	masterKeyFileLocation := filepath.Join(vaultLocation, masterKeyFilename)

	// Open our jsonFile
	jsonFile, err := os.Open(masterKeyFileLocation)
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var masterKey masterKeyFile
	json.Unmarshal([]byte(byteValue), &masterKey)

	var crypto CryptomatorVault
	crypto.masterKeyFile = &masterKey

	dk, err := scrypt.Key([]byte(password), masterKey.ScryptSalt, masterKey.ScryptCostParam, masterKey.ScryptBlockSize, 1, 32)
	if err != nil {
		log.Fatal(err)
	}

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

// DecryptFilename decrypts a filename in the specified directory (directory UUID)
func (crypto CryptomatorVault) DecryptFilename(encrypted string, directory string) (string, error) {
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

// EncryptFilename encrypts a filename in the specified directory (directory UUID)
func (crypto CryptomatorVault) EncryptFilename(plaintext string, directory string) (string, error) {
	folderEncoded, err := crypto.aessiv.Seal(nil, []byte(plaintext), []byte(directory))
	if err != nil {
		return "", err
	}

	return base32.StdEncoding.EncodeToString(folderEncoded), nil
}

// HashDirectoryID performs hasing on directory (directory UUID)
func (crypto CryptomatorVault) HashDirectoryID(directory string) string {
	decoded, err := crypto.aessiv.Seal(nil, []byte(directory))
	if err != nil {
		fmt.Println(err)
	}

	hashedBytes := sha1.Sum(decoded)

	return base32.StdEncoding.EncodeToString(hashedBytes[:])
}

func (crypto CryptomatorVault) getFilePath(directory string) string {
	hash := crypto.HashDirectoryID(directory)

	return filepath.Join(crypto.vaultLocation, "d", hash[:2], hash[2:])
}

// GetRootDirectory returns the root directory of the vault
func (crypto CryptomatorVault) GetRootDirectory() Directory {
	var dir Directory

	dir.crypto = &crypto
	dir.decryptedPath = ""
	dir.uuid = ""
	dir.encryptedPath = crypto.getFilePath(dir.uuid)

	dir.updateDirectory()

	return dir
}

// GetEncryptedPath returns the encrypted version of the file path (the one as it appears on disk)
func (file CryptomatorFile) GetEncryptedPath() string {
	return file.encryptedPath
}

// encrypt / decrypt taken from here https://stackoverflow.com/questions/7263928/decrypt-using-the-ctr-mode

/*func encrypt(block cipher.Block, value []byte, iv []byte) []byte {
	encrypted := make([]byte, len(value))
	stream := cipher.NewCTR(block, iv)

	stream.XORKeyStream(encrypted, value)
	return encrypted
}*/

func applyCTR(block cipher.Block, ciphertext []byte, iv []byte) []byte {
	plain := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)

	stream.XORKeyStream(plain, ciphertext)
	return plain
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
