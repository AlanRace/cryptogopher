package cryptogopher

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

type File interface {
	GetNumChunks() int64
	GetDecryptedName() string
	ReadChunk(chunkIndex int64) ([]byte, error)
	WriteChunk(data []byte, chunkIndex int64) error
}

// File is a file stored within a Cryptomator vault
type BaseFile struct {
	CryptomatorFileOrDir

	nonce      []byte
	contentKey []byte
}

type LocalFile struct {
	BaseFile
}

func (file BaseFile) GetDecryptedName() string {
	return file.decryptedName
}

func (file *LocalFile) processHeader() error {
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

	block, err := aes.NewCipher(file.crypto.getPrimaryKey())
	if err != nil {
		panic(err)
	}

	decryptedPayload := applyCTR(block, encryptedPayload, file.nonce)
	file.contentKey = decryptedPayload[8:]

	// TODO: Check MAC

	fmt.Println(hex.EncodeToString(file.contentKey))

	return nil
}

// GetNumChunks returns the number of chunks that would make up this file
func (file LocalFile) GetNumChunks() int64 {
	fileInfo, e := os.Stat(file.encryptedPath)
	if e != nil {
		// TODO: Handle error
		fmt.Println(e)
	}

	//log.Printf("File size: %d\n", fileInfo.Size())
	payloadSize := fileInfo.Size() - HeaderSize

	numChunks := payloadSize / EncryptedChunkSize

	if numChunks*EncryptedChunkSize < payloadSize {
		numChunks++
	}

	return numChunks
}

// ReadChunk reads and decompresses the chunk at the specified index
func (file LocalFile) ReadChunk(chunkIndex int64) ([]byte, error) {
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
	if err != nil {
		return nil, err
	}
	defer f.Close()

	chunkOffset := HeaderSize + chunkIndex*EncryptedChunkSize

	//log.Printf("Chunk offset: %d\n", chunkOffset)

	_, err = f.Seek(chunkOffset, io.SeekStart)
	if err != nil {
		return nil, err
	}

	chunk := make([]byte, EncryptedChunkSize)
	numRead, err := f.Read(chunk)
	if err != nil {
		return nil, err
	}

	//fmt.Printf("Read %d\n", numRead)

	chunkNonce := chunk[:16]
	payload := chunk[16 : numRead-32]
	mac := chunk[numRead-32 : numRead]
	file.checkMAC(mac, chunkNonce, payload, chunkIndex)

	decryptedBlock := applyCTR(fileBlock, payload, chunkNonce)

	return decryptedBlock, nil
}

func (file BaseFile) checkMAC(macBytes, nonce, payload []byte, chunkNumber int64) error {
	mac := hmac.New(sha256.New, file.crypto.getMacKey())

	var macBuffer bytes.Buffer

	mac.Write(file.nonce)
	binary.Write(&macBuffer, binary.BigEndian, chunkNumber)
	mac.Write(macBuffer.Bytes())
	mac.Write(nonce)
	mac.Write(payload)
	//mac.Write(file.crypto.macKey)

	calculatedMAC := mac.Sum(nil)

	if !hmac.Equal(macBytes, calculatedMAC) {
		return errors.New("Invalid MAC")
	}

	//log.Printf("MAC Size: %d\n", len(macBytes))
	//log.Printf("Expected:   %s\n", base64.StdEncoding.EncodeToString(macBytes))
	//log.Printf("Calculated: %s\n", base64.StdEncoding.EncodeToString(calculatedMAC))

	return nil
}

// writeHeader creates necessary nonce and writes the Cryptomator header.
func (file *LocalFile) writeHeader() error {
	f, err := os.Create(file.encryptedPath)
	defer f.Close()
	if err != nil {
		return err
	}

	var header bytes.Buffer
	payloadBuffer := make([]byte, 40)

	binary.Write(&header, binary.LittleEndian, file.nonce)

	block, err := aes.NewCipher(file.crypto.getPrimaryKey())
	if err != nil {
		panic(err)
	}

	for i := 0; i < 8; i++ {
		payloadBuffer[i] = 255
	}
	copy(payloadBuffer[8:], file.contentKey)

	//fmt.Println(base64.StdEncoding.EncodeToString(payloadBuffer))

	encryptedPayload := applyCTR(block, payloadBuffer, file.nonce)

	//fmt.Println(base64.StdEncoding.EncodeToString(encryptedPayload))
	//fmt.Printf("Encrypted payload size %d\n", len(encryptedPayload))

	binary.Write(&header, binary.LittleEndian, encryptedPayload)

	mac := hmac.New(sha256.New, file.crypto.getMacKey())
	mac.Write(header.Bytes())
	calculatedMAC := mac.Sum(nil)

	binary.Write(&header, binary.LittleEndian, calculatedMAC)

	_, err = f.Write(header.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	return nil
}

// WriteChunk encrypts and then writes a chunk of data to the file.
func (file LocalFile) WriteChunk(data []byte, chunkIndex int64) error {
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

	encryptedPayload := applyCTR(fileBlock, []byte(data), nonce)

	binary.Write(&payload, binary.LittleEndian, encryptedPayload)

	mac := hmac.New(sha256.New, file.crypto.getMacKey())

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
