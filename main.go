package main

import (
	"encoding/base32"
	"flag"
	"fmt"

	"alanrace.com/cryptogopher/cryptogopher"
)

func main() {
	var vaultLocation, passphrase string

	flag.StringVar(&vaultLocation, "vault", "", "Vault location")
	flag.StringVar(&passphrase, "passphrase", "", "Vault passphrase")

	flag.Parse()

	crypto, err := cryptogopher.Open(vaultLocation, passphrase)
	if err != nil {
		fmt.Println(err)
	}

	decrypted, err := crypto.DecryptFilename("VACG73MM7JSF4UIPQUZX2F63PS5RYIY2RUSBQLHI3TQR427PPA======", "")

	fmt.Println(decrypted)

	fmt.Println(crypto.HashDirectoryId("aef38a8d-7a1f-429c-b4b6-36f10c4d20d6"))

	t := "0JSRIGJWNFTIQ3ZWO4NPNTXCPUCTGKYEP"
	tDecoded, err := base32.StdEncoding.DecodeString(t[1:])
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(string(tDecoded))

	decrypted, err = crypto.DecryptFilename("UYDJQXIOID377RLWLYTCHRDVLNJTGT7UH56E6X3RRG3I34MAGE======", "aef38a8d-7a1f-429c-b4b6-36f10c4d20d6")

	fmt.Println("Decrypted: " + decrypted)

	reencrypted, err := crypto.EncryptFilename(decrypted, "aef38a8d-7a1f-429c-b4b6-36f10c4d20d6")

	fmt.Println("Reencrypted: " + reencrypted)

	//fmt.Println(crypto.getFilePath(""))

	//crypto.ListFiles("test")

	fmt.Println("--- Root Content ---")
	rootDir := crypto.GetRootDirectory()

	rootDir.Print()

	rootDir.GetSubDirectory("test/inner").Print()

	// // Open our jsonFile
	// textFile, err := os.Open(rootDir.files[0].encryptedPath)
	// // if we os.Open returns an error then handle it
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// defer textFile.Close()

	// byteValue, _ := ioutil.ReadAll(textFile)

	// //fmt.Println(string(byteValue))

	// nonce := byteValue[:16]
	// encryptedPayload := byteValue[16:56]
	// //headerMAC := byteValue[56:88]

	// block, err := aes.NewCipher(crypto.primaryKey)
	// if err != nil {
	// 	panic(err)
	// }

	// decryptedPayload := decrypt(block, encryptedPayload, nonce)
	// contentKey := decryptedPayload[8:]

	// fmt.Println(hex.EncodeToString(contentKey))
	// fmt.Printf("Length: %d, [0] = %d\n", len(contentKey), decryptedPayload[0])

	// fileBlock, err := aes.NewCipher(contentKey)
	// if err != nil {
	// 	panic(err)
	// }

	// restOfFile := byteValue[88:]

	// chunkNonce := restOfFile[:16]
	// payload := restOfFile[16 : len(restOfFile)-32]

	// decryptedBlock := decrypt(fileBlock, payload, chunkNonce)

	// fmt.Println(string(decryptedBlock))

	//fmt.Printf("Num chunks: %d\n", rootDir.files[0].GetNumChunks())
	//fmt.Printf("Num chunks: %d\n", rootDir.files[1].GetNumChunks())

	//_, err = rootDir.files[0].ReadChunk(1)

	//fmt.Println(string(chunkData))

	newFile, err := rootDir.CreateFile("hello.txt")
	newFile.WriteChunk([]byte("Hi my friendly encrypted data"), 0)

	chunkData, err := newFile.ReadChunk(0)

	fmt.Println(string(chunkData))
}
