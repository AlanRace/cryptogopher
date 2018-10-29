package main

import (
	"flag"
	"fmt"

	"github.com/AlanRace/cryptogopher/cryptogopher"
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

	rootDir := crypto.GetRootDirectory()

	fmt.Println("--- Root Content ---")
	rootDir.Print()

	fmt.Println("--- test/inner/ Content ---")
	rootDir.GetSubDirectory("test/inner").Print()

	newFile, err := rootDir.CreateFile("hello.txt")
	newFile.WriteChunk([]byte("Hi my friendly encrypted data"), 0)

	chunkData, err := newFile.ReadChunk(0)

	fmt.Println(string(chunkData))
}
