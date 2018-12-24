package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/AlanRace/cryptogopher"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
)

// Uploads a file to S3 given a bucket and object key. Also takes a duration
// value to terminate the update if it doesn't complete within that time.
//
// The AWS Region needs to be provided in the AWS shared config or on the
// environment variable as `AWS_REGION`. Credentials also must be provided
// Will default to shared config file, but can load from environment if provided.
//
// Usage:
//   # Upload myfile.txt to myBucket/myKey. Must complete within 10 minutes or will fail
//   go run withContext.go -b mybucket -k myKey -d 10m < myfile.txt
func main() {
	var bucket, vaultLocation, passphrase string

	flag.StringVar(&bucket, "b", "", "Bucket name.")
	flag.StringVar(&vaultLocation, "vault", "", "Vault location")
	flag.StringVar(&passphrase, "passphrase", "", "Vault passphrase")
	flag.Parse()

	if passphrase == "" {
		passFile, err := os.Open("pass")
		// if we os.Open returns an error then handle it
		if err != nil {
			fmt.Println(err)
		}
		defer passFile.Close()

		byteValue, _ := ioutil.ReadAll(passFile)

		passphrase = string(byteValue[:len(byteValue)-1])

		fmt.Println(passphrase)
	}

	// All clients require a Session. The Session provides the client with
	// shared configuration such as region, endpoint, and credentials. A
	// Session should be shared where possible to take advantage of
	// configuration and credential caching. See the session package for
	// more information.
	//sess := session.Must(session.NewSession())
	sess := session.Must(session.NewSession(&aws.Config{
		Endpoint: aws.String("s3.wasabisys.com"),
		Region:   aws.String("us-east-1"),
	}))

	s3Vault, err := cryptogopher.OpenS3(sess, bucket, vaultLocation, passphrase)
	if err != nil {
		fmt.Println(err)
	}

	//fmt.Println(s3Vault)

	rootDir := s3Vault.GetRootDirectory()

	fmt.Println("--- Root Content ---")
	rootDir.Print()

	fmt.Println("--- NPL/ Content ---")
	nplDir := rootDir.GetSubDirectory("NPL")
	nplDir.Print()

	newFile, err := nplDir.CreateFile("hello.txt")
	newFile.WriteChunk([]byte("Hi my friendly encrypted data"), 0)

	chunkData, err := newFile.ReadChunk(0)

	fmt.Println(string(chunkData))
}
