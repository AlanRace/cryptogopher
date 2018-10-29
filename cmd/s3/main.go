package main

import (
	"flag"
	"fmt"

	"github.com/AlanRace/cryptogopher"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
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

	// Create a new instance of the service's client with a Session.
	// Optional aws.Config values can also be provided as variadic arguments
	// to the New function. This option allows you to provide service
	// specific configuration.
	svc := s3.New(sess)

	s3Vault, err := cryptogopher.OpenS3(svc, bucket, vaultLocation, passphrase)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(s3Vault)
}
