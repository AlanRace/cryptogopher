package cryptogopher

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
)

type S3Vault struct {
	CryptomatorVault

	svc    *s3.S3
	bucket string
}

func OpenS3(svc *s3.S3, bucket string, vaultLocation string, password string) (*S3Vault, error) {
	var vault S3Vault
	vault.svc = svc
	vault.bucket = bucket
	vault.vaultLocation = vaultLocation

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

	fmt.Println(result.Contents)

	return &vault, nil
}
