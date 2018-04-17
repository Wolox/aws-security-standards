package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

type AuditResult struct {
	BucketName string
	Encrypted  bool
	Public     bool
}

func getClient() *s3.S3 {
	region := ""

	if len(os.Args) > 1 {
		region = os.Args[1]
	} else {
		region = "us-east-1"
	}

	sess, _ := session.NewSession(&aws.Config{Region: aws.String(region)})

	client := s3.New(sess)

	return client
}

func main() {

	csvFile, _ := os.Open("sse-audit-result.csv")
	reader := csv.NewReader(bufio.NewReader(csvFile))
	firstLine := true

	var toEncrypt []AuditResult

	for {
		line, error := reader.Read()

		if error == io.EOF {
			break
		} else if error != nil {
			log.Fatal(error)
		}

		if firstLine {
			firstLine = false
		} else {
			encrypted, _ := strconv.ParseBool(line[1])
			public, _ := strconv.ParseBool(line[2])
			if !encrypted && !public {
				toEncrypt = append(toEncrypt, AuditResult{BucketName: line[0], Encrypted: encrypted, Public: public})
			}
		}
	}

	client := getClient()

	var wg sync.WaitGroup

	wg.Add(len(toEncrypt))

	for _, element := range toEncrypt {
		go func() {
			defer wg.Done()
			encryptBucket(element.BucketName, client)
		}()
	}
	wg.Wait()
}

func setBucketEncryption(bucketName string, client *s3.S3) {
	defEnc := &s3.ServerSideEncryptionByDefault{SSEAlgorithm: aws.String(s3.ServerSideEncryptionAes256)}
	rule := &s3.ServerSideEncryptionRule{ApplyServerSideEncryptionByDefault: defEnc}
	rules := []*s3.ServerSideEncryptionRule{rule}
	serverConfig := &s3.ServerSideEncryptionConfiguration{Rules: rules}
	input := &s3.PutBucketEncryptionInput{Bucket: aws.String(bucketName), ServerSideEncryptionConfiguration: serverConfig}
	_, err := client.PutBucketEncryption(input)

	if err != nil {
		fmt.Println("Got an error adding default KMS encryption to bucket", bucketName)
		fmt.Println(err.Error())
		os.Exit(1)
	} else {
		fmt.Println("Encrypted ", bucketName)
	}
}

func setBucketEncryptionPolicy(bucketName string, client *s3.S3) {
	policy := getBucketEncriptionPolicyToSet(bucketName)
	_, error := client.PutBucketPolicy(&s3.PutBucketPolicyInput{Bucket: &bucketName, Policy: &policy})
	if error != nil {
		fmt.Println("Error while trying to set the encryption policy")
	}
}

func encryptBucket(bucketName string, client *s3.S3) {
	setBucketEncryption(bucketName, client)
	setBucketEncryptionPolicy(bucketName, client)
}

func getBucketEncriptionPolicyToSet(bucketName string) string {
	dat, _ := ioutil.ReadFile("./encryption-policy.json")

	policy := strings.Replace(string(dat), "YourBucket", bucketName, 2)

	return policy
}
