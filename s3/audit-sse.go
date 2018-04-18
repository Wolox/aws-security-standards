package main

import (
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

func getClient(region string) *s3.S3 {
	sess, _ := session.NewSession(&aws.Config{Region: aws.String(region)})

	client := s3.New(sess)

	return client
}

func main() {

	region := ""

	if len(os.Args) > 1 {
		region = os.Args[1]
	} else {
		region = "us-east-1"
	}

	// Get the AWS client for the given region
	client := getClient(region)

	// If no parameters are passed then no filters are applied
	req, resp := client.ListBucketsRequest(nil)

	err := req.Send()

	// map[string]interface{} builds a map from string to anything
	policies := make(chan map[string]interface{})

	if err == nil {
		for _, element := range resp.Buckets {
			go getBucketDetails(client, element.Name, policies)
		}
	} else {
		fmt.Println(err)
	}

	file := initFile()
	defer file.Close()

	for range resp.Buckets {
		writeToFile(<-policies, file)
	}
}

func initFile() *os.File {
	file, err := os.OpenFile(
		"sse-audit-result.csv",
		os.O_WRONLY|os.O_CREATE,
		0666,
	)

	byteSlice := []byte("bucket, encrypted, public\n")

	_, err = file.Write(byteSlice)
	if err != nil {
		log.Fatal(err)
	}

	return file
}

// Checks if the bucket is actually encrypted
func getBucketEncryption(client *s3.S3, bucketName *string) bool {
	_, err := client.GetBucketEncryption(&s3.GetBucketEncryptionInput{Bucket: aws.String(*bucketName)})

	var encryption bool

	if err == nil {
		encryption = true
	} else {
		encryption = false
	}

	return encryption
}

// Checks if the bucket is publicly readable
func isBucketPublicRead(client *s3.S3, bucketName *string) bool {
	location, error := getBucketLocation(client, bucketName)

	if error {
		return false
	}

	client = getClient(location)

	resp, err := client.GetBucketAcl(&s3.GetBucketAclInput{Bucket: bucketName})

	if err != nil {
		fmt.Println("Error for ", *bucketName)
		fmt.Println(err)
		return false
	}

	for _, element := range resp.Grants {
		if *element.Grantee.Type == "Group" && *element.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" && *element.Permission == "READ" {
			return true
		}
	}
	return false

}

// gets the bucket region
func getBucketLocation(client *s3.S3, bucketName *string) (string, bool) {
	resp, err := client.GetBucketLocation(&s3.GetBucketLocationInput{Bucket: bucketName})

	if err != nil {
		return "", true
	}

	if resp.LocationConstraint == nil {
		return "us-east-1", false
	}

	return *resp.LocationConstraint, false
}

// returns a map with the bucket details: encryption and public readability
func getBucketDetails(client *s3.S3, bucketName *string, policies chan map[string]interface{}) {
	var wg sync.WaitGroup
	var encryption bool
	var public bool

	wg.Add(2)

	go func() {
		defer wg.Done()
		encryption = getBucketEncryption(client, bucketName)
	}()

	go func() {
		defer wg.Done()
		public = isBucketPublicRead(client, bucketName)
	}()

	wg.Wait()

	policies <- map[string]interface{}{
		"bucket":     *bucketName,
		"encryption": encryption,
		"public":     public,
	}
}

// Writes the bucket details to a file
func writeToFile(data map[string]interface{}, file *os.File) {

	byteSlice := []byte(fmt.Sprintf("%s,%t,%t\n", data["bucket"].(string), data["encryption"].(bool), data["public"].(bool)))

	_, err := file.Write(byteSlice)
	if err != nil {
		log.Fatal(err)
	}
}
