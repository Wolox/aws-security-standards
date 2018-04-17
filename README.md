# aws-security-standards-infra

## S3
### Server Side Encryption
#### Audit

Run `cd s3 && AWS_PROFILE=your-aws-profile go run audit-sse.go`. You'll get a file called sse-audit-result.csv with one line per bucket.
```
bucket-1,false
bucket-2,true
bucket-2,false
bucket-3,false
```

#### Fix
Run `cd s3 && AWS_PROFILE=your-aws-profile go run fix-sse.go`. This will load the file generated from the previous script, filter those buckets that are not encrypted and encrypt them using AES256

WARNING: This will override the bucket's policy and insert a new one with the content found in `s3/encryption-policy.json`. If you want to change this policy, modify the file.
