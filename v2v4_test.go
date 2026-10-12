package awsig

import (
	"bytes"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/zeebo/assert"
)

var newV2V4 = func(provider CredentialsProvider[exampleAuthData], now func() time.Time) verifier[VerifiedRequest[exampleAuthData]] {
	v2v4 := NewV2V4(provider, V4Config{
		Region:  testDefaultRegion,
		Service: testDefaultService,
	})
	v2v4.v2.now = now
	v2v4.v4.now = now
	return v2v4
}

func TestV2V4(t *testing.T) {
	testV2(t, newV2V4)
	testV4(t, newV2V4)
}

func FuzzV2V4(f *testing.F) {
	const (
		accessKeyID     = "AKIAIOSFODNN7EXAMPLE"
		secretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	)

	f.Add(true, accessKeyID, secretAccessKey, uint(0), []byte(nil), "AWS4-HMAC-SHA256 Credential="+accessKeyID+"/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature="+testBogusSignatureV4, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 0, 0)
	f.Add(true, accessKeyID, secretAccessKey, uint(3), []byte("a;chunk-signature="+testBogusSignatureV4+"\r\n0123456789\r\n0;chunk-signature="+testBogusSignatureV4+"\r\n"), "AWS4-HMAC-SHA256 Credential="+accessKeyID+"/20130524/us-east-1/s3/aws4_request,SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length,Signature="+testBogusSignatureV4, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", 10, 180)
	f.Add(false, accessKeyID, secretAccessKey, uint(0), []byte(nil), "AWS "+accessKeyID+":"+testBogusSignatureV2, "", 0, 0)
	f.Add(false, accessKeyID, secretAccessKey, uint(3), []byte("1234567890"), "AWS "+accessKeyID+":"+testBogusSignatureV2, "", 0, 0)

	var now func() time.Time

	f.Fuzz(func(t *testing.T, v4 bool, accessKeyID, secretAccessKey string, methodIdx uint, body []byte, authorization, contentSHA256 string, contentLength, decodedContentLength int) {
		req := httptest.NewRequest(httpMethodByIdx(methodIdx), "https://examplebucket.s3.amazonaws.com/test.txt", bytes.NewReader(body))
		req.Header.Add("Authorization", authorization)
		if v4 {
			switch contentSHA256 {
			case streamingUnsignedPayloadTrailer, streamingAWS4HMACSHA256Payload, streamingAWS4HMACSHA256PayloadTrailer:
				req.Header.Add("Content-Encoding", "aws-chunked")
				req.Header.Add("x-amz-decoded-content-length", strconv.Itoa(decodedContentLength))
			}
			req.Header.Add("Content-Length", strconv.Itoa(contentLength))
			req.Header.Add("x-amz-content-sha256", contentSHA256)
			req.Header.Add("x-amz-date", "20130524T000000Z")
			now = dummyNow(2013, time.May, 24, 0, 0, 0)
		} else {
			req.Header.Add("Date", "Tue, 27 Mar 2007 19:36:42 +0000")
			now = dummyNow(2007, time.March, 27, 19, 36, 42)
		}

		provider := simpleCredentialsProvider{
			accessKeyID:     accessKeyID,
			secretAccessKey: secretAccessKey,
		}

		_, err := newV2V4(provider, now).Verify(req, "")
		assert.Error(t, err)
	})
}
