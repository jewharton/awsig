package awsig

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeebo/assert"
)

func TestV4(t *testing.T) {
	provider := SimpleCredentialsProvider{
		accessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	v4 := NewV4(provider, "us-east-1", "s3")
	v4.now = dummyNow(2013, time.May, 24, 0, 0, 0)

	t.Run("single chunk", func(t *testing.T) {
		t.Run("GET Object", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
			req.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
			req.Header.Add("Range", "bytes=0-9")
			req.Header.Add("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
			req.Header.Add("x-amz-date", "20130524T000000Z")

			r, err := v4.Verify(req)
			assert.NoError(t, err)

			p := make([]byte, 32*1024)
			n, err := r.Read(p)
			assert.That(t, n == 0)
			assert.That(t, errors.Is(err, io.EOF))
		})
		t.Run("PUT Object", func(t *testing.T) {
			const content = "Welcome to Amazon S3."

			req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.amazonaws.com/test$file.text", strings.NewReader(content))
			req.Header.Add("Date", "Fri, 24 May 2013 00:00:00 GMT")
			req.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd")
			req.Header.Add("x-amz-date", "20130524T000000Z")
			req.Header.Add("x-amz-storage-class", "REDUCED_REDUNDANCY")
			req.Header.Add("x-amz-content-sha256", "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072")

			r, err := v4.Verify(req)
			assert.NoError(t, err)

			b, err := io.ReadAll(r)
			assert.NoError(t, err)
			assert.Equal(t, content, string(b))
		})
		t.Run("GET Bucket Lifecycle", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/?lifecycle", nil)
			req.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543")
			req.Header.Add("x-amz-date", "20130524T000000Z")
			req.Header.Add("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

			r, err := v4.Verify(req)
			assert.NoError(t, err)

			p := make([]byte, 32*1024)
			n, err := r.Read(p)
			assert.That(t, n == 0)
			assert.That(t, errors.Is(err, io.EOF))
		})
		t.Run("Get Bucket (List Objects)", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", nil)
			req.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")
			req.Header.Add("x-amz-date", "20130524T000000Z")
			req.Header.Add("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

			r, err := v4.Verify(req)
			assert.NoError(t, err)

			p := make([]byte, 32*1024)
			n, err := r.Read(p)
			assert.That(t, n == 0)
			assert.That(t, errors.Is(err, io.EOF))
		})
	})
	t.Run("multiple chunks", func(t *testing.T) {
		t.SkipNow()
	})
	t.Run("trailing headers", func(t *testing.T) {
		t.SkipNow()
	})
}

type SimpleCredentialsProvider struct {
	accessKeyID     string
	secretAccessKey string
}

func (p SimpleCredentialsProvider) Provide(ctx context.Context, accessKeyID string) (secretAccessKey string, _ error) {
	if accessKeyID != p.accessKeyID {
		return "", ErrInvalidAccessKeyID
	}
	return p.secretAccessKey, nil
}

func dummyNow(year int, month time.Month, day, hour, min, sec int) func() time.Time {
	return func() time.Time {
		return time.Date(year, month, day, hour, min, sec, 0, time.UTC)
	}
}
