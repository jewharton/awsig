package awsig

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
		t.Run("GET", func(t *testing.T) {
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
		t.Run("PUT", func(t *testing.T) {
			t.SkipNow()
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
