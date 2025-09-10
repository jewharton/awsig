package awsig

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zeebo/assert"
)

func TestV2(t *testing.T) {
	provider := simpleCredentialsProvider{
		accessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	t.Run("Object GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://awsexamplebucket1.us-west-1.s3.amazonaws.com/photos/puppy.jpg", nil)
		req.Header.Add("Date", "Tue, 27 Mar 2007 19:36:42 +0000")
		req.Header.Add("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:qgk2+6Sv9/oM7G3qLEjTH1a1l1g=")

		v2 := NewV2(provider)
		v2.now = dummyNow(2007, time.March, 27, 19, 36, 42)

		r, err := v2.Verify(req, "awsexamplebucket1")
		assert.NoError(t, err)

		p := make([]byte, 32*1024)
		n, err := r.Read(p)
		assert.That(t, n == 0)
		assert.That(t, errors.Is(err, io.EOF))
	})
	t.Run("Object PUT", func(t *testing.T) {
		body := make([]byte, 94328)

		_, err := io.ReadFull(rand.Reader, body)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "https://awsexamplebucket1.us-west-1.s3.amazonaws.com/photos/puppy.jpg", bytes.NewBuffer(body))
		req.Header.Add("Content-Type", "image/jpeg")
		req.Header.Add("Content-Length", "94328")
		req.Header.Add("Date", "Tue, 27 Mar 2007 21:15:45 +0000")
		req.Header.Add("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:iqRzw+ileNPu1fhspnRs8nOjjIA=")

		v2 := NewV2(provider)
		v2.now = dummyNow(2007, time.March, 27, 21, 15, 45)

		r, err := v2.Verify(req, "awsexamplebucket1")
		assert.NoError(t, err)

		b, err := io.ReadAll(r)
		assert.NoError(t, err)
		assert.Equal(t, body, b)
	})
	t.Run("List", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://awsexamplebucket1.us-west-1.s3.amazonaws.com/?prefix=photos&max-keys=50&marker=puppy", nil)
		req.Header.Add("User-Agent", "Mozilla/5.0")
		req.Header.Add("Date", "Tue, 27 Mar 2007 19:42:41 +0000")
		req.Header.Add("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:m0WP8eCtspQl5Ahe6L1SozdX9YA=")

		v2 := NewV2(provider)
		v2.now = dummyNow(2007, time.March, 27, 19, 42, 41)

		r, err := v2.Verify(req, "awsexamplebucket1")
		assert.NoError(t, err)

		p := make([]byte, 32*1024)
		n, err := r.Read(p)
		assert.That(t, n == 0)
		assert.That(t, errors.Is(err, io.EOF))
	})
	t.Run("Fetch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://awsexamplebucket1.us-west-1.s3.amazonaws.com/?acl", nil)
		req.Header.Add("Date", "Tue, 27 Mar 2007 19:44:46 +0000")
		req.Header.Add("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:82ZHiFIjc+WbcwFKGUVEQspPn+0=")

		v2 := NewV2(provider)
		v2.now = dummyNow(2007, time.March, 27, 19, 44, 46)

		r, err := v2.Verify(req, "awsexamplebucket1")
		assert.NoError(t, err)

		p := make([]byte, 32*1024)
		n, err := r.Read(p)
		assert.That(t, n == 0)
		assert.That(t, errors.Is(err, io.EOF))
	})
	t.Run("Delete", func(t *testing.T) {
		// NOTE(amwolff): the "Delete" example from
		// https://docs.aws.amazon.com/AmazonS3/latest/API/RESTAuthentication.html#RESTAuthenticationExamples
		// is contradictory to the spec…
		t.SkipNow()
	})
	t.Run("Upload", func(t *testing.T) {
		// NOTE(amwolff): the "Upload" example from
		// https://docs.aws.amazon.com/AmazonS3/latest/API/RESTAuthentication.html#RESTAuthenticationExamples
		// doesn't say what the body is, so it's going to be hard to
		// reproduce the Content-MD5 header.
		t.SkipNow()
	})
	t.Run("List all my buckets", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://s3.us-west-1.amazonaws.com/", nil)
		req.Header.Add("Date", "Wed, 28 Mar 2007 01:29:59 +0000")
		req.Header.Add("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:qGdzdERIC03wnaRNKh6OqZehG9s=")

		v2 := NewV2(provider)
		v2.now = dummyNow(2007, time.March, 28, 1, 29, 59)

		r, err := v2.Verify(req, "")
		assert.NoError(t, err)

		p := make([]byte, 32*1024)
		n, err := r.Read(p)
		assert.That(t, n == 0)
		assert.That(t, errors.Is(err, io.EOF))
	})
	t.Run("Unicode keys", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://s3.us-west-1.amazonaws.com/dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re", nil)
		req.Header.Add("Date", "Wed, 28 Mar 2007 01:49:49 +0000")
		req.Header.Add("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:DNEZGsoieTZ92F3bUfSPQcbGmlM=")

		v2 := NewV2(provider)
		v2.now = dummyNow(2007, time.March, 28, 1, 49, 49)

		r, err := v2.Verify(req, "")
		assert.NoError(t, err)

		p := make([]byte, 32*1024)
		n, err := r.Read(p)
		assert.That(t, n == 0)
		assert.That(t, errors.Is(err, io.EOF))
	})
}
