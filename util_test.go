package awsig

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/zeebo/assert"
)

func TestNestedError(t *testing.T) {
	outer := errors.New("outer")
	inner := errors.New("inner")

	nested := nestError(outer, "oops: %w", inner)

	t.Run("Error", func(t *testing.T) {
		assert.Equal(t, "outer: oops: inner", nested.Error())
	})
	t.Run("Unwrap", func(t *testing.T) {
		assert.Equal(t, inner, errors.Unwrap(errors.Unwrap(nested)))
	})
	t.Run("Is", func(t *testing.T) {
		assert.That(t, errors.Is(nested, outer))
		assert.That(t, errors.Is(nested, inner))
	})
}

func TestURIEncode(t *testing.T) {
	const (
		testPath   = "photos/Jan/sample.jpg"
		unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	)
	assert.Equal(t, testPath, uriEncode(testPath, true))
	assert.Equal(t, unreserved+"with%20spaces", uriEncode(unreserved+"with spaces", false))
}

func TestHashBuilder(t *testing.T) {
	const (
		hashZero = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		hashTest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	)

	b := newHashBuilder(sha256.New)
	b.Write(nil)
	b.WriteString("")
	assert.Equal(t, hashZero, hex.EncodeToString(b.Sum()))
	b.Write([]byte("test"))
	assert.Equal(t, hashTest, hex.EncodeToString(b.Sum()))
	b.WriteByte('!')
	assert.Equal(t, "1882b91b7f49d479cf1ec2f1ecee30d0e5392e963a2109015b7149bf712ad1b6", hex.EncodeToString(b.Sum()))
	b.WriteString("!!")
	assert.Equal(t, "28f0f0df65f6e12393536e8b76b4a227e2e84c323cc4d3fdd5e56966f29019ad", hex.EncodeToString(b.Sum()))
}

func TestLimitedReader(t *testing.T) {
	expected := make([]byte, 30)
	_, err := io.ReadFull(rand.Reader, expected)
	assert.NoError(t, err)

	r := limitReader(bytes.NewReader(expected), 10)

	b := make([]byte, 9)
	n, err := io.ReadFull(r, b)
	assert.Equal(t, 9, n)
	assert.NoError(t, err)
	assert.Equal(t, expected[:9], b)

	b = make([]byte, 11)
	n, err = io.ReadFull(r, b)
	assert.Equal(t, 1, n)
	assert.That(t, errors.Is(err, io.EOF))
	assert.That(t, errors.Is(err, errLimitReached))
	assert.Equal(t, expected[9:10], b[:1])
	assert.Equal(t, make([]byte, 10), b[1:])

	r.toggle()

	b = make([]byte, 10)
	n, err = io.ReadFull(r, b)
	assert.Equal(t, 10, n)
	assert.NoError(t, err)
	assert.Equal(t, expected[10:20], b)

	r.toggle()

	b, err = io.ReadAll(r)
	assert.Equal(t, 0, len(b))
	assert.That(t, errors.Is(err, io.EOF))
	assert.That(t, errors.Is(err, errLimitReached))

	r.toggle()

	b, err = io.ReadAll(r)
	assert.NoError(t, err)
	assert.Equal(t, expected[20:], b)
}

type simpleCredentialsProvider struct {
	accessKeyID     string
	secretAccessKey string
}

func (p simpleCredentialsProvider) Provide(ctx context.Context, accessKeyID string) (secretAccessKey string, _ error) {
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
