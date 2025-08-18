package awsig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/zeebo/assert"
)

func TestNestedError(t *testing.T) {
	outer := errors.New("outer")
	inner := errors.New("inner")

	nested := nestError(outer, "oops: %w", inner)

	// Error
	assert.Equal(t, "outer: oops: inner", nested.Error())
	// Unwrap
	assert.Equal(t, inner, errors.Unwrap(errors.Unwrap(nested)))
	// Is
	assert.That(t, errors.Is(nested, outer))
	assert.That(t, errors.Is(nested, inner))
}

func TestReuseBuffer(t *testing.T) {
	buf := make([]byte, 2)
	{
		b, err := reuseBuffer(buf, 1)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(b))
	}
	{
		b, err := reuseBuffer(buf, 2)
		assert.NoError(t, err)
		assert.Equal(t, buf, b)
	}
	{
		_, err := reuseBuffer(buf, 3)
		assert.Error(t, err)
	}
}

const (
	hashZero = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	hashTest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)

func TestSHA256Hash(t *testing.T) {

	assert.Equal(t, hashZero, hex.EncodeToString(sha256Hash(nil)))
	assert.Equal(t, hashTest, hex.EncodeToString(sha256Hash([]byte("test"))))
}

func TestHashBuilder(t *testing.T) {
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

func TestURIEncode(t *testing.T) {
	const (
		testPath   = "photos/Jan/sample.jpg"
		unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	)
	assert.Equal(t, testPath, uriEncode(testPath, true))
	assert.Equal(t, unreserved+"with%20spaces", uriEncode(unreserved+"with spaces", false))
}
