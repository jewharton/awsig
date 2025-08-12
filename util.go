package awsig

import (
	"crypto/sha256"
	"hash"
	"io"
	"net/url"
	"strings"
)

func reuseBuffer(buf []byte, size int) ([]byte, error) {
	if cap(buf) < size {
		return nil, io.ErrShortBuffer
	}
	return buf[:size], nil
}

func sha256Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

type hashBuilder struct {
	h hash.Hash
}

func (b *hashBuilder) Write(p []byte) (int, error) {
	return b.h.Write(p)
}

func (b *hashBuilder) WriteByte(c byte) error {
	_, err := b.h.Write([]byte{c})
	return err
}

func (b *hashBuilder) WriteString(s string) (int, error) {
	return b.h.Write([]byte(s))
}

func (b *hashBuilder) Sum() []byte {
	return b.h.Sum(nil)
}

func newHashBuilder(h func() hash.Hash) *hashBuilder {
	return &hashBuilder{
		h: h(),
	}
}

func uriEncode(value string, path bool) string {
	encoded := url.QueryEscape(value)
	oldnews := []string{"+", "%20", "*", "%2A", "%7E", "~"}

	if path {
		oldnews = append(oldnews, "%2F", "/")
	}

	return strings.NewReplacer(oldnews...).Replace(encoded)
}
