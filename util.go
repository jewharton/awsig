package awsig

import (
	"crypto/sha256"
	"io"
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
