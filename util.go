package awsig

import "io"

func reuseBuffer(buf []byte, size int) ([]byte, error) {
	if cap(buf) < size {
		return nil, io.ErrShortBuffer
	}
	return buf[:size], nil
}
