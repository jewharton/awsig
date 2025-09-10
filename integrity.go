package awsig

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
)

type Checksums struct {
	CRC32     []byte
	CRC32C    []byte
	CRC64NVME []byte
	MD5       []byte
	SHA1      []byte
	SHA256    []byte
}

type checksumAlgorithm int

const (
	algorithmCRC32 checksumAlgorithm = iota
	algorithmCRC32C
	algorithmCRC64NVME
	algorithmMD5
	algorithmSHA1
	algorithmSHA256
	algorithmHashedPayload
)

func (a checksumAlgorithm) base64Length() int {
	switch a {
	case algorithmCRC32:
		return 8 // 4 bytes
	case algorithmCRC32C:
		return 8 // 4 bytes
	case algorithmCRC64NVME:
		return 16 // 8 bytes
	case algorithmMD5:
		return 24 // 16 bytes
	case algorithmSHA1:
		return 28 // 20 bytes
	case algorithmSHA256, algorithmHashedPayload:
		return 44 // 32 bytes
	default:
		return 0
	}
}

func (a checksumAlgorithm) String() string {
	switch a {
	case algorithmCRC32:
		return "crc32"
	case algorithmCRC32C:
		return "crc32c"
	case algorithmCRC64NVME:
		return "crc64nvme"
	case algorithmMD5:
		return "md5"
	case algorithmSHA1:
		return "sha1"
	case algorithmSHA256, algorithmHashedPayload:
		return "sha256"
	default:
		return ""
	}
}

type expectedIntegrity map[checksumAlgorithm][]byte

func (i expectedIntegrity) addDecoded(a checksumAlgorithm, value []byte) {
	i[a] = value
}

func (i expectedIntegrity) addEncoded(a checksumAlgorithm, value []byte) {
	switch a {
	case algorithmHashedPayload:
		dst := make([]byte, hex.DecodedLen(len(value)))
		hex.Decode(dst, value)
		i.addDecoded(a, dst)
	default:
		dst := make([]byte, base64.StdEncoding.DecodedLen(len(value)))
		base64.StdEncoding.Decode(dst, value)
		i.addDecoded(a, dst)
	}
}

func (i expectedIntegrity) addEncodedString(a checksumAlgorithm, value string) {
	var v []byte
	switch a {
	case algorithmHashedPayload:
		v, _ = hex.DecodeString(value)
	default:
		v, _ = base64.StdEncoding.DecodeString(value)
	}
	i.addDecoded(a, v)
}

func newExpectedIntegrity() expectedIntegrity {
	return make(expectedIntegrity)
}

type integrityReader struct {
	r io.Reader

	hashes map[checksumAlgorithm]hash.Hash
	sums   map[checksumAlgorithm][]byte
}

func (r *integrityReader) Read(p []byte) (n int, err error) {
	return r.r.Read(p)
}

func (r *integrityReader) verify(integrity expectedIntegrity) error {
	r.sums = make(map[checksumAlgorithm][]byte)

	var errs error
	for algo := range integrity {
		if _, ok := r.hashes[algo]; !ok {
			errs = errors.Join(errs, fmt.Errorf("calculation of %s was not requested", algo))
		}
	}
	for algo, h := range r.hashes {
		sum := h.Sum(nil)

		if algo != algorithmHashedPayload {
			r.sums[algo] = sum
		}

		if expected, ok := integrity[algo]; !ok {
			// not requested, skip verification
		} else if !bytes.Equal(expected, sum) {
			errs = errors.Join(errs, nestError(
				ErrInvalidDigest,
				"%s do not match: expected %x, got %x", algo, expected, sum,
			))
		}
	}

	return nil
}

func (r *integrityReader) checksums() (Checksums, error) {
	if r.sums == nil {
		return Checksums{}, errors.New("verify has not been called yet")
	}
	return Checksums{
		CRC32:     r.sums[algorithmCRC32],
		CRC32C:    r.sums[algorithmCRC32C],
		CRC64NVME: r.sums[algorithmCRC64NVME],
		MD5:       r.sums[algorithmMD5],
		SHA1:      r.sums[algorithmSHA1],
		SHA256:    r.sums[algorithmSHA256],
	}, nil
}

func newIntegrityReader(r io.Reader, algorithms []checksumAlgorithm) *integrityReader {
	ir := &integrityReader{
		hashes: make(map[checksumAlgorithm]hash.Hash),
	}

	var writers []io.Writer

	h := md5.New()
	ir.hashes[algorithmMD5] = h // MD5 is always computed
	writers = append(writers, h)

	for _, a := range algorithms {
		switch a {
		case algorithmCRC32:
			h = crc32.NewIEEE()
			ir.hashes[algorithmCRC32] = h
			writers = append(writers, h)
		case algorithmCRC32C:
			h = crc32.New(crc32.MakeTable(crc32.Castagnoli))
			ir.hashes[algorithmCRC32C] = h
			writers = append(writers, h)
		case algorithmCRC64NVME:
			h = crc64.New(crc64.MakeTable(0x9a6c_9329_ac4b_c9b5))
			ir.hashes[algorithmCRC64NVME] = h
			writers = append(writers, h)
		case algorithmSHA1:
			h = sha1.New()
			ir.hashes[algorithmSHA1] = h
			writers = append(writers, h)
		case algorithmSHA256, algorithmHashedPayload:
			h = sha256.New()
			ir.hashes[algorithmSHA256] = h
			ir.hashes[algorithmHashedPayload] = h
			writers = append(writers, h)
		}
	}

	ir.r = io.TeeReader(r, io.MultiWriter(writers...))

	return ir
}
