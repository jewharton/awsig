package awsig

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"hash/crc32"
	"io"

	"github.com/minio/crc64nvme"
)

var (
	ErrIntegrityVerificationFailed = errors.New("integrity verification failed")
)

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

type expectedIntegrity struct {
	crc32         *string
	crc32c        *string
	crc64nvme     *string
	md5           *string
	sha1          *string
	sha256        *string
	hashedPayload *string
}

func (i *expectedIntegrity) add(a checksumAlgorithm, value string) {
	switch a {
	case algorithmCRC32:
		i.crc32 = &value
	case algorithmCRC32C:
		i.crc32c = &value
	case algorithmCRC64NVME:
		i.crc64nvme = &value
	case algorithmMD5:
		i.md5 = &value
	case algorithmSHA1:
		i.sha1 = &value
	case algorithmSHA256:
		i.sha256 = &value
	case algorithmHashedPayload:
		i.hashedPayload = &value
	}
}

type integrityReader struct {
	r io.Reader

	crc32     hash.Hash32
	crc32c    hash.Hash32
	crc64nvme hash.Hash64
	md5       hash.Hash
	sha1      hash.Hash
	sha256    hash.Hash
}

func (r *integrityReader) Read(p []byte) (n int, err error) {
	return r.r.Read(p)
}

func (r *integrityReader) verify(integrity expectedIntegrity) error {
	if integrity.crc32 != nil {
		if r.crc32 == nil {
			return errors.New("calculation of CRC32 was not requested")
		}
		if !equalSumsBase64(*integrity.crc32, r.crc32.Sum(nil)) {
			return ErrIntegrityVerificationFailed
		}
	}
	if integrity.crc32c != nil {
		if r.crc32c == nil {
			return errors.New("calculation of CRC32C was not requested")
		}
		if !equalSumsBase64(*integrity.crc32c, r.crc32c.Sum(nil)) {
			return ErrIntegrityVerificationFailed
		}
	}
	if integrity.crc64nvme != nil {
		if r.crc64nvme == nil {
			return errors.New("calculation of CRC64NVME was not requested")
		}
		if !equalSumsBase64(*integrity.crc64nvme, r.crc64nvme.Sum(nil)) {
			return ErrIntegrityVerificationFailed
		}
	}
	if integrity.md5 != nil {
		if equalSumsHex(*integrity.md5, r.md5.Sum(nil)) {
			return ErrIntegrityVerificationFailed
		}
	}
	if integrity.sha1 != nil {
		if r.sha1 == nil {
			return errors.New("calculation of SHA1 was not requested")
		}
		if !equalSumsBase64(*integrity.sha1, r.sha1.Sum(nil)) {
			return ErrIntegrityVerificationFailed
		}
	}
	if integrity.sha256 != nil {
		if r.sha256 == nil {
			return errors.New("calculation of SHA256 was not requested")
		}
		if !equalSumsBase64(*integrity.sha256, r.sha256.Sum(nil)) {
			return ErrIntegrityVerificationFailed
		}
	}
	if integrity.hashedPayload != nil {
		if r.sha256 == nil {
			return errors.New("calculation of SHA256 was not requested")
		}
		if equalSumsHex(*integrity.hashedPayload, r.sha256.Sum(nil)) {
			return ErrIntegrityVerificationFailed
		}
	}

	return nil
}

func equalSumsBase64(expected string, actual []byte) bool {
	return expected == base64.StdEncoding.EncodeToString(actual)
}

func equalSumsHex(expected string, actual []byte) bool {
	return expected == hex.EncodeToString(actual)
}

func newIntegrityReader(r io.Reader, algorithms ...checksumAlgorithm) *integrityReader {
	ir := new(integrityReader)

	var writers []io.Writer

	ir.md5 = md5.New() // MD5 is always computed
	writers = append(writers, ir.md5)

	for _, a := range algorithms {
		switch a {
		case algorithmCRC32:
			if ir.crc32 == nil {
				ir.crc32 = crc32.NewIEEE()
				writers = append(writers, ir.crc32)
			}
		case algorithmCRC32C:
			if ir.crc32c == nil {
				ir.crc32c = crc32.New(crc32.MakeTable(crc32.Castagnoli))
				writers = append(writers, ir.crc32c)
			}
		case algorithmCRC64NVME:
			if ir.crc64nvme == nil {
				ir.crc64nvme = crc64nvme.New()
				writers = append(writers, ir.crc64nvme)
			}
		case algorithmSHA1:
			if ir.sha1 == nil {
				ir.sha1 = sha1.New()
				writers = append(writers, ir.sha1)
			}
		case algorithmSHA256, algorithmHashedPayload:
			if ir.sha256 == nil {
				ir.sha256 = sha256.New()
				writers = append(writers, ir.sha256)
			}
		}
	}

	ir.r = io.TeeReader(r, io.MultiWriter(writers...))

	return ir
}
