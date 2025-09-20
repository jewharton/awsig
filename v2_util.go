package awsig

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
)

type signatureV2 []byte

func newSignatureV2FromEncoded(s string, urlEncoded bool) (signatureV2, error) {
	var err error

	if urlEncoded {
		if s, err = url.QueryUnescape(s); err != nil {
			return nil, err
		}
	}

	if len(s) != signatureV2EncodedLength {
		return nil, errors.New("invalid signature length")
	}

	return base64.StdEncoding.DecodeString(s)
}

func (s signatureV2) compare(other signatureV2) bool {
	return subtle.ConstantTimeCompare(s, other) == 1
}

func (s signatureV2) String() string {
	return base64.StdEncoding.EncodeToString(s)
}

func hmacSHA1(key []byte, s string) []byte {
	h := hmac.New(sha1.New, key)
	h.Write([]byte(s))
	return h.Sum(nil)
}

func calculateSignatureV2(stringToSign string, secretAccessKey string) signatureV2 {
	return hmacSHA1([]byte(secretAccessKey), stringToSign)
}
