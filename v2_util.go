package awsig

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
)

type signatureV2 []byte

func newSignatureV2FromEncoded(b []byte) (signatureV2, error) {
	if len(b) != signatureV2EncodedLength {
		return nil, ErrInvalidSignature
	}

	s := make(signatureV2, signatureV2DecodedLength)

	n, err := base64.StdEncoding.Decode(s, b)
	if err != nil {
		return nil, ErrInvalidSignature
	}

	if n != signatureV2DecodedLength {
		return nil, ErrInvalidSignature
	}

	return s, nil
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
