package awsig

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

const (
	timeFormatISO8601  = "20060102T150405Z"
	timeFormatYYYYMMDD = "20060102"

	signingAlgorithmPrefix = "AWS4-"
)

type signingAlgorithm int

const (
	algorithmHMACSHA256 signingAlgorithm = iota
	algorithmECDSAP256SHA256
)

func (a signingAlgorithm) String() string {
	switch a {
	case algorithmHMACSHA256:
		return "HMAC-SHA256"
	case algorithmECDSAP256SHA256:
		return "ECDSA-P256-SHA256"
	default:
		return ""
	}
}

type signingAlgorithmSuffix int

const (
	algorithmSuffixNone signingAlgorithmSuffix = iota
	algorithmSuffixPayload
	algorithmSuffixTrailer
)

func (s signingAlgorithmSuffix) String() string {
	switch s {
	case algorithmSuffixPayload:
		return "PAYLOAD"
	case algorithmSuffixTrailer:
		return "TRAILER"
	default:
		return ""
	}
}

type scope struct {
	date    string
	region  string
	service string
}

func (s scope) String() string {
	return s.date + "/" + s.region + "/" + s.service + "/" + authorizationHeaderCredentialTerminator
}

type signatureV4 []byte

func newSignatureV4FromEncoded(b []byte) (signatureV4, error) {
	if len(b) != signatureV4EncodedLength {
		return nil, ErrSignatureMalformed
	}

	s := make(signatureV4, signatureV4DecodedLength)

	n, err := hex.Decode(s, b)
	if err != nil {
		return nil, ErrSignatureMalformed
	}

	if n != signatureV4DecodedLength {
		return nil, ErrSignatureMalformed
	}

	return s, nil
}

func (s signatureV4) compare(other signatureV4) bool {
	return subtle.ConstantTimeCompare(s, other) == 1
}

func (s signatureV4) String() string {
	return hex.EncodeToString(s)
}

type signatureData struct {
	algorithm       signingAlgorithm
	algorithmSuffix signingAlgorithmSuffix
	dateTime        string
	scope           scope
	previous        signatureV4
	digest          []byte
}

func hmacSHA256(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(s))
	return h.Sum(nil)
}

func signingKeyHMACSHA256(key, date, region, service string) []byte {
	dateKey := hmacSHA256([]byte("AWS4"+key), date)
	dateRegionKey := hmacSHA256(dateKey, region)
	dateRegionServiceKey := hmacSHA256(dateRegionKey, service)
	return hmacSHA256(dateRegionServiceKey, authorizationHeaderCredentialTerminator)
}

func calculateSignature(data signatureData, secretAccessKey string) signatureV4 {
	if data.algorithm == algorithmECDSAP256SHA256 {
		panic("not implemented")
	}

	b := new(strings.Builder)

	b.WriteString(signingAlgorithmPrefix)
	b.WriteString(data.algorithm.String())
	b.WriteString(data.algorithmSuffix.String())
	b.WriteByte('\n')
	b.WriteString(data.dateTime)
	b.WriteByte('\n')
	b.WriteString(data.scope.String())
	b.WriteByte('\n')

	switch data.algorithmSuffix {
	case algorithmSuffixPayload:
		b.WriteString(data.previous.String())
		b.WriteByte('\n')
		b.WriteString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		b.WriteByte('\n')
	case algorithmSuffixTrailer:
		b.WriteString(data.previous.String())
		b.WriteByte('\n')
	}

	hex.NewEncoder(b).Write(data.digest)

	key := signingKeyHMACSHA256(secretAccessKey, data.scope.date, data.scope.region, data.scope.service)

	return hmacSHA256(key, b.String())
}
