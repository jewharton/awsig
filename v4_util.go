package awsig

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

const awsISO8601Format = "20060102T150405Z"

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
	case algorithmSuffixNone:
		return ""
	case algorithmSuffixPayload:
		return "PAYLOAD"
	case algorithmSuffixTrailer:
		return "TRAILER"
	default:
		return ""
	}
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

func newSignatureV4FromDecoded(b []byte) (signatureV4, error) {
	if len(b) != signatureV4DecodedLength {
		return nil, ErrSignatureMalformed
	}

	s := make(signatureV4, signatureV4DecodedLength)

	copy(s, b)

	return s, nil
}

func mustNewSignatureV4FromDecoded(b []byte) signatureV4 {
	s, err := newSignatureV4FromDecoded(b)
	if err != nil {
		panic(err)
	}

	return s
}

func (s signatureV4) compare(other signatureV4) bool {
	return subtle.ConstantTimeCompare(s, other) == 1
}

func (s signatureV4) String() string {
	return hex.EncodeToString(s)
}

func sha256Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

func hmacSHA256(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(s))
	return h.Sum(nil)
}

func signingKeyHMACSHA256(key, dateTime, region, service string) []byte {
	dateKey := hmacSHA256([]byte("AWS4"+key), dateTime)
	dateRegionKey := hmacSHA256(dateKey, region)
	dateRegionServiceKey := hmacSHA256(dateRegionKey, service)
	return hmacSHA256(dateRegionServiceKey, "aws4_request")
}

type seedSignatureData struct{}

func extractDataFromHeaders(r *http.Request) seedSignatureData {
	return seedSignatureData{}
}

func extractDataFromQuery(r *http.Request) seedSignatureData {
	return seedSignatureData{}
}

func calculateSeedSignature(data seedSignatureData) signatureV4 {
	return nil
}

type scope struct {
	date    time.Time
	region  string
	service string
}

func (s scope) String() string {
	return s.date.Format("20060102") + "/" + s.region + "/" + s.service + "/aws4_request"
}

type chunkSignatureData struct {
	algorithm       signingAlgorithm
	algorithmSuffix signingAlgorithmSuffix
	scope           scope
	previous        signatureV4
	currentSHA256   []byte
	secretAccessKey string
}

func calculateChunkSignature(data chunkSignatureData) signatureV4 {
	if data.algorithm == algorithmECDSAP256SHA256 {
		panic("not implemented")
	}

	dateTime := data.scope.date.Format(awsISO8601Format)

	b := new(strings.Builder)

	b.WriteString("AWS4-")
	b.WriteString(data.algorithm.String())
	b.WriteString(data.algorithmSuffix.String())
	b.WriteByte('\n')
	b.WriteString(dateTime)
	b.WriteByte('\n')
	b.WriteString(data.scope.String())
	b.WriteByte('\n')
	b.WriteString(data.previous.String())
	b.WriteByte('\n')

	if data.algorithmSuffix == algorithmSuffixPayload {
		b.WriteString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		b.WriteByte('\n')
	}

	hex.NewEncoder(b).Write(data.currentSHA256)

	key := signingKeyHMACSHA256(data.secretAccessKey, dateTime, data.scope.region, data.scope.service)

	return mustNewSignatureV4FromDecoded(hmacSHA256(key, b.String()))
}
