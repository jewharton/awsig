package awsig

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"time"
)

var (
	ErrNotImplemented = errors.New("not implemented")

	ErrNotFound = errors.New("authentication credentials not found")

	ErrDecodedContentLengthExceeded  = errors.New("decoded content length exceeded")
	ErrDecodedContentLengthIncorrect = errors.New("decoded content length incorrect")

	ErrChunkMalformed = errors.New("chunk malformed")

	ErrSignatureMismatch  = errors.New("signature mismatch")
	ErrSignatureMalformed = errors.New("signature malformed")
)

const (
	headerAuthorization     = "authorization"
	headerXAmzContentSha256 = "x-amz-content-sha256"

	queryXAmzAlgorithm     = "X-Amz-Algorithm"
	queryXAmzCredential    = "X-Amz-Credential"
	queryXAmzDate          = "X-Amz-Date"
	queryXAmzExpires       = "X-Amz-Expires"
	queryXAmzSignedHeaders = "X-Amz-SignedHeaders"
	queryXAmzSignature     = "X-Amz-Signature"

	unsignedPayload                            = "UNSIGNED-PAYLOAD"
	streamingUnsignedPayloadTrailer            = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	streamingAWS4HMACSHA256Payload             = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	streamingAWS4HMACSHA256PayloadTrailer      = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	streamingAWS4ECDSAP256SHA256Payload        = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD"
	streamingAWS4ECDSAP256SHA256PayloadTrailer = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER"

	signatureV4DecodedLength = 32
	signatureV4EncodedLength = 64

	chunkMaxLengthEncoded     = "140000000"
	chunkMaxLength            = 5368709120 // 5 GiB
	chunkMinLength            = 8000       // 8 KB
	chunkSignatureHeader      = "chunk-signature="
	chunkTrailingHeaderPrefix = "x-amz-checksum-"

	cr = '\r'
	lf = '\n'
)

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

type CredentialsProvider interface {
	Credentials(accessKeyID string) (Credentials, error)
}

type V4 struct {
	provider CredentialsProvider
	region   string
	service  string

	now func() time.Time
}

type V4Reader struct {
	r  io.Reader
	ir *integrityReader

	unsigned        bool
	multipleChunks  bool
	trailingHeader  bool
	trailingSumAlgo checksumAlgorithm
	date            time.Time

	integrity            expectedIntegrity
	decodedContentLength int

	chunkBytesLeft         int
	chunkSHA256            hash.Hash
	chunkPreviousSignature signatureV4
	chunkExpectedSignature signatureV4
}

func (r *V4Reader) consumeLF() error {
	buf := make([]byte, 1)

	if _, err := io.ReadFull(r.r, buf); err != nil {
		return err
	}

	if buf[0] != lf {
		return ErrChunkMalformed
	}

	return nil
}

func (r *V4Reader) consumeCRLF() error {
	expected := []byte{cr, lf}
	actual := make([]byte, len(expected))

	if _, err := io.ReadFull(r.r, actual); err != nil {
		return err
	}

	if !bytes.Equal(expected, actual) {
		return ErrChunkMalformed
	}

	return nil
}

func (r *V4Reader) readChunkLength() (int, error) {
	var (
		rawLength      []byte
		separatorFound bool
	)

	for i := 0; i < len(chunkMaxLengthEncoded) && !separatorFound; i++ {
		buf := make([]byte, 1)

		if _, err := io.ReadFull(r.r, buf); err != nil {
			return 0, err
		}

		if buf[0] == cr {
			if !r.unsigned {
				return 0, ErrChunkMalformed
			}

			if err := r.consumeLF(); err != nil {
				return 0, err
			}

			separatorFound = true
			break
		} else if buf[0] == ';' {
			if r.unsigned {
				return 0, ErrChunkMalformed
			}

			separatorFound = true
			break
		} else {
			rawLength = append(rawLength, buf[0])
		}
	}

	if !separatorFound {
		return 0, ErrChunkMalformed
	}

	length, err := strconv.ParseInt(string(rawLength), 16, 64)
	if err != nil {
		return 0, ErrChunkMalformed
	}

	if length != 0 && length < chunkMinLength { // this could be the last chunk
		return 0, ErrChunkMalformed
	}
	if length > chunkMaxLength {
		return 0, ErrChunkMalformed
	}

	return int(length), nil
}

func (r *V4Reader) readChunkSignature() (signatureV4, error) {
	if r.unsigned {
		return nil, nil
	}

	rawSignatureWithHeader := make([]byte, len(chunkSignatureHeader)+signatureV4EncodedLength)

	if _, err := io.ReadFull(r.r, rawSignatureWithHeader); err != nil {
		return nil, err
	}

	rawSignature := bytes.TrimPrefix(rawSignatureWithHeader, []byte(chunkSignatureHeader))

	signature, err := newSignatureV4FromEncoded(rawSignature)
	if err != nil {
		return nil, ErrChunkMalformed
	}

	return signature, r.consumeCRLF()
}

func (r *V4Reader) readChunkSignatureWithoutHeader() (signatureV4, error) {
	if r.unsigned {
		return nil, nil
	}

	rawSignature := make([]byte, signatureV4EncodedLength)

	if _, err := io.ReadFull(r.r, rawSignature); err != nil {
		return nil, err
	}

	signature, err := newSignatureV4FromEncoded(rawSignature)
	if err != nil {
		return nil, ErrChunkMalformed
	}

	return signature, r.consumeCRLF()
}

func (r *V4Reader) readChunkHeader() (int, signatureV4, error) {
	length, err := r.readChunkLength()
	if err != nil {
		return 0, nil, err
	}

	signature, err := r.readChunkSignature()
	if err != nil {
		return 0, nil, err
	}

	return length, signature, nil
}

func (r *V4Reader) readChunkTrailer() error {
	name := chunkTrailingHeaderPrefix + r.trailingSumAlgo.String() + ":"

	length := len(name)
	length += r.trailingSumAlgo.base64Length()

	buf := make([]byte, length+1) // +1 for the trailing LF

	if _, err := io.ReadFull(r.r, buf); err != nil {
		return err
	}

	if !bytes.HasPrefix(buf, []byte(name)) {
		return ErrChunkMalformed
	}

	r.integrity.add(r.trailingSumAlgo, string(buf[len(name):len(buf)-1]))

	switch buf[len(buf)-1] {
	case cr:
		if err := r.consumeLF(); err != nil {
			return err
		}
	case lf:
		if err := r.consumeCRLF(); err != nil {
			return err
		}
	default:
		return ErrChunkMalformed
	}

	if !r.unsigned {
		expected, err := r.readChunkSignatureWithoutHeader()
		if err != nil {
			return err
		}

		buf[len(buf)-1] = lf

		signature := calculateTrailerChunkSignature(r.chunkPreviousSignature, buf)
		if !expected.compare(signature) {
			return ErrSignatureMismatch
		}
	} else {
		if err := r.consumeCRLF(); err != nil {
			return err
		}
	}

	return nil
}

func (r *V4Reader) close() error {
	if r.decodedContentLength != 0 {
		return ErrDecodedContentLengthIncorrect
	}

	if !r.unsigned {
		signature := calculateRegularChunkSignature(r.chunkPreviousSignature, chunkSignatureData{})
		if !r.chunkExpectedSignature.compare(signature) {
			return ErrSignatureMismatch
		}
		r.chunkPreviousSignature = signature
	}

	if r.trailingHeader {
		if err := r.readChunkTrailer(); err != nil {
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}

	if err := r.consumeCRLF(); !errors.Is(err, io.EOF) {
		return ErrChunkMalformed
	}

	if err := r.ir.verify(r.integrity); err != nil {
		return err
	}

	return io.EOF
}

func (r *V4Reader) currentChunkSignatureData() chunkSignatureData {
	return chunkSignatureData{}
}

func (r *V4Reader) Read(p []byte) (n int, err error) {
	if !r.multipleChunks { // fast path for single chunk
		if n, err = r.ir.Read(p); errors.Is(err, io.EOF) {
			if err := r.ir.verify(r.integrity); err != nil {
				return n, err
			}
		}
		return n, err
	}

	if r.chunkBytesLeft == 0 {
		length, signature, err := r.readChunkHeader()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return n, io.ErrUnexpectedEOF
			}
			return n, err
		}

		if length == 0 {
			return n, r.close()
		}

		r.chunkBytesLeft = length

		if !r.unsigned {
			r.chunkSHA256.Reset()
			r.chunkExpectedSignature = signature
		}
	}

	if len(p) > r.chunkBytesLeft {
		p = p[:r.chunkBytesLeft]
	}

	n, err = r.ir.Read(p)

	if r.chunkBytesLeft -= n; r.chunkBytesLeft == 0 && !r.unsigned {
		signature := calculateRegularChunkSignature(r.chunkPreviousSignature, r.currentChunkSignatureData())
		if !r.chunkExpectedSignature.compare(signature) {
			return n, ErrSignatureMismatch
		}
		r.chunkPreviousSignature = signature
	}

	if r.decodedContentLength -= n; r.decodedContentLength < 0 {
		return n, ErrDecodedContentLengthExceeded
	}

	if errors.Is(err, io.EOF) {
		return n, io.ErrUnexpectedEOF
	}

	if r.chunkBytesLeft == 0 {
		if r.consumeCRLF(); err != nil {
			if errors.Is(err, io.EOF) {
				return n, io.ErrUnexpectedEOF
			}
			return n, err
		}
	}

	return n, err
}

func (v4 *V4) Validate(r *http.Request) (*V4Reader, error) {
	if r.Header.Get(headerAuthorization) != "" {
		data := extractDataFromHeaders(r)
		signature := calculateSeedSignature(data)

		chunkSHA256 := sha256.New()
		return &V4Reader{
			r:  r.Body,
			ir: newIntegrityReader(io.TeeReader(r.Body, chunkSHA256)), // if signed
			// …
		}, nil
	} else if r.URL.Query().Has(queryXAmzAlgorithm) {
		data := extractDataFromQuery(r)
		signature := calculateSeedSignature(data)

		chunkSHA256 := sha256.New()
		return &V4Reader{
			r:  r.Body,
			ir: newIntegrityReader(io.TeeReader(r.Body, chunkSHA256)), // if signed
		}, nil
	} else if r.Method == http.MethodPost {
		return nil, fmt.Errorf("authenticating HTTP POST requests is not implemented yet: %w", ErrNotImplemented)
	}
	return nil, ErrNotFound
}

func NewV4(provider CredentialsProvider, region, service string) *V4 {
	return &V4{
		provider: provider,
		region:   region,
		service:  service,
		now:      time.Now,
	}
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

type chunkSignatureData struct {
	algorithm string
	date      string
	region    string
}

func calculateRegularChunkSignature(previous signatureV4, data chunkSignatureData) signatureV4 {
	return nil
}

func calculateTrailerChunkSignature(previous signatureV4, header []byte) signatureV4 {
	return nil
}
