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

	chunkMaxLengthEncoded        = "140000000"
	chunkMaxLength               = 5368709120 // 5 GiB
	chunkMinLength               = 8000       // 8 KB
	chunkSignatureHeader         = "chunk-signature="
	chunkTrailingHeaderPrefix    = "x-amz-checksum-"
	chunkTrailingSignaturePrefix = "x-amz-trailer-signature:"

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

	signingAlgo     signingAlgorithm
	scope           scope
	secretAccessKey string

	integrity            expectedIntegrity
	decodedContentLength int

	chunkCount             int
	chunkBytesLeft         int
	chunkSHA256            hash.Hash
	chunkPreviousSignature signatureV4
	chunkExpectedSignature signatureV4
}

func (r *V4Reader) consumeLF(buf []byte) error {
	buf, err := reuseBuffer(buf, 1)
	if err != nil {
		return err
	}

	if _, err = io.ReadFull(r.r, buf); err != nil {
		return err
	}

	if buf[0] != lf {
		return ErrChunkMalformed
	}

	return nil
}

func (r *V4Reader) consumeCRLF(buf []byte) error {
	buf, err := reuseBuffer(buf, 2)
	if err != nil {
		return err
	}

	if _, err = io.ReadFull(r.r, buf); err != nil {
		return err
	}

	if buf[0] != cr || buf[1] != lf {
		return ErrChunkMalformed
	}

	return nil
}

func (r *V4Reader) readChunkLength(buf []byte) (int, error) {
	var (
		rawLength      []byte
		separatorFound bool
	)

	buf, err := reuseBuffer(buf, 1)
	if err != nil {
		return 0, err
	}

	for i := 0; i < len(chunkMaxLengthEncoded) && !separatorFound; i++ {
		if _, err = io.ReadFull(r.r, buf); err != nil {
			return 0, err
		}

		if buf[0] == cr {
			if !r.unsigned {
				return 0, ErrChunkMalformed
			}

			if err = r.consumeLF(buf); err != nil {
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

func (r *V4Reader) readChunkSignature(prefix string, buf []byte) (signatureV4, error) {
	buf, err := reuseBuffer(buf, len(prefix)+signatureV4EncodedLength)
	if err != nil {
		return nil, err
	}

	if _, err = io.ReadFull(r.r, buf); err != nil {
		return nil, err
	}

	rawSignature := bytes.TrimPrefix(buf, []byte(prefix))

	signature, err := newSignatureV4FromEncoded(rawSignature)
	if err != nil {
		return nil, ErrChunkMalformed
	}

	return signature, r.consumeCRLF(buf)
}

func (r *V4Reader) readChunkHeader(buf []byte) (int, signatureV4, error) {
	length, err := r.readChunkLength(buf)
	if err != nil {
		return 0, nil, err
	}

	var signature signatureV4

	if !r.unsigned {
		signature, err = r.readChunkSignature(chunkSignatureHeader, buf)
		if err != nil {
			return 0, nil, err
		}
	}

	return length, signature, nil
}

func (r *V4Reader) readChunkTrailer(buf []byte) error {
	name := chunkTrailingHeaderPrefix + r.trailingSumAlgo.String() + ":"

	length := len(name)
	length += r.trailingSumAlgo.base64Length()

	buf, err := reuseBuffer(buf, length+1) // +1 for the trailing LF
	if err != nil {
		return err
	}

	if _, err = io.ReadFull(r.r, buf); err != nil {
		return err
	}

	if !bytes.HasPrefix(buf, []byte(name)) {
		return ErrChunkMalformed
	}

	r.integrity.add(r.trailingSumAlgo, string(buf[len(name):len(buf)-1]))

	var (
		trailingByte = buf[len(buf)-1]
		trailingHash []byte
	)

	if !r.unsigned {
		buf[len(buf)-1] = lf
		trailingHash = sha256Hash(buf)
	}

	switch trailingByte {
	case cr:
		if err = r.consumeLF(buf); err != nil {
			return err
		}
	case lf:
		if err = r.consumeCRLF(buf); err != nil {
			return err
		}
	default:
		return ErrChunkMalformed
	}

	if !r.unsigned {
		expected, err := r.readChunkSignature(chunkTrailingSignaturePrefix, buf)
		if err != nil {
			return err
		}

		signature := calculateChunkSignature(chunkSignatureData{
			algorithm:       r.signingAlgo,
			algorithmSuffix: algorithmSuffixTrailer,
			scope:           r.scope,
			previous:        r.chunkPreviousSignature,
			currentSHA256:   trailingHash,
			secretAccessKey: r.secretAccessKey,
		})
		if !expected.compare(signature) {
			return ErrSignatureMismatch
		}
	} else {
		if err = r.consumeCRLF(buf); err != nil {
			return err
		}
	}

	return nil
}

func (r *V4Reader) currentChunkSignatureData() chunkSignatureData {
	return chunkSignatureData{
		algorithm:       r.signingAlgo,
		algorithmSuffix: algorithmSuffixPayload,
		scope:           r.scope,
		previous:        r.chunkPreviousSignature,
		currentSHA256:   r.chunkSHA256.Sum(nil),
		secretAccessKey: r.secretAccessKey,
	}
}

func (r *V4Reader) close(buf []byte) error {
	if r.decodedContentLength != 0 {
		return ErrDecodedContentLengthIncorrect
	}

	if !r.unsigned {
		signature := calculateChunkSignature(r.currentChunkSignatureData())
		if !r.chunkExpectedSignature.compare(signature) {
			return ErrSignatureMismatch
		}
		r.chunkPreviousSignature = signature
	}

	if r.trailingHeader {
		if err := r.readChunkTrailer(buf); err != nil {
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}

	if err := r.consumeCRLF(buf); !errors.Is(err, io.EOF) {
		return ErrChunkMalformed
	}

	if err := r.ir.verify(r.integrity); err != nil {
		return err
	}

	return io.EOF
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
		if r.chunkCount > 0 {
			if err = r.consumeCRLF(p); err != nil {
				if errors.Is(err, io.EOF) {
					return n, io.ErrUnexpectedEOF
				}
				return n, err
			}
		}

		length, signature, err := r.readChunkHeader(p)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return n, io.ErrUnexpectedEOF
			}
			return n, err
		}

		r.chunkBytesLeft = length

		if !r.unsigned {
			r.chunkSHA256.Reset()
			r.chunkExpectedSignature = signature
		}

		if length == 0 { // completion chunk
			return n, r.close(p)
		}
	}

	if len(p) > r.chunkBytesLeft {
		p = p[:r.chunkBytesLeft]
	}

	n, err = r.ir.Read(p)

	if r.chunkBytesLeft -= n; r.chunkBytesLeft == 0 {
		r.chunkCount++
		if !r.unsigned {
			signature := calculateChunkSignature(r.currentChunkSignatureData())
			if !r.chunkExpectedSignature.compare(signature) {
				return n, ErrSignatureMismatch
			}
			r.chunkPreviousSignature = signature
		}
	}

	if r.decodedContentLength -= n; r.decodedContentLength < 0 {
		return n, ErrDecodedContentLengthExceeded
	}

	if errors.Is(err, io.EOF) {
		return n, io.ErrUnexpectedEOF
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
