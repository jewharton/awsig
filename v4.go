package awsig

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

var (
	ErrNotImplemented = errors.New("not implemented")

	ErrDecodedContentLengthExceeded  = errors.New("decoded content length exceeded")
	ErrDecodedContentLengthIncorrect = errors.New("decoded content length incorrect")
	ErrChunkMalformed                = errors.New("chunk malformed") // TODO(amwolff): this is likely incorrect
	ErrSignatureMalformed            = errors.New("signature malformed")

	ErrInvalidArgument              = errors.New("invalid argument")
	ErrAuthorizationHeaderMalformed = errors.New("the authorization header that you provided is not valid")

	ErrAuthorizationQueryParametersError = errors.New("the authorization query parameters that you provided are not valid")
	ErrAccessDenied                      = errors.New("access denied")
	ErrAccountProblem                    = errors.New("there is a problem with your AWS account that prevents the operation from completing successfully")
	ErrAllAccessDisabled                 = errors.New("all access to this Amazon S3 resource has been disabled")
	ErrCredentialsNotSupported           = errors.New("this request does not support credentials")
	ErrCrossLocationLoggingProhibited    = errors.New("cross-region logging is not allowed")
	ErrExpiredToken                      = errors.New("the provided token has expired")
	ErrInvalidAccessKeyID                = errors.New("the AWS access key ID that you provided does not exist in our records")
	ErrInvalidObjectState                = errors.New("the operation is not valid for the current state of the object")
	ErrInvalidSecurity                   = errors.New("the provided security credentials are not valid")
	ErrInvalidSignature                  = errors.New("the request signature that the server calculated does not match the signature that you provided")
	ErrInvalidToken                      = errors.New("the provided token is malformed or otherwise not valid")
	ErrMissingAuthenticationToken        = errors.New("the request was not signed")
	ErrMissingSecurityElement            = errors.New("the SOAP 1.1 request is missing a security element")
	ErrMissingSecurityHeader             = errors.New("your request is missing a required header")
	ErrNotSignedUp                       = errors.New("your account is not signed up for the Amazon S3 service")
	ErrRequestTimeTooSkewed              = errors.New("the difference between the request time and the server's time is too large")
	ErrSignatureDoesNotMatch             = errors.New("the request signature that the server calculated does not match the signature that you provided")
	ErrUnauthorizedAccess                = errors.New("unauthorized access")
	ErrUnexpectedIPError                 = errors.New("this request was rejected because the IP was unexpected")
	ErrUnsupportedSignature              = errors.New("the provided request is signed with an unsupported STS Token version or the signature version is not supported")
)

const (
	headerDate     = "date"
	headerXAmzDate = "x-amz-date"

	headerAuthorization = "authorization"

	authorizationHeaderCredentialPrefix     = "Credential="
	authorizationHeaderSignedHeadersPrefix  = "SignedHeaders="
	authorizationHeaderSignaturePrefix      = "Signature="
	authorizationHeaderCredentialTerminator = "aws4_request"

	headerXAmzContentSha256 = "x-amz-content-sha256"

	unsignedPayload                            = "UNSIGNED-PAYLOAD"
	streamingUnsignedPayloadTrailer            = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	streamingAWS4HMACSHA256Payload             = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	streamingAWS4HMACSHA256PayloadTrailer      = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	streamingAWS4ECDSAP256SHA256Payload        = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD"
	streamingAWS4ECDSAP256SHA256PayloadTrailer = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER"

	queryXAmzAlgorithm     = "X-Amz-Algorithm"
	queryXAmzCredential    = "X-Amz-Credential"
	queryXAmzDate          = "X-Amz-Date"
	queryXAmzExpires       = "X-Amz-Expires"
	queryXAmzSignedHeaders = "X-Amz-SignedHeaders"
	queryXAmzSignature     = "X-Amz-Signature"

	signatureV4DecodedLength = 32
	signatureV4EncodedLength = 64

	chunkMaxLengthEncoded        = "140000000"
	chunkMaxLength               = 5368709120 // 5 GiB
	chunkMinLength               = 8000       // 8 KB
	chunkSignaturePrefix         = "chunk-signature="
	chunkTrailingHeaderPrefix    = "x-amz-checksum-"
	chunkTrailingSignaturePrefix = "x-amz-trailer-signature:"

	cr = '\r'
	lf = '\n'
)

type V4Reader struct {
	r  io.Reader
	ir *integrityReader

	unsigned        bool
	multipleChunks  bool
	trailingHeader  bool
	trailingSumAlgo checksumAlgorithm

	signingAlgo     signingAlgorithm
	dateTime        string
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

func (r *V4Reader) readChunkMeta(buf []byte) (int, signatureV4, error) {
	length, err := r.readChunkLength(buf)
	if err != nil {
		return 0, nil, err
	}

	var signature signatureV4

	if !r.unsigned {
		signature, err = r.readChunkSignature(chunkSignaturePrefix, buf)
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

		signature := calculateSignature(signatureData{
			algorithm:       r.signingAlgo,
			algorithmSuffix: algorithmSuffixTrailer,
			dateTime:        r.dateTime,
			scope:           r.scope,
			previous:        r.chunkPreviousSignature,
			digest:          trailingHash,
		}, r.secretAccessKey)
		if !expected.compare(signature) {
			return ErrSignatureDoesNotMatch
		}
	} else {
		if err = r.consumeCRLF(buf); err != nil {
			return err
		}
	}

	return nil
}

func (r *V4Reader) currentChunkSignatureData() signatureData {
	return signatureData{
		algorithm:       r.signingAlgo,
		algorithmSuffix: algorithmSuffixPayload,
		dateTime:        r.dateTime,
		scope:           r.scope,
		previous:        r.chunkPreviousSignature,
		digest:          r.chunkSHA256.Sum(nil),
	}
}

func (r *V4Reader) close(buf []byte) error {
	if r.decodedContentLength != 0 {
		return ErrDecodedContentLengthIncorrect
	}

	if !r.unsigned {
		signature := calculateSignature(r.currentChunkSignatureData(), r.secretAccessKey)
		if !r.chunkExpectedSignature.compare(signature) {
			return ErrSignatureDoesNotMatch
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

		length, signature, err := r.readChunkMeta(p)
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
			signature := calculateSignature(r.currentChunkSignatureData(), r.secretAccessKey)
			if !r.chunkExpectedSignature.compare(signature) {
				return n, ErrSignatureDoesNotMatch
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

// TODO(amwolff): create a constructor for V4Reader taking readerOptions

type CredentialsProvider interface {
	Provide(accessKeyID string) (secretAccessKey string, _ error)
}

type V4 struct {
	provider CredentialsProvider
	region   string
	service  string

	now func() time.Time
}

func (v4 *V4) parseSigningAlgo(rawAlgorithm string) (signingAlgorithm, error) {
	if !strings.HasPrefix(rawAlgorithm, authorizationHeaderSignaturePrefix) {
		return 0, errors.Join(
			ErrAuthorizationHeaderMalformed,
			errors.New("the Algorithm parameter is missing"),
		)
	}
	rawAlgorithm = rawAlgorithm[len(authorizationHeaderSignaturePrefix):]

	switch strings.TrimPrefix(rawAlgorithm, signingAlgorithmPrefix) {
	case algorithmHMACSHA256.String():
		return algorithmHMACSHA256, nil
	case algorithmECDSAP256SHA256.String():
		return 0, errors.Join(
			ErrNotImplemented,
			errors.New("calculation using the AWS4-ECDSA-P256-SHA256 algorithm is not implemented yet"),
		)
	default:
		return 0, errors.Join(
			ErrInvalidArgument,
			errors.New("the Authorization header does not contain a valid signing algorithm"),
		)
	}
}

type parsedCredential struct {
	accessKeyID string
	scope       scope
}

func (v4 *V4) parseCredential(rawCredential string, expectedDate time.Time) (parsedCredential, error) {
	if !strings.HasPrefix(rawCredential, authorizationHeaderCredentialPrefix) {
		return parsedCredential{}, errors.Join(
			ErrAuthorizationHeaderMalformed,
			errors.New("the Credential parameter is missing"),
		)
	}

	parts := strings.SplitN(rawCredential[len(authorizationHeaderCredentialPrefix):], "/", 5)

	if len(parts) != 5 {
		return parsedCredential{}, errors.Join(
			ErrInvalidArgument,
			errors.New("the Credential parameter does not contain necessary parts"),
		)
	}

	// TODO(amwolff): optional Access Key ID validation

	date, err := time.Parse(timeFormatYYYYMMDD, parts[1])
	if err != nil {
		return parsedCredential{}, errors.Join(
			ErrInvalidArgument,
			fmt.Errorf("the Credential parameter does not contain a valid date: %w", err),
		)
	}

	if date.Year() != expectedDate.Year() || date.Month() != expectedDate.Month() || date.Day() != expectedDate.Day() {
		return parsedCredential{}, errors.Join(
			ErrInvalidArgument,
			errors.New("the Credential parameter does not contain the expected date"),
		)
	}

	if parts[2] != v4.region { // TODO(amwolff): make region validation optional
		return parsedCredential{}, errors.Join(
			ErrInvalidArgument,
			errors.New("the Credential parameter does not contain the expected region"),
		)
	}

	if parts[3] != v4.service {
		return parsedCredential{}, errors.Join(
			ErrInvalidArgument,
			errors.New("the Credential parameter does not contain the expected service"),
		)
	}

	if parts[4] != authorizationHeaderCredentialTerminator {
		return parsedCredential{}, errors.Join(
			ErrInvalidArgument,
			errors.New("the Credential parameter does not contain the expected terminator"),
		)
	}

	return parsedCredential{
		accessKeyID: parts[0],
		scope: scope{
			date:    parts[1],
			region:  parts[2],
			service: parts[3],
		},
	}, nil
}

func (v4 *V4) parseSignedHeaders(rawSignedHeaders string, actualHeaders http.Header) ([]string, error) {
	if !strings.HasPrefix(rawSignedHeaders, authorizationHeaderSignedHeadersPrefix) {
		return nil, errors.Join(
			ErrAuthorizationHeaderMalformed,
			errors.New("the SignedHeaders parameter is missing"),
		)
	}
	rawSignedHeaders = rawSignedHeaders[len(authorizationHeaderSignedHeadersPrefix):]

	// TODO(amwolff): there's a lot of senseless copying going on here ↓

	signedHeaders := strings.Split(rawSignedHeaders, ";")
	signedHeadersLookup := make(map[string]struct{})

	var hostFound bool
	for _, header := range signedHeaders {
		if strings.EqualFold(header, "host") {
			hostFound = true
		}
		signedHeadersLookup[textproto.CanonicalMIMEHeaderKey(header)] = struct{}{}
	}

	// …

	for key := range textproto.MIMEHeader(actualHeaders) {
		if strings.EqualFold(key, headerXAmzContentSha256) {
			continue
		}
		if strings.HasPrefix(key, "X-Amz-") {
			if _, ok := signedHeadersLookup[key]; !ok {
				// oops
			}
		}
	}

	return nil, nil
}

func (v4 *V4) parseSignature(rawSignature string) (signatureV4, error) {
	if !strings.HasPrefix(rawSignature, authorizationHeaderSignaturePrefix) {
		return nil, errors.Join(
			ErrAuthorizationHeaderMalformed,
			errors.New("the Signature parameter is missing"),
		)
	}
	rawSignature = rawSignature[len(authorizationHeaderSignaturePrefix):]

	signature, err := newSignatureV4FromEncoded([]byte(rawSignature))
	if err != nil {
		return nil, errors.Join(
			ErrInvalidArgument,
			fmt.Errorf("the Signature parameter does not contain a valid signature: %w", err),
		)
	}

	return signature, nil
}

type parsedAuthorization struct {
	signingAlgo   signingAlgorithm
	credential    parsedCredential
	signedHeaders []string
	signature     signatureV4
}

func (v4 *V4) parseAuthorization(rawAuthorization string, expectedDate time.Time, headers http.Header) (parsedAuthorization, error) {
	rawAlgorithm, afterAlgorithm, ok := strings.Cut(rawAuthorization, " ")
	if !ok {
		return parsedAuthorization{}, errors.Join(
			ErrAuthorizationHeaderMalformed,
			errors.New("the Authorization header does not contain expected parts"),
		)
	}

	signingAlgo, err := v4.parseSigningAlgo(rawAlgorithm)
	if err != nil {
		return parsedAuthorization{}, err
	}

	pairs := strings.SplitN(afterAlgorithm, ",", 3)

	if len(pairs) != 3 {
		return parsedAuthorization{}, errors.Join(
			ErrAuthorizationHeaderMalformed,
			errors.New("the Authorization header does not contain expected key=value pairs"),
		)
	}

	credential, err := v4.parseCredential(pairs[0], expectedDate)
	if err != nil {
		return parsedAuthorization{}, err
	}

	signedHeaders, err := v4.parseSignedHeaders(pairs[1], headers)
	if err != nil {
		return parsedAuthorization{}, err
	}

	signature, err := v4.parseSignature(pairs[2])
	if err != nil {
		return parsedAuthorization{}, err
	}

	return parsedAuthorization{
		signingAlgo:   signingAlgo,
		credential:    credential,
		signedHeaders: signedHeaders,
		signature:     signature,
	}, nil
}

type parsedXAmzContentSHA256 struct {
	unsigned             bool
	streaming            bool
	signingAlgo          signingAlgorithm
	trailer              bool
	decodedContentLength int
}

func (v4 *V4) parseXAmzContentSHA256(rawXAmzContentSHA256 string) (parsedXAmzContentSHA256, error) {
	switch rawXAmzContentSHA256 {
	case unsignedPayload:
		return parsedXAmzContentSHA256{
			unsigned: true,
		}, nil
	case streamingUnsignedPayloadTrailer:
		return parsedXAmzContentSHA256{
			unsigned:  true,
			streaming: true,
			trailer:   true,
		}, nil
	case streamingAWS4HMACSHA256Payload:
		return parsedXAmzContentSHA256{
			streaming:   true,
			signingAlgo: algorithmHMACSHA256,
		}, nil
	case streamingAWS4HMACSHA256PayloadTrailer:
		return parsedXAmzContentSHA256{
			streaming:   true,
			signingAlgo: algorithmHMACSHA256,
			trailer:     true,
		}, nil
	case streamingAWS4ECDSAP256SHA256Payload, streamingAWS4ECDSAP256SHA256PayloadTrailer:
		return parsedXAmzContentSHA256{}, fmt.Errorf("(streaming) calculation using the AWS4-ECDSA-P256-SHA256 algorithm is not implemented yet: %w", ErrNotImplemented)
	}

	return parsedXAmzContentSHA256{}, nil
}

func (v4 *V4) determineIntegrity(options parsedXAmzContentSHA256, headers http.Header) (checksumAlgorithm, expectedIntegrity, error) {
	return 0, expectedIntegrity{}, ErrNotImplemented
}

type requestData struct { // TODO(amwolff): make this readerOptions
	options          parsedXAmzContentSHA256
	integritySumAlgo checksumAlgorithm // TODO(amwolff): there can be multiple integrity algorithms, so this should be a slice (an individual one for the trailer, though)
	integrity        expectedIntegrity
	dateTime         string
	scope            scope
	secretAccessKey  string
	seedSignature    signatureV4
}

func (v4 *V4) verify(r *http.Request) (requestData, error) {
	rawDate := r.Header.Get("x-amz-date")
	if rawDate == "" {
		rawDate = r.Header.Get("date")
	}

	parsedDateTime, err := time.Parse(timeFormatISO8601, rawDate)
	if err != nil {
		return requestData{}, errors.Join(
			ErrInvalidArgument,
			fmt.Errorf("the x-amz-date or date header does not contain a valid date: %w", err),
		)
	}

	if skew := v4.now().Sub(parsedDateTime); skew < -15*time.Minute || skew > 15*time.Minute {
		return requestData{}, ErrRequestTimeTooSkewed
	}

	authorization, err := v4.parseAuthorization(r.Header.Get("authorization"), parsedDateTime, r.Header)
	if err != nil {
		return requestData{}, err
	}

	rawXAmzContentSHA256 := r.Header.Get(headerXAmzContentSha256)
	if rawXAmzContentSHA256 == "" {
		// error?
	}

	options, err := v4.parseXAmzContentSHA256(rawXAmzContentSHA256)
	if err != nil {
		return requestData{}, err
	}

	integritySumAlgo, integrity, err := v4.determineIntegrity(options, r.Header)
	if err != nil {
		return requestData{}, err
	}

	// TODO(amwolff): build canonical request

	secretAccessKey, err := v4.provider.Provide(authorization.credential.accessKeyID)
	if err != nil {
		return requestData{}, err
	}

	signature := calculateSignature(signatureData{
		algorithm:       authorization.signingAlgo,
		algorithmSuffix: algorithmSuffixNone,
		dateTime:        rawDate,
		scope:           authorization.credential.scope,
		previous:        nil,
		// TODO(amwolff): digest is hex(sha256hash(canonical request))
	}, secretAccessKey)

	if !signature.compare(authorization.signature) {
		return requestData{}, ErrSignatureDoesNotMatch
	}

	return requestData{
		options:          options,
		integritySumAlgo: integritySumAlgo,
		integrity:        integrity,
		dateTime:         rawDate,
		scope:            authorization.credential.scope,
		secretAccessKey:  secretAccessKey,
		seedSignature:    signature,
	}, nil
}

func (v4 *V4) verifyPresigned(r *http.Request) (requestData, error) {
	return requestData{}, nil
}

func (v4 *V4) Verify(r *http.Request) (*V4Reader, error) {
	if r.Header.Get(headerAuthorization) != "" {
		data, err := v4.verify(r)
		if err != nil {
			return nil, err
		}

		var (
			ir          *integrityReader
			chunkSHA256 hash.Hash
		)

		if !data.options.unsigned {
			chunkSHA256 = sha256.New()
			ir = newIntegrityReader(io.TeeReader(r.Body, chunkSHA256))
		} else {
			ir = newIntegrityReader(r.Body)
		}

		return &V4Reader{
			r:                      r.Body,
			ir:                     ir,
			unsigned:               data.options.unsigned,
			multipleChunks:         data.options.streaming,
			trailingHeader:         data.options.trailer,
			trailingSumAlgo:        data.integritySumAlgo,
			signingAlgo:            data.options.signingAlgo,
			dateTime:               data.dateTime,
			scope:                  data.scope,
			secretAccessKey:        data.secretAccessKey,
			integrity:              data.integrity,
			decodedContentLength:   data.options.decodedContentLength,
			chunkSHA256:            chunkSHA256,
			chunkPreviousSignature: data.seedSignature,
		}, nil
	} else if r.URL.Query().Has(queryXAmzAlgorithm) {
		data, err := v4.verifyPresigned(r)
		if err != nil {
			return nil, err
		}

		var (
			ir          *integrityReader
			chunkSHA256 hash.Hash
		)

		if !data.options.unsigned { // TODO(amwolff): can these options be even used for presigned requests?
			chunkSHA256 = sha256.New()
			ir = newIntegrityReader(io.TeeReader(r.Body, chunkSHA256))
		} else {
			ir = newIntegrityReader(r.Body)
		}

		return &V4Reader{
			r:                      r.Body,
			ir:                     ir,
			unsigned:               data.options.unsigned,
			multipleChunks:         data.options.streaming,
			trailingHeader:         data.options.trailer,
			trailingSumAlgo:        data.integritySumAlgo,
			signingAlgo:            data.options.signingAlgo,
			dateTime:               data.dateTime,
			scope:                  data.scope,
			secretAccessKey:        data.secretAccessKey,
			integrity:              data.integrity,
			decodedContentLength:   data.options.decodedContentLength,
			chunkSHA256:            chunkSHA256,
			chunkPreviousSignature: data.seedSignature,
		}, nil
	} else if r.Method == http.MethodPost {
		return nil, fmt.Errorf("authenticating HTTP POST requests is not implemented yet: %w", ErrNotImplemented)
	}
	return nil, ErrMissingAuthenticationToken
}

func NewV4(provider CredentialsProvider, region, service string) *V4 {
	return &V4{
		provider: provider,
		region:   region,
		service:  service,
		now:      time.Now,
	}
}
