package awsig

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	headerContentLength            = "content-length"
	headerHost                     = "host"
	headerTransferEncoding         = "transfer-encoding"
	headerXAmzDecodedContentLength = xAmzHeaderPrefix + "decoded-content-length"
	headerXAmzTrailer              = xAmzHeaderPrefix + "trailer"

	v4AuthorizationHeaderCredentialPrefix     = "Credential="
	v4AuthorizationHeaderSignedHeadersPrefix  = "SignedHeaders="
	v4AuthorizationHeaderSignaturePrefix      = "Signature="
	v4AuthorizationHeaderCredentialTerminator = "aws4_request"

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
	queryXAmzSecurityToken = "X-Amz-Security-Token"
	queryXAmzSignedHeaders = "X-Amz-SignedHeaders"
	queryXAmzSignature     = "X-Amz-Signature"

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

	signingAlgo     v4SigningAlgorithm
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

type v4ReaderOptions struct {
	dateTime        string
	scope           scope
	parsedOptions   parsedXAmzContentSHA256
	parsedIntegrity parsedIntegrity
	secretAccessKey string
	seedSignature   signatureV4
}

func newV4Reader(r io.Reader, data v4ReaderOptions) *V4Reader {
	var (
		ir          *integrityReader
		chunkSHA256 hash.Hash
	)

	if !data.parsedOptions.unsigned {
		chunkSHA256 = sha256.New()
		ir = newIntegrityReader(io.TeeReader(r, chunkSHA256), data.parsedIntegrity.sumAlgos)
	} else {
		ir = newIntegrityReader(r, data.parsedIntegrity.sumAlgos)
	}

	return &V4Reader{
		r:                      r,
		ir:                     ir,
		unsigned:               data.parsedOptions.unsigned,
		multipleChunks:         data.parsedOptions.streaming,
		trailingHeader:         data.parsedOptions.trailer,
		trailingSumAlgo:        data.parsedIntegrity.trailingSumAlgo,
		signingAlgo:            data.parsedOptions.signingAlgo,
		dateTime:               data.dateTime,
		scope:                  data.scope,
		secretAccessKey:        data.secretAccessKey,
		integrity:              data.parsedIntegrity.integrity,
		decodedContentLength:   data.parsedOptions.decodedContentLength,
		chunkSHA256:            chunkSHA256,
		chunkPreviousSignature: data.seedSignature,
	}
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
		return ErrIncompleteBody
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
		return ErrIncompleteBody
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
				return 0, ErrIncompleteBody
			}

			if err = r.consumeLF(buf); err != nil {
				return 0, err
			}

			separatorFound = true
			break
		} else if buf[0] == ';' {
			if r.unsigned {
				return 0, ErrIncompleteBody
			}

			separatorFound = true
			break
		} else {
			rawLength = append(rawLength, buf[0])
		}
	}

	if !separatorFound {
		return 0, ErrIncompleteBody
	}

	length, err := strconv.ParseInt(string(rawLength), 16, 64)
	if err != nil {
		return 0, ErrIncompleteBody
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
		return nil, ErrInvalidSignature
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
		return ErrIncompleteBody
	}

	r.integrity.addEncoded(r.trailingSumAlgo, buf[len(name):len(buf)-1])

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
		return ErrIncompleteBody
	}

	if !r.unsigned {
		expected, err := r.readChunkSignature(chunkTrailingSignaturePrefix, buf)
		if err != nil {
			return err
		}

		signature := calculateSignatureV4(signatureV4Data{
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

func (r *V4Reader) currentChunkSignatureData() signatureV4Data {
	return signatureV4Data{
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
		return ErrIncompleteBody
	}

	if !r.unsigned {
		signature := calculateSignatureV4(r.currentChunkSignatureData(), r.secretAccessKey)
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

	if err := r.consumeCRLF(buf); !errors.Is(err, io.EOF) { // TODO(amwolff): latch the error?
		return ErrIncompleteBody
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
		} else if length > chunkMaxLength {
			return 0, ErrEntityTooLarge
		} else if length < chunkMinLength && r.decodedContentLength > int(length) {
			return 0, ErrEntityTooSmall
		}
	}

	if len(p) > r.chunkBytesLeft {
		p = p[:r.chunkBytesLeft]
	}

	n, err = r.ir.Read(p)

	if r.chunkBytesLeft -= n; r.chunkBytesLeft == 0 {
		r.chunkCount++
		if !r.unsigned {
			signature := calculateSignatureV4(r.currentChunkSignatureData(), r.secretAccessKey)
			if !r.chunkExpectedSignature.compare(signature) {
				return n, ErrSignatureDoesNotMatch
			}
			r.chunkPreviousSignature = signature
		}
	}

	if r.decodedContentLength -= n; r.decodedContentLength < 0 {
		return n, ErrIncompleteBody
	}

	if errors.Is(err, io.EOF) {
		return n, io.ErrUnexpectedEOF
	}

	return n, err
}

func (r *V4Reader) Checksums() (Checksums, error) {
	return r.ir.checksums()
}

type V4 struct {
	provider CredentialsProvider
	region   string
	service  string

	now func() time.Time
}

func NewV4(provider CredentialsProvider, region, service string) *V4 {
	return &V4{
		provider: provider,
		region:   region,
		service:  service,
		now:      time.Now,
	}
}

func (v4 *V4) parseTime(main, alt string) (string, time.Time, error) {
	parsed, err := parseTimeWithFormats(main, []string{timeFormatISO8601})
	if err != nil {
		parsed, err := parseTimeWithFormats(alt, httpTimeFormats)
		if err != nil {
			return "", time.Time{}, err
		}
		return parsed.Format(timeFormatISO8601), parsed, nil
	}
	return main, parsed, nil
}

func (v4 *V4) parseSigningAlgo(rawAlgorithm string) (v4SigningAlgorithm, error) {
	if !strings.HasPrefix(rawAlgorithm, v4SigningAlgorithmPrefix) {
		return 0, nestError(
			ErrUnsupportedSignature,
			"the Algorithm parameter does not contain a valid signing algorithm",
		)
	}

	switch rawAlgorithm[len(v4SigningAlgorithmPrefix):] {
	case algorithmHMACSHA256.String():
		return algorithmHMACSHA256, nil
	case algorithmECDSAP256SHA256.String():
		return 0, nestError(
			ErrNotImplemented,
			"calculation using the AWS4-ECDSA-P256-SHA256 algorithm is not implemented yet",
		)
	default:
		return 0, nestError(
			ErrUnsupportedSignature,
			"the Algorithm parameter does not contain a valid signing algorithm",
		)
	}
}

type parsedCredential struct {
	accessKeyID string
	scope       scope
}

func (v4 *V4) parseCredential(rawCredential string, expectedDate time.Time, skipPrefixCheck bool) (parsedCredential, error) {
	if !skipPrefixCheck {
		if !strings.HasPrefix(rawCredential, v4AuthorizationHeaderCredentialPrefix) {
			return parsedCredential{}, nestError(
				ErrAuthorizationHeaderMalformed,
				"the Credential parameter is missing",
			)
		}
		rawCredential = rawCredential[len(v4AuthorizationHeaderCredentialPrefix):]
	}

	parts := strings.SplitN(rawCredential, "/", 5)

	if len(parts) != 5 {
		return parsedCredential{}, nestError(
			ErrAuthorizationHeaderMalformed,
			"the Credential parameter does not contain necessary parts",
		)
	}

	// TODO(amwolff): optional Access Key ID validation

	date, err := time.Parse(timeFormatYYYYMMDD, parts[1])
	if err != nil {
		return parsedCredential{}, nestError(
			ErrAuthorizationHeaderMalformed,
			"the Credential parameter does not contain a valid date: %w", err,
		)
	}

	if date.Year() != expectedDate.Year() || date.Month() != expectedDate.Month() || date.Day() != expectedDate.Day() {
		return parsedCredential{}, nestError(
			ErrAuthorizationHeaderMalformed,
			"the Credential parameter does not contain the expected date",
		)
	}

	if parts[2] != v4.region { // TODO(amwolff): make region validation optional
		return parsedCredential{}, nestError(
			ErrAuthorizationHeaderMalformed,
			"the Credential parameter does not contain the expected region",
		)
	}

	if parts[3] != v4.service {
		return parsedCredential{}, nestError(
			ErrAuthorizationHeaderMalformed,
			"the Credential parameter does not contain the expected service",
		)
	}

	if parts[4] != v4AuthorizationHeaderCredentialTerminator {
		return parsedCredential{}, nestError(
			ErrAuthorizationHeaderMalformed,
			"the Credential parameter does not contain the expected terminator",
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

func (v4 *V4) parseSignedHeaders(rawSignedHeaders string, actualHeaders http.Header, skipPrefixCheck bool) ([]string, error) {
	if !skipPrefixCheck {
		if !strings.HasPrefix(rawSignedHeaders, v4AuthorizationHeaderSignedHeadersPrefix) {
			return nil, nestError(
				ErrAuthorizationHeaderMalformed,
				"the SignedHeaders parameter is missing",
			)
		}
		rawSignedHeaders = rawSignedHeaders[len(v4AuthorizationHeaderSignedHeadersPrefix):]
	}

	signedHeaders := strings.Split(rawSignedHeaders, ";")
	signedHeadersLookup := make(map[string]struct{})

	var (
		hostFound      bool
		previousHeader string
	)
	for _, header := range signedHeaders {
		if header != strings.ToLower(header) {
			return nil, nestError(
				ErrAuthorizationHeaderMalformed,
				"the SignedHeaders parameter contains a header that is not lowercase: %s", header,
			)
		}
		if header < previousHeader {
			return nil, nestError(
				ErrAuthorizationHeaderMalformed,
				"the SignedHeaders parameter contains headers that are not sorted: %s < %s", header, previousHeader,
			)
		}

		if header == headerHost {
			hostFound = true
		} else if actualHeaders.Get(header) == "" {
			return nil, nestError(
				ErrMissingSecurityHeader,
				"the %s signed header is not present in the request", header,
			)
		}

		previousHeader, signedHeadersLookup[header] = header, struct{}{}
	}

	if !hostFound {
		return nil, nestError(
			ErrMissingSecurityHeader,
			"the SignedHeaders parameter does not contain the host header",
		)
	}

	for key := range actualHeaders {
		if strings.EqualFold(key, headerXAmzContentSha256) {
			continue
		}
		if strings.EqualFold(key, headerContentMD5) {
			if _, ok := signedHeadersLookup[headerContentMD5]; !ok {
				return nil, nestError(
					ErrMissingSecurityHeader,
					"the SignedHeaders parameter does not contain the %s header", headerContentMD5,
				)
			}
		}
		if k := strings.ToLower(key); strings.HasPrefix(k, xAmzHeaderPrefix) {
			if _, ok := signedHeadersLookup[k]; !ok {
				return nil, nestError(
					ErrMissingSecurityHeader,
					"the SignedHeaders parameter does not contain the %s header", k,
				)
			}
		}
	}

	return signedHeaders, nil
}

func (v4 *V4) parseSignature(rawSignature string, skipPrefixCheck bool) (signatureV4, error) {
	if !skipPrefixCheck {
		if !strings.HasPrefix(rawSignature, v4AuthorizationHeaderSignaturePrefix) {
			return nil, nestError(
				ErrAuthorizationHeaderMalformed,
				"the Signature parameter is missing",
			)
		}
		rawSignature = rawSignature[len(v4AuthorizationHeaderSignaturePrefix):]
	}

	signature, err := newSignatureV4FromEncoded([]byte(rawSignature))
	if err != nil {
		return nil, nestError(
			ErrInvalidSignature,
			"the Signature parameter does not contain a valid signature: %w", err,
		)
	}

	return signature, nil
}

type parsedAuthorization struct {
	signingAlgo   v4SigningAlgorithm
	credential    parsedCredential
	signedHeaders []string
	signature     signatureV4
}

func (v4 *V4) parseAuthorization(rawAuthorization string, expectedDate time.Time, headers http.Header) (parsedAuthorization, error) {
	rawAlgorithm, afterAlgorithm, ok := strings.Cut(rawAuthorization, " ")
	if !ok {
		return parsedAuthorization{}, nestError(
			ErrAuthorizationHeaderMalformed,
			"the %s header does not contain expected parts", headerAuthorization,
		)
	}

	signingAlgo, err := v4.parseSigningAlgo(rawAlgorithm)
	if err != nil {
		return parsedAuthorization{}, err
	}

	pairs := strings.SplitN(afterAlgorithm, ",", 3)

	if len(pairs) != 3 {
		return parsedAuthorization{}, nestError(
			ErrAuthorizationHeaderMalformed,
			"the %s header does not contain expected key=value pairs", headerAuthorization,
		)
	}

	credential, err := v4.parseCredential(pairs[0], expectedDate, false)
	if err != nil {
		return parsedAuthorization{}, err
	}

	signedHeaders, err := v4.parseSignedHeaders(pairs[1], headers, false)
	if err != nil {
		return parsedAuthorization{}, err
	}

	signature, err := v4.parseSignature(pairs[2], false)
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

func (v4 *V4) parseAuthorizationFromQuery(query url.Values, expectedDate time.Time, headers http.Header) (parsedAuthorization, error) {
	signingAlgo, err := v4.parseSigningAlgo(query.Get(queryXAmzAlgorithm))
	if err != nil {
		return parsedAuthorization{}, err
	}

	credential, err := v4.parseCredential(query.Get(queryXAmzCredential), expectedDate, true)
	if err != nil {
		return parsedAuthorization{}, err
	}

	signedHeaders, err := v4.parseSignedHeaders(query.Get(queryXAmzSignedHeaders), headers, true)
	if err != nil {
		return parsedAuthorization{}, err
	}

	signature, err := v4.parseSignature(query.Get(queryXAmzSignature), true)
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
	signingAlgo          v4SigningAlgorithm
	trailer              bool
	decodedContentLength int
}

func (v4 *V4) decodedContentLength(headers http.Header) (int, error) {
	rawDecodedContentLength := headers.Get(headerXAmzDecodedContentLength)
	if rawDecodedContentLength == "" {
		return 0, nestError(
			ErrMissingSecurityHeader,
			"the %s header is missing", headerXAmzDecodedContentLength,
		)
	}

	decodedContentLength, err := strconv.Atoi(rawDecodedContentLength)
	if err != nil {
		return 0, nestError(
			ErrInvalidRequest,
			"the %s header does not contain a valid integer: %w", headerXAmzDecodedContentLength, err,
		)
	}

	cl := headers.Get(headerContentLength)
	te := headers.Get(headerTransferEncoding)
	if cl != "" && (te != "" && te != "identity") {
		return 0, nestError(
			ErrInvalidRequest,
			"the %s header must have been omitted", headerContentLength,
		)
	} else if cl == "" && te == "" {
		return 0, nestError(
			ErrMissingContentLength,
			"the %s header is missing", headerContentLength,
		)
	}

	return decodedContentLength, nil
}

func (v4 *V4) parseXAmzContentSHA256(rawXAmzContentSHA256 string, headers http.Header) (parsedXAmzContentSHA256, error) {
	switch rawXAmzContentSHA256 {
	case unsignedPayload:
		return parsedXAmzContentSHA256{
			unsigned: true,
		}, nil
	case streamingUnsignedPayloadTrailer:
		length, err := v4.decodedContentLength(headers)
		if err != nil {
			return parsedXAmzContentSHA256{}, err
		}
		return parsedXAmzContentSHA256{
			unsigned:             true,
			streaming:            true,
			trailer:              true,
			decodedContentLength: length,
		}, nil
	case streamingAWS4HMACSHA256Payload:
		length, err := v4.decodedContentLength(headers)
		if err != nil {
			return parsedXAmzContentSHA256{}, err
		}
		return parsedXAmzContentSHA256{
			streaming:            true,
			signingAlgo:          algorithmHMACSHA256,
			decodedContentLength: length,
		}, nil
	case streamingAWS4HMACSHA256PayloadTrailer:
		length, err := v4.decodedContentLength(headers)
		if err != nil {
			return parsedXAmzContentSHA256{}, err
		}
		return parsedXAmzContentSHA256{
			streaming:            true,
			signingAlgo:          algorithmHMACSHA256,
			trailer:              true,
			decodedContentLength: length,
		}, nil
	case streamingAWS4ECDSAP256SHA256Payload, streamingAWS4ECDSAP256SHA256PayloadTrailer:
		return parsedXAmzContentSHA256{}, nestError(
			ErrNotImplemented,
			"(streaming) calculation using the AWS4-ECDSA-P256-SHA256 algorithm is not implemented yet",
		)
	}

	return parsedXAmzContentSHA256{}, nil
}

type parsedIntegrity struct {
	sumAlgos        []checksumAlgorithm
	trailingSumAlgo checksumAlgorithm
	integrity       expectedIntegrity
}

func (v4 *V4) determineIntegrity(rawXAmzContentSHA256 string, options parsedXAmzContentSHA256, headers http.Header) (parsedIntegrity, error) {
	// thanks, Ermiya Eskandary (https://stackoverflow.com/a/77663532)!

	ret := parsedIntegrity{
		integrity: newExpectedIntegrity(),
	}

	rawAlgorithm := headers.Get(headerXAmzSdkChecksumAlgorithm)
	headerToAlgo := map[string]checksumAlgorithm{
		headerXAmzChecksumCrc32:     algorithmCRC32,
		headerXAmzChecksumCrc32c:    algorithmCRC32C,
		headerXAmzChecksumCrc64nvme: algorithmCRC64NVME,
		headerXAmzChecksumSha1:      algorithmSHA1,
		headerXAmzChecksumSha256:    algorithmSHA256,
	}

	var (
		specifiedAlgorithm *checksumAlgorithm
		rawChecksum        string
	)
	for h, a := range headerToAlgo {
		c := headers.Get(h)
		if specifiedAlgorithm != nil && c != "" {
			return parsedIntegrity{}, nestError(
				ErrInvalidDigest,
				"expecting a single x-amz-checksum- header; multiple checksum types are not allowed",
			)
		}
		if c != "" {
			if rawAlgorithm != "" && !strings.EqualFold(rawAlgorithm, a.String()) {
				return parsedIntegrity{}, nestError(
					ErrInvalidDigest,
					"the %s header does not match the %s header", headerXAmzSdkChecksumAlgorithm, h,
				)
			}
			specifiedAlgorithm, rawChecksum = &a, c
		}
	}

	if rawAlgorithm != "" && specifiedAlgorithm == nil {
		return parsedIntegrity{}, nestError(
			ErrMissingSecurityHeader,
			"a corresponding x-amz-checksum- header is missing",
		)
	}

	if trailerValue := headers.Get(headerXAmzTrailer); trailerValue != "" {
		if specifiedAlgorithm != nil {
			return parsedIntegrity{}, nestError(
				ErrInvalidRequest,
				"the x-amz-checksum- header is not allowed when the %s header is present", headerXAmzTrailer,
			)
		}
		if !options.streaming || !options.trailer {
			return parsedIntegrity{}, nestError(
				ErrInvalidRequest,
				"the %s header is only allowed for streaming requests with trailer signatures", headerXAmzTrailer,
			)
		}

		a, ok := headerToAlgo[trailerValue]
		if !ok {
			return parsedIntegrity{}, nestError(
				ErrInvalidRequest,
				"the %s header does not contain currently supported values", headerXAmzTrailer,
			)
		}

		if rawAlgorithm != "" && !strings.EqualFold(rawAlgorithm, a.String()) {
			return parsedIntegrity{}, nestError(
				ErrInvalidDigest,
				"the %s header does not match the %s header", headerXAmzSdkChecksumAlgorithm, headerXAmzTrailer,
			)
		}

		specifiedAlgorithm = &a
	} else if options.trailer {
		return parsedIntegrity{}, nestError(
			ErrMissingSecurityHeader,
			"the %s header is missing", headerXAmzTrailer,
		)
	}

	if specifiedAlgorithm != nil {
		ret.sumAlgos = append(ret.sumAlgos, *specifiedAlgorithm)
		if options.trailer {
			ret.trailingSumAlgo = *specifiedAlgorithm
		} else {
			ret.integrity.addEncodedString(*specifiedAlgorithm, rawChecksum)
		}
	} else {
		ret.sumAlgos = append(ret.sumAlgos, algorithmCRC64NVME)
	}

	if !options.unsigned && !options.streaming {
		ret.sumAlgos = append(ret.sumAlgos, algorithmHashedPayload)
		ret.integrity.addEncodedString(algorithmHashedPayload, rawXAmzContentSHA256)
	}

	if contentMD5 := headers.Get(headerContentMD5); contentMD5 != "" {
		ret.sumAlgos = append(ret.sumAlgos, algorithmMD5)
		ret.integrity.addEncodedString(algorithmMD5, contentMD5)
	}

	return ret, nil
}

func (v4 *V4) canonicalRequestHash(r *http.Request, query url.Values, signedHeaders []string, hashedPayload string) []byte {
	b := newHashBuilder(sha256.New)

	// http verb
	b.WriteString(r.Method)
	b.WriteByte(lf)
	// canonical uri
	b.WriteString(uriEncode(r.URL.Path, true))
	b.WriteByte(lf)
	// canonical query string
	queryParams := slices.Collect(maps.Keys(query))
	slices.Sort(queryParams)
	for i, p := range queryParams {
		for _, v := range query[p] {
			if i > 0 {
				b.WriteByte('&')
			}
			b.WriteString(uriEncode(p, false))
			b.WriteByte('=')
			b.WriteString(uriEncode(v, false))
		}
	}
	b.WriteByte(lf)
	// canonical headers
	//
	// NOTE: parseSignedHeaders already ensured that signedHeaders are
	// lowercase and sorted.
	for _, name := range signedHeaders {
		if name == headerHost {
			b.WriteString(name)
			b.WriteByte(':')
			b.WriteString(strings.TrimSpace(r.Host))
			b.WriteByte(lf)
			continue
		}
		for _, v := range r.Header.Values(name) {
			b.WriteString(name)
			b.WriteByte(':')
			b.WriteString(strings.TrimSpace(v))
			b.WriteByte(lf)
		}
	}
	b.WriteByte(lf)
	// signed headers
	//
	// NOTE: parseSignedHeaders already ensured that signedHeaders are
	// lowercase and sorted.
	for i, h := range signedHeaders {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(h)
	}
	b.WriteByte(lf)
	// hashed payload
	b.WriteString(hashedPayload)

	return b.Sum()
}

func (v4 *V4) verify(r *http.Request) (v4ReaderOptions, error) {
	rawDate, parsedDateTime, err := v4.parseTime(r.Header.Get(headerXAmzDate), r.Header.Get(headerDate))
	if err != nil {
		return v4ReaderOptions{}, nestError(
			ErrInvalidRequest,
			"the %s or %s header does not contain a valid date: %w", headerXAmzDate, headerDate, err,
		)
	}

	if timeSkewExceeded(v4.now, parsedDateTime, maxRequestTimeSkew) {
		return v4ReaderOptions{}, ErrRequestTimeTooSkewed
	}

	authorization, err := v4.parseAuthorization(r.Header.Get(headerAuthorization), parsedDateTime, r.Header)
	if err != nil {
		return v4ReaderOptions{}, err
	}

	rawXAmzContentSHA256 := r.Header.Get(headerXAmzContentSha256)
	if rawXAmzContentSHA256 == "" {
		return v4ReaderOptions{}, nestError(
			ErrMissingSecurityHeader,
			"the %s header is missing", headerXAmzContentSha256,
		)
	}

	options, err := v4.parseXAmzContentSHA256(rawXAmzContentSHA256, r.Header)
	if err != nil {
		return v4ReaderOptions{}, err
	}

	integrity, err := v4.determineIntegrity(rawXAmzContentSHA256, options, r.Header)
	if err != nil {
		return v4ReaderOptions{}, err
	}

	secretAccessKey, err := v4.provider.Provide(r.Context(), authorization.credential.accessKeyID)
	if err != nil {
		return v4ReaderOptions{}, err
	}

	canonicalRequestHash := v4.canonicalRequestHash(r, r.URL.Query(), authorization.signedHeaders, rawXAmzContentSHA256)

	signature := calculateSignatureV4(signatureV4Data{
		algorithm:       authorization.signingAlgo,
		algorithmSuffix: algorithmSuffixNone,
		dateTime:        rawDate,
		scope:           authorization.credential.scope,
		previous:        nil,
		digest:          canonicalRequestHash,
	}, secretAccessKey)

	if !signature.compare(authorization.signature) {
		return v4ReaderOptions{}, ErrSignatureDoesNotMatch
	}

	return v4ReaderOptions{
		dateTime:        rawDate,
		scope:           authorization.credential.scope,
		parsedOptions:   options,
		parsedIntegrity: integrity,
		secretAccessKey: secretAccessKey,
		seedSignature:   signature,
	}, nil
}

func (v4 *V4) verifyPresigned(r *http.Request, query url.Values) (v4ReaderOptions, error) {
	expires, err := strconv.ParseInt(query.Get(queryXAmzExpires), 10, 64)
	if err != nil {
		return v4ReaderOptions{}, nestError(
			ErrInvalidRequest,
			"the %s query parameter does not contain a valid integer: %w", queryXAmzExpires, err,
		)
	}

	if expires < 0 {
		return v4ReaderOptions{}, nestError(
			ErrAuthorizationQueryParametersError,
			"the %s query parameter is negative", queryXAmzExpires,
		)
	} else if expires > 604800 {
		return v4ReaderOptions{}, nestError(
			ErrAuthorizationQueryParametersError,
			"the %s query parameter exceeds the maximum of 604800 seconds (7 days)", queryXAmzExpires,
		)
	}

	rawDate := query.Get(queryXAmzDate)

	parsedDateTime, err := parseTimeWithFormats(rawDate, []string{timeFormatISO8601})
	if err != nil {
		return v4ReaderOptions{}, nestError(
			ErrInvalidRequest,
			"the %s query parameter does not contain a valid date: %w", queryXAmzDate, err,
		)
	}

	if v4.now().Before(parsedDateTime) {
		return v4ReaderOptions{}, nestError(
			ErrAccessDenied,
			"the request is not yet valid",
		)
	} else if v4.now().After(parsedDateTime.Add(time.Duration(expires) * time.Second)) {
		return v4ReaderOptions{}, nestError(
			ErrAccessDenied,
			"the request has expired",
		)
	}

	authorization, err := v4.parseAuthorizationFromQuery(query, parsedDateTime, r.Header)
	if err != nil {
		return v4ReaderOptions{}, err
	}

	rawXAmzContentSHA256, options := unsignedPayload, parsedXAmzContentSHA256{unsigned: true}

	integrity, err := v4.determineIntegrity(rawXAmzContentSHA256, options, r.Header)
	if err != nil {
		return v4ReaderOptions{}, err
	}

	secretAccessKey, err := v4.provider.Provide(r.Context(), authorization.credential.accessKeyID)
	if err != nil {
		return v4ReaderOptions{}, err
	}

	query.Del(queryXAmzSignature)
	canonicalRequestHash := v4.canonicalRequestHash(r, query, authorization.signedHeaders, rawXAmzContentSHA256)

	signature := calculateSignatureV4(signatureV4Data{
		algorithm:       authorization.signingAlgo,
		algorithmSuffix: algorithmSuffixNone,
		dateTime:        rawDate,
		scope:           authorization.credential.scope,
		previous:        nil,
		digest:          canonicalRequestHash,
	}, secretAccessKey)

	if !signature.compare(authorization.signature) {
		return v4ReaderOptions{}, ErrSignatureDoesNotMatch
	}

	return v4ReaderOptions{
		dateTime:        rawDate,
		scope:           authorization.credential.scope,
		parsedOptions:   options,
		parsedIntegrity: integrity,
		secretAccessKey: secretAccessKey,
		seedSignature:   signature,
	}, nil
}

func (v4 *V4) verifyPost(form PostForm) (v4ReaderOptions, error) {
	return v4ReaderOptions{}, nil
}

func (v4 *V4) Verify(r *http.Request) (*V4Reader, error) {
	typ, params, err := mime.ParseMediaType(r.Header.Get(headerContentType))
	if err != nil {
		typ = ""
	}

	if r.Method == http.MethodPost && typ == "multipart/form-data" {
		file, form, err := parseMultipartFormUntilFile(r.Body, params["boundary"])
		if err != nil {
			return nil, nestError(
				ErrInvalidRequest,
				"unable to parse multipart form data: %w", err,
			)
		}
		data, err := v4.verifyPost(form)
		if err != nil {
			return nil, err
		}
		return newV4Reader(file, data), nil
	} else if r.Header.Get(headerAuthorization) != "" {
		data, err := v4.verify(r)
		if err != nil {
			return nil, err
		}
		return newV4Reader(r.Body, data), nil
	} else if query := r.URL.Query(); query.Has(queryXAmzAlgorithm) {
		data, err := v4.verifyPresigned(r, query)
		if err != nil {
			return nil, err
		}
		return newV4Reader(r.Body, data), nil
	}

	return nil, ErrMissingAuthenticationToken
}
