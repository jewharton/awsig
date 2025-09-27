package awsig

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"hash"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	queryAWSAccessKeyId = "AWSAccessKeyId"
	queryExpires        = "Expires"
	querySignature      = "Signature"
)

type V2Reader struct {
	ir        *integrityReader
	integrity expectedIntegrity
}

type v2ReaderOptions struct {
	sumAlgos          []checksumAlgorithm
	expectedIntegrity expectedIntegrity
}

func newV2Reader(r io.Reader, data v2ReaderOptions) *V2Reader {
	return &V2Reader{
		ir:        newIntegrityReader(r, data.sumAlgos),
		integrity: data.expectedIntegrity,
	}
}

func (r *V2Reader) Read(p []byte) (n int, err error) {
	if n, err = r.ir.Read(p); errors.Is(err, io.EOF) {
		if err := r.ir.verify(r.integrity); err != nil {
			return n, err
		}
	}
	return n, err
}

func (r *V2Reader) Checksums() (Checksums, error) {
	return r.ir.checksums()
}

type V2 struct {
	provider CredentialsProvider
	now      func() time.Time
}

func NewV2(provider CredentialsProvider) *V2 {
	return &V2{
		provider: provider,
		now:      time.Now,
	}
}

func (v2 *V2) parseTime(main, alt string) (time.Time, error) {
	parsed, err := parseTimeWithFormats(main, httpTimeFormats)
	if err != nil {
		return parseTimeWithFormats(alt, httpTimeFormats)
	}
	return parsed, nil
}

type parsedAuthorizationV2 struct {
	accessKeyID string
	signature   signatureV2
}

func (v2 *V2) parseAuthorization(rawAuthorization string) (parsedAuthorizationV2, error) {
	rawAlgorithm, afterAlgorithm, ok := strings.Cut(rawAuthorization, " ")
	if !ok {
		return parsedAuthorizationV2{}, nestError(
			ErrAuthorizationHeaderMalformed,
			"the %s header does not contain expected parts", headerAuthorization,
		)
	}

	if rawAlgorithm != "AWS" {
		return parsedAuthorizationV2{}, nestError(
			ErrUnsupportedSignature,
			"the %s header does not contain a valid signing algorithm", headerAuthorization,
		)
	}

	accessKeyID, rawSignature, ok := strings.Cut(afterAlgorithm, ":")
	if !ok {
		return parsedAuthorizationV2{}, nestError(
			ErrAuthorizationHeaderMalformed,
			"the %s header does not contain expected parts", headerAuthorization,
		)
	}

	signature, err := newSignatureV2FromEncoded(rawSignature)
	if err != nil {
		return parsedAuthorizationV2{}, nestError(
			ErrInvalidSignature,
			"the %s header does not contain a valid signature: %w", headerAuthorization, err,
		)
	}

	return parsedAuthorizationV2{
		accessKeyID: accessKeyID,
		signature:   signature,
	}, nil
}

func (v2 *V2) determineIntegrity(headers http.Header) ([]checksumAlgorithm, expectedIntegrity, error) {
	return nil, expectedIntegrity{}, nil // TODO(amwolff)
}

func (v2 *V2) calculateSignature(r *http.Request, dateElement, virtualHostedBucket, key string) signatureV2 {
	b := newHashBuilder(func() hash.Hash { return hmac.New(sha1.New, []byte(key)) })

	b.WriteString(r.Method)
	b.WriteByte(lf)
	b.WriteString(r.Header.Get(headerContentMD5))
	b.WriteByte(lf)
	b.WriteString(r.Header.Get(headerContentType))
	b.WriteByte(lf)
	b.WriteString(dateElement)
	b.WriteByte(lf)

	var xAmzHeaderPrefixKeys []string
	for key := range r.Header {
		if k := strings.ToLower(key); strings.HasPrefix(k, xAmzHeaderPrefix) {
			xAmzHeaderPrefixKeys = append(xAmzHeaderPrefixKeys, k)
		}
	}
	slices.Sort(xAmzHeaderPrefixKeys)
	for _, key := range xAmzHeaderPrefixKeys {
		b.WriteString(key)
		b.WriteByte(':')
		for i, v := range r.Header.Values(key) {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(v)
		}
		b.WriteByte(lf)
	}

	if virtualHostedBucket != "" {
		b.WriteByte('/')
		b.WriteString(virtualHostedBucket)
	}
	// NOTE(amwolff): it felt like a bad idea to use a RawPath that
	// might contain an invalid encoding the software down the chain
	// might use long after we've authenticated this request.
	b.WriteString(r.URL.EscapedPath())

	if query := r.URL.Query(); len(query) > 0 {
		included := map[string]bool{
			"acl":                          true,
			"lifecycle":                    true,
			"location":                     true,
			"logging":                      true,
			"notification":                 true,
			"partNumber":                   true,
			"policy":                       true,
			"requestPayment":               true,
			"uploadId":                     true,
			"uploads":                      true,
			"versionId":                    true,
			"versioning":                   true,
			"versions":                     true,
			"website":                      true,
			"response-content-type":        false,
			"response-content-language":    false,
			"response-expires":             false,
			"response-cache-control":       false,
			"response-content-disposition": false,
			"response-content-encoding":    false,
			"delete":                       true,
		}

		queryParams := slices.Collect(maps.Keys(query))
		slices.Sort(queryParams)

		for i, p := range queryParams {
			encode, ok := included[p]
			if !ok {
				continue
			}

			if i == 0 {
				b.WriteByte('?')
			}

			for _, v := range query[p] {
				if i > 0 {
					b.WriteByte('&')
				}
				b.WriteString(p)
				if v != "" {
					b.WriteByte('=')
					if encode {
						b.WriteString(uriEncode(v, false))
					} else {
						b.WriteString(v)
					}
				}
			}
		}
	}

	return b.Sum()
}

func (v2 *V2) verify(r *http.Request, virtualHostedBucket string) (v2ReaderOptions, error) {
	headerDateValue := r.Header.Get(headerDate)
	parsedDateTime, err := v2.parseTime(r.Header.Get(headerXAmzDate), headerDateValue)
	if err != nil {
		return v2ReaderOptions{}, nestError(
			ErrInvalidRequest,
			"the %s or %s header does not contain a valid date: %w", headerXAmzDate, headerDate, err,
		)
	}

	if timeSkewExceeded(v2.now, parsedDateTime, maxRequestTimeSkew) {
		return v2ReaderOptions{}, ErrRequestTimeTooSkewed
	}

	authorization, err := v2.parseAuthorization(r.Header.Get(headerAuthorization))
	if err != nil {
		return v2ReaderOptions{}, err
	}

	integritySumAlgos, integrity, err := v2.determineIntegrity(r.Header)
	if err != nil {
		return v2ReaderOptions{}, err
	}

	secretAccessKey, err := v2.provider.Provide(r.Context(), authorization.accessKeyID)
	if err != nil {
		return v2ReaderOptions{}, err
	}

	signature := v2.calculateSignature(r, headerDateValue, virtualHostedBucket, secretAccessKey)

	if !signature.compare(authorization.signature) {
		return v2ReaderOptions{}, ErrSignatureDoesNotMatch
	}

	return v2ReaderOptions{
		sumAlgos:          integritySumAlgos,
		expectedIntegrity: integrity,
	}, nil
}

func (v2 *V2) verifyPresigned(r *http.Request, query url.Values, virtualHostedBucket string) (v2ReaderOptions, error) {
	rawExpires := query.Get(queryExpires)

	expires, err := strconv.ParseInt(rawExpires, 10, 64)
	if err != nil {
		return v2ReaderOptions{}, nestError(
			ErrInvalidRequest,
			"the %s query parameter does not contain a valid integer: %w", queryExpires, err,
		)
	}

	if timeOutOfBounds(v2.now, time.Time{}, time.Unix(expires, 0)) {
		return v2ReaderOptions{}, ErrAccessDenied
	}

	signature, err := newSignatureV2FromEncoded(query.Get(querySignature))
	if err != nil {
		return v2ReaderOptions{}, nestError(
			ErrInvalidSignature,
			"the %s query parameter does not contain a valid signature: %w", querySignature, err,
		)
	}

	integritySumAlgos, integrity, err := v2.determineIntegrity(r.Header)
	if err != nil {
		return v2ReaderOptions{}, err
	}

	secretAccessKey, err := v2.provider.Provide(r.Context(), query.Get(queryAWSAccessKeyId))
	if err != nil {
		return v2ReaderOptions{}, err
	}

	if !v2.calculateSignature(r, rawExpires, virtualHostedBucket, secretAccessKey).compare(signature) {
		return v2ReaderOptions{}, ErrSignatureDoesNotMatch
	}

	return v2ReaderOptions{
		sumAlgos:          integritySumAlgos,
		expectedIntegrity: integrity,
	}, nil
}

func (v2 *V2) Verify(r *http.Request, virtualHostedBucket string) (*V2Reader, error) {
	if r.Method == http.MethodPost {
		return nil, nestError(
			ErrNotImplemented,
			"authenticating HTTP POST requests is not implemented yet",
		)
	} else if r.Header.Get(headerAuthorization) != "" {
		data, err := v2.verify(r, virtualHostedBucket)
		if err != nil {
			return nil, err
		}
		return newV2Reader(r.Body, data), nil
	} else if query := r.URL.Query(); query.Has(queryAWSAccessKeyId) {
		data, err := v2.verifyPresigned(r, query, virtualHostedBucket)
		if err != nil {
			return nil, err
		}
		return newV2Reader(r.Body, data), nil
	}
	return nil, ErrMissingAuthenticationToken
}
