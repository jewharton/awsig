package awsig

import (
	"context"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrAuthorizationHeaderMalformed      = errors.New("the authorization header that you provided is not valid")
	ErrAuthorizationQueryParametersError = errors.New("the authorization query parameters that you provided are not valid")
	ErrEntityTooLarge                    = errors.New("your proposed upload exceeds the maximum allowed object size")
	ErrEntityTooSmall                    = errors.New("your proposed upload is smaller than the minimum allowed object size")
	ErrIncompleteBody                    = errors.New("you did not provide the number of bytes specified by the Content-Length HTTP header")
	ErrInvalidArgument                   = errors.New("invalid argument")
	ErrInvalidDigest                     = errors.New("the Content-MD5 or checksum value that you specified is not valid")
	ErrInvalidRequest                    = errors.New("invalid request")
	ErrInvalidSignature                  = errors.New("the request signature that the server calculated does not match the signature that you provided")
	ErrMissingAuthenticationToken        = errors.New("the request was not signed")
	ErrMissingContentLength              = errors.New("you must provide the Content-Length HTTP header")
	ErrMissingSecurityHeader             = errors.New("your request is missing a required header")
	ErrRequestTimeTooSkewed              = errors.New("the difference between the request time and the server's time is too large")
	ErrSignatureDoesNotMatch             = errors.New("the request signature that the server calculated does not match the signature that you provided")
	ErrUnsupportedSignature              = errors.New("the provided request is signed with an unsupported STS Token version or the signature version is not supported")

	ErrAccessDenied       = errors.New("access denied")
	ErrInvalidAccessKeyID = errors.New("the AWS access key ID that you provided does not exist in our records")

	ErrNotImplemented = errors.New("not implemented")
)

const (
	xAmzHeaderPrefix = "x-amz-"

	headerAuthorization            = "authorization"
	headerContentMD5               = "content-md5"
	headerContentType              = "content-type"
	headerDate                     = "date"
	headerXAmzChecksumCrc32        = xAmzHeaderPrefix + "checksum-crc32"
	headerXAmzChecksumCrc32c       = xAmzHeaderPrefix + "checksum-crc32c"
	headerXAmzChecksumCrc64nvme    = xAmzHeaderPrefix + "checksum-crc64nvme"
	headerXAmzChecksumSha1         = xAmzHeaderPrefix + "checksum-sha1"
	headerXAmzChecksumSha256       = xAmzHeaderPrefix + "checksum-sha256"
	headerXAmzContentSha256        = xAmzHeaderPrefix + "content-sha256"
	headerXAmzDate                 = xAmzHeaderPrefix + "date"
	headerXAmzSdkChecksumAlgorithm = xAmzHeaderPrefix + "sdk-checksum-algorithm"

	timeFormatISO8601  = "20060102T150405Z"
	timeFormatYYYYMMDD = "20060102"

	maxRequestTimeSkew = 15 * time.Minute
)

var httpTimeFormats = []string{
	http.TimeFormat,
	"Mon, 02 Jan 2006 15:04:05 -0700",
	time.RFC850,
	time.ANSIC,
}

type CredentialsProvider interface {
	Provide(ctx context.Context, accessKeyID string) (secretAccessKey string, _ error)
}

type nestedError struct {
	outer error
	inner error
}

func (e *nestedError) Error() string {
	return fmt.Sprintf("%v: %v", e.outer, e.inner)
}

func (e *nestedError) Unwrap() error {
	return e.inner
}

func (e *nestedError) Is(target error) bool {
	if e.outer == target {
		return true
	}
	return errors.Is(e.inner, target)
}

func nestError(outer error, format string, a ...any) *nestedError {
	return &nestedError{
		outer: outer,
		inner: fmt.Errorf(format, a...),
	}
}

func parseTimeWithFormats(value string, formats []string) (time.Time, error) {
	var (
		t   time.Time
		err error
	)
	for _, layout := range formats {
		t, err = time.Parse(layout, value)
		if err == nil {
			return t, nil
		}
	}
	return t, err
}

func timeOutOfBounds(now func() time.Time, b1, b2 time.Time) bool { // TODO(amwolff): write a unit test
	if b1.After(b2) {
		b1, b2 = b2, b1
	}
	if n := now(); n.Before(b1) || n.After(b2) {
		return true
	}
	return false
}

func timeSkewExceeded(now func() time.Time, t time.Time, skew time.Duration) bool { // TODO(amwolff): write a unit test
	return timeOutOfBounds(now, t.Add(-skew), t.Add(skew))
}

func uriEncode(value string, path bool) string {
	encoded := url.QueryEscape(value)
	oldnews := []string{"+", "%20"}

	if path {
		oldnews = append(oldnews, "%2F", "/")
	}

	return strings.NewReplacer(oldnews...).Replace(encoded)
}

type hashBuilder struct {
	h hash.Hash
}

func (b *hashBuilder) Write(p []byte) (int, error) {
	return b.h.Write(p)
}

func (b *hashBuilder) WriteByte(c byte) error {
	_, err := b.h.Write([]byte{c})
	return err
}

func (b *hashBuilder) WriteString(s string) (int, error) {
	return b.h.Write([]byte(s))
}

func (b *hashBuilder) Sum() []byte {
	return b.h.Sum(nil)
}

func newHashBuilder(h func() hash.Hash) *hashBuilder {
	return &hashBuilder{
		h: h(),
	}
}
