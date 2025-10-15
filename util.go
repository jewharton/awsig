package awsig

import (
	"context"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

var (
	ErrAuthorizationHeaderMalformed      = errors.New("the authorization header that you provided is not valid")
	ErrAuthorizationQueryParametersError = errors.New("the authorization query parameters that you provided are not valid")
	ErrBadDigest                         = errors.New("the Content-MD5 or checksum value that you specified did not match what the server received")
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

	headerAuthorization     = "authorization"
	headerContentMD5        = "content-md5"
	headerContentType       = "content-type"
	headerDate              = "date"
	headerXAmzContentSha256 = xAmzHeaderPrefix + "content-sha256"
	headerXAmzDate          = xAmzHeaderPrefix + "date"

	formNamePolicy = "Policy"

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

var errMessageTooLarge = errors.New("message too large")

type CredentialsProvider interface {
	Provide(ctx context.Context, accessKeyID string) (secretAccessKey string, _ error)
}

type AccessKey struct {
	ID        string
	SecretKey string
}

type Reader interface {
	io.Reader
	Checksums() (map[ChecksumAlgorithm][]byte, error)
}

type VerifiedRequest interface {
	PostForm() PostForm
	Reader(...ChecksumRequest) (Reader, error)
	AccessKey() AccessKey
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

func timeOutOfBounds(now func() time.Time, b1, b2 time.Time) bool {
	if b1.After(b2) {
		b1, b2 = b2, b1
	}
	if n := now(); n.Before(b1) || n.After(b2) {
		return true
	}
	return false
}

func timeSkewExceeded(now func() time.Time, t time.Time, skew time.Duration) bool {
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

type PostFormElement struct {
	Value   string
	Headers textproto.MIMEHeader
}

type PostForm map[string][]PostFormElement

func (f PostForm) FileName() string {
	v, _ := f.Get("file")
	return v
}

func (f PostForm) Add(key, value string, headers textproto.MIMEHeader) {
	k := textproto.CanonicalMIMEHeaderKey(key)
	f[k] = append(f[k], PostFormElement{
		Value:   value,
		Headers: headers,
	})
}

func (f PostForm) Set(key string, value string, headers textproto.MIMEHeader) {
	k := textproto.CanonicalMIMEHeaderKey(key)
	f[k] = []PostFormElement{{
		Value:   value,
		Headers: headers,
	}}
}

func (f PostForm) Get(key string) (string, textproto.MIMEHeader) {
	if f == nil {
		return "", nil
	}
	v := f[textproto.CanonicalMIMEHeaderKey(key)]
	if len(v) == 0 {
		return "", nil
	}
	return v[0].Value, v[0].Headers
}

func (f PostForm) Values(key string) ([]string, []textproto.MIMEHeader) {
	if f == nil {
		return nil, nil
	}
	v := f[textproto.CanonicalMIMEHeaderKey(key)]
	vals := make([]string, 0, len(v))
	hdrs := make([]textproto.MIMEHeader, 0, len(v))
	for _, e := range v {
		vals = append(vals, e.Value)
		hdrs = append(hdrs, e.Headers)
	}
	return vals, hdrs
}

func (f PostForm) Has(key string) bool {
	if f == nil {
		return false
	}
	_, ok := f[textproto.CanonicalMIMEHeaderKey(key)]
	return ok
}

var errLimitReached = errors.New("limitedReader: limit reached")

func limitReader(r io.Reader, n int64) *limitedReader {
	return &limitedReader{
		r:       r,
		n:       n,
		enabled: true,
	}
}

type limitedReader struct {
	r       io.Reader
	n       int64
	enabled bool
}

func (l *limitedReader) Read(p []byte) (n int, err error) {
	if !l.enabled {
		return l.r.Read(p)
	}
	if l.n <= 0 {
		return 0, errors.Join(io.EOF, errLimitReached)
	}

	if int64(len(p)) > l.n {
		p = p[0:l.n]
	}

	n, err = l.r.Read(p)
	l.n -= int64(n)

	return n, err
}

func (l *limitedReader) toggle() {
	l.enabled = !l.enabled
}

func parseMultipartFormUntilFile(r io.Reader, boundary string) (io.ReadCloser, PostForm, error) {
	if boundary == "" {
		return nil, nil, http.ErrMissingBoundary
	}

	lr := limitReader(r, 20000) // the 20KB limit is mentioned in https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTForms.html
	mr := multipart.NewReader(lr, boundary)

	form := make(PostForm)
	for {
		part, err := mr.NextPart()
		if err != nil {
			if errors.Is(err, errLimitReached) {
				err = errMessageTooLarge
			} else if errors.Is(err, io.EOF) {
				break
			}
			return nil, PostForm{}, err
		}

		name := part.FormName()

		if name == "file" {
			lr.toggle() // stop limiting the reader as we reached the file part
			form.Set(name, part.FileName(), part.Header)
			return part, form, nil
		}

		b, err := io.ReadAll(part)
		if err != nil {
			if errors.Is(err, errLimitReached) {
				err = errMessageTooLarge
			}
			if errClose := part.Close(); errClose != nil {
				err = errors.Join(err, errClose)
			}
			return nil, PostForm{}, err
		}
		form.Add(name, string(b), part.Header)

		if err = part.Close(); err != nil {
			return nil, PostForm{}, err
		}
	}

	return nil, PostForm{}, errors.New("missing file part in multipart form data")
}
