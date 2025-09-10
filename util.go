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
