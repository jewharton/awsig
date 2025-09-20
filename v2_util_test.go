package awsig

import (
	"net/url"
	"strings"
	"testing"

	"github.com/zeebo/assert"
)

func TestSignatureV2(t *testing.T) {
	t.Run("invalid length", func(t *testing.T) {
		_, err := newSignatureV2FromEncoded("ąćęłńóśźż", false)
		assert.Error(t, err)
	})
	t.Run("invalid bytes", func(t *testing.T) {
		_, err := newSignatureV2FromEncoded(strings.Repeat("_", signatureV2EncodedLength), false)
		assert.Error(t, err)
	})

	const encoded = "qgk2+6Sv9/oM7G3qLEjTH1a1l1g="

	signature := mustNewSignatureV2FromEncoded(encoded)
	otherSame := mustNewSignatureV2FromEncoded(encoded)
	otherDiff := mustNewSignatureV2FromEncoded("iqRzw+ileNPu1fhspnRs8nOjjIA=")

	assert.True(t, signature.compare(otherSame))
	assert.Equal(t, encoded, signature.String())
	assert.Equal(t, encoded, otherSame.String())
	assert.False(t, signature.compare(otherDiff))
}

func TestSignatureV2WithURLEncoding(t *testing.T) {
	t.Run("invalid length", func(t *testing.T) {
		_, err := newSignatureV2FromEncoded("ąćęłńóśźż", true)
		assert.Error(t, err)
	})
	t.Run("invalid bytes", func(t *testing.T) {
		_, err := newSignatureV2FromEncoded(strings.Repeat("_", signatureV2EncodedLength), true)
		assert.Error(t, err)
	})

	const encoded = "vjbyPxybdZaNmGa%2ByT272YEAiv4%3D"

	signature := mustNewSignatureV2FromURLEncoded(encoded)
	otherSame := mustNewSignatureV2FromURLEncoded(encoded)
	otherDiff := mustNewSignatureV2FromURLEncoded("NpgCjnDzrM%2BWFzoENXmpNDUsSn8%3D")

	assert.True(t, signature.compare(otherSame))
	assert.Equal(t, mustQueryUnescape(encoded), signature.String())
	assert.Equal(t, mustQueryUnescape(encoded), otherSame.String())
	assert.False(t, signature.compare(otherDiff))
}

func TestCalculateSignatureV2(t *testing.T) {
	const secretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	t.Run("Object GET", func(t *testing.T) {
		stringToSign := "GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/awsexamplebucket1/photos/puppy.jpg"

		actual := calculateSignatureV2(stringToSign, secretAccessKey)
		expected := mustNewSignatureV2FromEncoded("qgk2+6Sv9/oM7G3qLEjTH1a1l1g=")

		assert.True(t, expected.compare(actual))
	})
	t.Run("Object PUT", func(t *testing.T) {
		stringToSign := "PUT\n\nimage/jpeg\nTue, 27 Mar 2007 21:15:45 +0000\n/awsexamplebucket1/photos/puppy.jpg"

		actual := calculateSignatureV2(stringToSign, secretAccessKey)
		expected := mustNewSignatureV2FromEncoded("iqRzw+ileNPu1fhspnRs8nOjjIA=")

		assert.True(t, expected.compare(actual))
	})
	t.Run("List", func(t *testing.T) {
		stringToSign := "GET\n\n\nTue, 27 Mar 2007 19:42:41 +0000\n/awsexamplebucket1/"

		actual := calculateSignatureV2(stringToSign, secretAccessKey)
		expected := mustNewSignatureV2FromEncoded("m0WP8eCtspQl5Ahe6L1SozdX9YA=")

		assert.True(t, expected.compare(actual))
	})
	t.Run("Fetch", func(t *testing.T) {
		stringToSign := "GET\n\n\nTue, 27 Mar 2007 19:44:46 +0000\n/awsexamplebucket1/?acl"

		actual := calculateSignatureV2(stringToSign, secretAccessKey)
		expected := mustNewSignatureV2FromEncoded("82ZHiFIjc+WbcwFKGUVEQspPn+0=")

		assert.True(t, expected.compare(actual))
	})
	t.Run("Delete", func(t *testing.T) {
		stringToSign := "DELETE\n\n\nTue, 27 Mar 2007 21:20:26 +0000\n/awsexamplebucket1/photos/puppy.jpg"

		actual := calculateSignatureV2(stringToSign, secretAccessKey)
		expected := mustNewSignatureV2FromEncoded("XbyTlbQdu9Xw5o8P4iMwPktxQd8=")

		assert.True(t, expected.compare(actual))
	})
	t.Run("Upload", func(t *testing.T) {
		stringToSign := "PUT\n4gJE4saaMU4BqNR0kLY+lw==\napplication/x-download\nTue, 27 Mar 2007 21:06:08 +0000\nx-amz-acl:public-read\nx-amz-meta-checksumalgorithm:crc32\nx-amz-meta-filechecksum:0x02661779\nx-amz-meta-reviewedby:joe@example.com,jane@example.com\n/static.example.com/db-backup.dat.gz"

		actual := calculateSignatureV2(stringToSign, secretAccessKey)
		expected := mustNewSignatureV2FromEncoded("jtBQa0Aq+DkULFI8qrpwIjGEx0E=")

		assert.True(t, expected.compare(actual))
	})
	t.Run("List all my buckets", func(t *testing.T) {
		stringToSign := "GET\n\n\nWed, 28 Mar 2007 01:29:59 +0000\n/"

		actual := calculateSignatureV2(stringToSign, secretAccessKey)
		expected := mustNewSignatureV2FromEncoded("qGdzdERIC03wnaRNKh6OqZehG9s=")

		assert.True(t, expected.compare(actual))
	})
	t.Run("Unicode keys", func(t *testing.T) {
		stringToSign := "GET\n\n\nWed, 28 Mar 2007 01:49:49 +0000\n/dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re"

		actual := calculateSignatureV2(stringToSign, secretAccessKey)
		expected := mustNewSignatureV2FromEncoded("DNEZGsoieTZ92F3bUfSPQcbGmlM=")

		assert.True(t, expected.compare(actual))
	})
}

func mustNewSignatureV2FromEncoded(s string) signatureV2 {
	signature, err := newSignatureV2FromEncoded(s, false)
	if err != nil {
		panic(err)
	}
	return signature
}

func mustNewSignatureV2FromURLEncoded(s string) signatureV2 {
	signature, err := newSignatureV2FromEncoded(s, true)
	if err != nil {
		panic(err)
	}
	return signature
}

func mustQueryUnescape(s string) string {
	u, err := url.QueryUnescape(s)
	if err != nil {
		panic(err)
	}
	return u
}
