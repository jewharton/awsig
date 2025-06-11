package awsig

import (
	"crypto/subtle"
	"encoding/hex"
)

type signatureV4 []byte

func newSignatureV4FromEncoded(b []byte) (signatureV4, error) {
	if len(b) != signatureV4EncodedLength {
		return nil, ErrSignatureMalformed
	}

	s := make(signatureV4, signatureV4DecodedLength)

	// TODO(amwolff): does copying affect performance or do other
	// factors dominate it?
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

	// TODO(amwolff): does copying affect performance or do other
	// factors dominate it?
	copy(s, b)

	return s, nil
}

func (s signatureV4) compare(other signatureV4) bool {
	return subtle.ConstantTimeCompare(s, other) == 1
}

func (s signatureV4) String() string {
	return hex.EncodeToString(s)
}
