package awsig

import (
	"mime"
	"net/http"
	"strings"
)

type V2V4 struct {
	v2 *V2
	v4 *V4
}

func NewV2V4(provider CredentialsProvider, v4Config V4Config) *V2V4 {
	return &V2V4{
		v2: NewV2(provider),
		v4: NewV4(provider, v4Config),
	}
}

func (v2v4 *V2V4) Verify(r *http.Request, virtualHostedBucket string) (VerifiedRequest, error) {
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
		if form.Has(queryXAmzAlgorithm) {
			data, err := v2v4.v4.verifyPost(r.Context(), form)
			if err != nil {
				return nil, err
			}
			return newV4VerifiedRequestWithForm(file, data, form)
		} else if form.Has(queryAWSAccessKeyId) {
			if err = v2v4.v2.verifyPost(r.Context(), form); err != nil {
				return nil, err
			}
			return newV2VerifiedRequestWithForm(file, form)
		}
	} else if h := r.Header.Get(headerAuthorization); h != "" {
		if strings.HasPrefix(h, v4SigningAlgorithmPrefix) {
			data, err := v2v4.v4.verify(r)
			if err != nil {
				return nil, err
			}
			return newV4VerifiedRequest(r.Body, data)
		}
		if err = v2v4.v2.verify(r, virtualHostedBucket); err != nil {
			return nil, err
		}
		return newV2VerifiedRequest(r.Body)
	} else if query := r.URL.Query(); query.Has(queryXAmzAlgorithm) {
		data, err := v2v4.v4.verifyPresigned(r, query)
		if err != nil {
			return nil, err
		}
		return newV4VerifiedRequest(r.Body, data)
	} else if query := r.URL.Query(); query.Has(queryAWSAccessKeyId) {
		if err = v2v4.v2.verifyPresigned(r, query, virtualHostedBucket); err != nil {
			return nil, err
		}
		return newV2VerifiedRequest(r.Body)
	}

	return nil, ErrMissingAuthenticationToken
}
