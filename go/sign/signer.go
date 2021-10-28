package sign

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Truelayer/truelayer-signing/go/crypto"
	"github.com/Truelayer/truelayer-signing/go/errors"
	tlhttp "github.com/Truelayer/truelayer-signing/go/http"
	"github.com/Truelayer/truelayer-signing/go/jws"
	orderedmap "github.com/wk8/go-ordered-map"
)

// Builder to generate a "Tl-Signature" header value using a private key.
type Signer struct {
	kid        string
	privateKey []byte
	body       []byte
	method     string
	path       string
	headers    *orderedmap.OrderedMap
}

func NewSigner(kid string, privateKeyPem []byte) *Signer {
	return &Signer{
		kid:        kid,
		privateKey: privateKeyPem,
		method:     "POST",
		path:       "",
		body:       []byte(""),
		headers:    orderedmap.New(),
	}
}

// Body adds the full request body.
//
// Note: This **must** be identical to what is sent with the request.
func (s *Signer) Body(body []byte) *Signer {
	s.body = body
	return s
}

// Method adds the request method, defaults to "POST" if unspecified.
func (s *Signer) Method(method string) *Signer {
	s.method = method
	return s
}

// Path adds the request absolute path starting with a leading '/' and without any trailing slashes.
func (s *Signer) Path(path string) *Signer {
	s.path = path
	return s
}

// Header adds a header name & value.
// May be called multiple times to add multiple different headers.
//
// Warning: Only a single value per header name is supported.
func (s *Signer) Header(name string, value []byte) *Signer {
	s.AddHeader(name, value)
	return s
}

// AddHeader adds a header name & value.
// May be called multiple times to add multiple different headers.
//
// Warning: Only a single value per header name is supported.
func (s *Signer) AddHeader(name string, value []byte) {
	header := &tlhttp.Header{
		Name:  name,
		Value: value,
	}
	s.headers.Set(strings.ToLower(name), header)
}

// SignBodyOnly produces a JWS "Tl-Signature" v1 header value, signing just the request body.
//
// Any specified method, path & headers will be ignored.
//
// In general full request signing should be preferred.
func (s *Signer) SignBodyOnly() (string, error) {
	privateKey, err := crypto.ParseEcPrivateKey(s.privateKey)
	if err != nil {
		return "", errors.NewInvalidKeyError(fmt.Sprintf("private key parsing failed: %v", err))
	}

	body := base64.RawURLEncoding.EncodeToString(s.body)
	jwsHeaderB64 := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("{\"alg\":\"ES512\",\"kid\":\"%s\"}", s.kid)))
	jwsHeaderAndPayload := fmt.Sprintf("%s.%s", jwsHeaderB64, body)
	signature, err := crypto.SignES512(privateKey, []byte(jwsHeaderAndPayload))
	if err != nil {
		return "", errors.NewJwsError(fmt.Sprintf("signing failed: %v", err))
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	jws := jwsHeaderB64 + ".." + signatureB64

	return jws, nil
}

// Sign produces a JWS 'Tl-Signature' v2 header value.
func (s *Signer) Sign() (string, error) {
	privateKey, err := crypto.ParseEcPrivateKey(s.privateKey)
	if err != nil {
		return "", errors.NewInvalidKeyError(fmt.Sprintf("private key parsing failed: %v", err))
	}
	jwsHeader := jws.NewJwsHeaderV2(s.kid, s.headers)
	marshalledJwsHeader, err := json.Marshal(jwsHeader)
	if err != nil {
		return "", errors.NewJwsError(fmt.Sprintf("jws header json marshalling failed: %v", err))
	}
	jwsHeaderB64 := base64.RawURLEncoding.EncodeToString(marshalledJwsHeader)

	signingPayload := BuildV2SigningPayload(s.method, s.path, s.headers, s.body)
	signingPayloadB64 := base64.RawURLEncoding.EncodeToString(signingPayload)

	jwsHeaderAndPayload := fmt.Sprintf("%s.%s", jwsHeaderB64, signingPayloadB64)
	signature, err := crypto.SignES512(privateKey, []byte(jwsHeaderAndPayload))
	if err != nil {
		return "", errors.NewJwsError(fmt.Sprintf("signing failed: %v", err))
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	jws := string(jwsHeaderB64) + ".." + signatureB64

	return jws, nil
}

// BuildV2SigningPayload builds a v2 signing payload.
func BuildV2SigningPayload(method string, path string, headers *orderedmap.OrderedMap, body []byte) []byte {
	payload := make([]byte, 0)
	payload = append(payload, []byte(strings.ToUpper(method))...)
	payload = append(payload, []byte(" ")...)
	payload = append(payload, []byte(path)...)
	payload = append(payload, []byte("\n")...)
	for pair := headers.Oldest(); pair != nil; pair = pair.Next() {
		header := pair.Value.(*tlhttp.Header)
		payload = append(payload, []byte(header.Name)...)
		payload = append(payload, []byte(": ")...)
		payload = append(payload, []byte(header.Value)...)
		payload = append(payload, []byte("\n")...)
	}
	payload = append(payload, body...)
	return payload
}
