package verify

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Truelayer/truelayer-signing/go/crypto"
	"github.com/Truelayer/truelayer-signing/go/errors"
	"github.com/Truelayer/truelayer-signing/go/jws"
	"github.com/Truelayer/truelayer-signing/go/sign"
)

// Build to verify a request against a "Tl-Signature" header.
type Verifier struct {
	publicKey       []byte
	jwks            []byte
	body            []byte
	method          string
	path            string
	headers         map[string][]byte
	requiredHeaders []string
}

// Truelayer signature data
type TlSignature struct {
	JwsHeader    *jws.JwsHeader
	HeaderBase64 string
	Signature    []byte
}

func NewVerifier(publicKeyPem []byte) *Verifier {
	verifier := Verifier{}
	verifier.publicKey = publicKeyPem
	verifier.method = ""
	verifier.path = ""
	verifier.body = []byte("")
	verifier.headers = make(map[string][]byte)
	return &verifier
}

func NewVerifierWithJwks(jwks []byte) *Verifier {
	verifier := Verifier{}
	verifier.jwks = jwks
	verifier.method = ""
	verifier.path = ""
	verifier.body = []byte("")
	verifier.headers = make(map[string][]byte)
	return &verifier
}

// Body adds the full received request body.
func (v *Verifier) Body(body []byte) *Verifier {
	v.body = body
	return v
}

// Method adds the request method, e.g. "POST".
func (v *Verifier) Method(method string) *Verifier {
	v.method = method
	return v
}

// Path adds the request path, e.g. "/payouts".
func (v *Verifier) Path(path string) *Verifier {
	v.path = path
	return v
}

// Header adds a header name & value.
// May be called multiple times to add multiple different headers.
//
// All request headers may be added here, any headers not mentioned
// in the jws signature header will be ignored unless required
// using "RequiredHeader".
func (v *Verifier) Header(name string, value []byte) *Verifier {
	v.headers[strings.ToLower(name)] = value
	return v
}

// Headers appends multiple header name & value.
//
// Warning: Only a single value per header name is supported.
func (v *Verifier) Headers(headers map[string][]byte) *Verifier {
	for name, value := range headers {
		v.Header(name, value)
	}
	return v
}

// RequireHeader specifies a header name that must be included in the "Tl-Signature".
// May be called multiple times to add multiple required headers.
//
// Signatures missing these will fail verification.
func (v *Verifier) RequireHeader(name string) *Verifier {
	v.requiredHeaders = append(v.requiredHeaders, name)
	return v
}

// Verify verifies the given "Tl-Signature" header value.
//
// Supports v1 (body-only) & v2 full request signatures.
//
// Returns error if verification fails.
func (v *Verifier) Verify(tlSignature string) error {
	if !strings.HasPrefix(v.path, "/") {
		return errors.NewInvalidArgumentError("path must start with '/'")
	}

	tlSignatureData, err := ParseTlSignature(tlSignature)
	if err != nil {
		return errors.NewJwsError(fmt.Sprintf("signature parsing failed: %v", err))
	}
	jwsHeader := tlSignatureData.JwsHeader

	var publicKey *ecdsa.PublicKey
	if v.publicKey == nil {
		if v.jwks == nil {
			return errors.NewInvalidKeyError("no public key nor jwks supplied: verification is not possible")
		} else {
			publicKey, err = crypto.FindAndParseEcJwk([]byte(jwsHeader.Kid), v.jwks)
			if err != nil {
				return errors.NewInvalidKeyError(fmt.Sprintf("jwk find and parse failed: %v", err))
			}
		}
	} else {
		publicKey, err = crypto.ParseEcPublicKey(v.publicKey)
		if err != nil {
			return errors.NewInvalidKeyError(fmt.Sprintf("public key parsing failed: %v", err))
		}
	}

	if jwsHeader.Alg != "ES512" {
		return errors.NewJwsError(fmt.Sprintf("unexpected header alg: %s", jwsHeader.Alg))
	}

	if jwsHeader.TlVersion == "" || jwsHeader.TlVersion == "1" {
		return errors.NewJwsError("v1 signature not allowed")
	}

	// check and order all required headers
	orderedHeaders, err := jwsHeader.FilterHeaders(v.headers)
	if err != nil {
		return errors.NewJwsError(fmt.Sprintf("headers filtering failed: %v", err))
	}
	// fail if signature is missing a required header
	for _, header := range v.requiredHeaders {
		_, exists := orderedHeaders.Get(strings.ToLower(header))
		if !exists {
			return errors.NewJwsError(fmt.Sprintf("signature is missing required header: %s", header))
		}
	}

	// reconstruct the payload as it would have been signed
	signingPayload := sign.BuildV2SigningPayload(v.method, v.path, orderedHeaders, v.body, false)
	payload := fmt.Sprintf("%s.%s", tlSignatureData.HeaderBase64, base64.RawURLEncoding.EncodeToString(signingPayload))
	err = crypto.VerifyES512(publicKey, []byte(payload), tlSignatureData.Signature)
	if err != nil {
		// try again with/without a trailing slash (#80)
		newPath, addPathTrailingSlash := v.handleTrailingSlashRetry()
		signingPayload := sign.BuildV2SigningPayload(v.method, newPath, orderedHeaders, v.body, addPathTrailingSlash)
		payload := fmt.Sprintf("%s.%s", tlSignatureData.HeaderBase64, base64.RawURLEncoding.EncodeToString(signingPayload))
		if retryErr := crypto.VerifyES512(publicKey, []byte(payload), tlSignatureData.Signature); retryErr != nil {
			// use original error if both fail
			return errors.NewJwsError(fmt.Sprintf("signature verification failed: %v", err))
		}
	}

	return nil
}

func (v *Verifier) handleTrailingSlashRetry() (string, bool) {
	if strings.HasSuffix(v.path, "/") {
		return strings.TrimSuffix(v.path, "/"), false
	} else {
		return v.path, true
	}
}

// ParseTlSignature parses a tl signature header value into (header, headerBase64, signature).
func ParseTlSignature(tlSignature string) (*TlSignature, error) {
	splits := strings.Split(tlSignature, "..")
	if len(splits) != 2 {
		return nil, fmt.Errorf("invalid signature format")
	}
	headerB64 := splits[0]
	signatureB64 := splits[1]
	header, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, fmt.Errorf("jws header base64 decode failed: %v", err)
	}
	signature := make([]byte, base64.RawURLEncoding.DecodedLen(len(signatureB64)))
	length, err := base64.RawURLEncoding.Decode(signature, []byte(signatureB64))
	if err != nil {
		return nil, fmt.Errorf("signature base64 decode failed: %v", err)
	}
	signature = signature[:length]

	var jwsHeader jws.JwsHeader
	err = json.Unmarshal(header, &jwsHeader)
	if err != nil {
		return nil, fmt.Errorf("jws header json unmarshalling failed: %v", err)
	}

	return &TlSignature{
		JwsHeader:    &jwsHeader,
		HeaderBase64: headerB64,
		Signature:    signature,
	}, nil
}
