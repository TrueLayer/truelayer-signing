package verify

import (
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
	body            []byte
	method          string
	path            string
	headers         map[string][]byte
	requiredHeaders []string
	allowV1         bool
}

func NewVerifier(publicKeyPem []byte) *Verifier {
	verifier := Verifier{}
	verifier.publicKey = publicKeyPem
	verifier.method = "POST"
	verifier.path = ""
	verifier.body = []byte("")
	verifier.headers = make(map[string][]byte)
	verifier.allowV1 = false
	return &verifier
}

// Sets whether v1 body-only signature are allowed to pass verification.
// Default "false".
// "true" means both v1 & v2 signatures are allowed.
func (v *Verifier) AllowV1(allowV1 bool) *Verifier {
	v.allowV1 = allowV1
	return v
}

// Add the full received request body.
func (v *Verifier) Body(body []byte) *Verifier {
	v.body = body
	return v
}

// Add the request method, e.g. "POST".
func (v *Verifier) Method(method string) *Verifier {
	v.method = method
	return v
}

// Add the request path, e.g. "/payouts".
func (v *Verifier) Path(path string) *Verifier {
	v.path = path
	return v
}

// Add a header name & value.
// May be called multiple times to add multiple different headers.
//
// All request headers may be added here, any headers not mentioned
// in the jws signature header will be ignored unless required
// using "RequiredHeader".
func (v *Verifier) Header(name string, value []byte) *Verifier {
	v.AddHeader(name, value)
	return v
}

// Add a header name & value.
// May be called multiple times to add multiple different headers.
//
// All request headers may be added here, any headers not mentioned
// in the jws signature header will be ignored unless required
// using "RequiredHeader".
func (v *Verifier) AddHeader(name string, value []byte) {
	v.headers[strings.ToLower(name)] = value
}

// Required a header name that must be included in the "Tl-Signature".
// May be called multiple times to add multiple required headers.
//
// Signatures missing these will fail verification.
func (v *Verifier) RequireHeader(name string) *Verifier {
	v.requiredHeaders = append(v.requiredHeaders, name)
	return v
}

// Verify the given "Tl-Signature" header value.
//
// Supports v1 (body-only) & v2 full request signatures.
//
// Returns error if verification fails.
func (v *Verifier) Verify(tlSignature string) (bool, error) {
	publicKey, err := crypto.ParseEcPublicKey(v.publicKey)
	if err != nil {
		return false, errors.NewInvalidKeyError(fmt.Sprintf("public key parsing failed: %v", err))
	}
	jwsHeader, headerB64, signature, err := ParseTlSignature(tlSignature)
	if err != nil {
		return false, errors.NewJwsError(fmt.Sprintf("signature parsing failed: %v", err))
	}

	if jwsHeader.Alg != "ES512" {
		return false, errors.NewJwsError(fmt.Sprintf("unexpected header alg: %s", jwsHeader.Alg))
	}

	if jwsHeader.TlVersion == "" || jwsHeader.TlVersion == "1" {
		if !v.allowV1 {
			return false, errors.NewJwsError("v1 signature not allowed")
		}

		// v1 signature: body only
		body := base64.RawURLEncoding.EncodeToString(v.body)
		payload := fmt.Sprintf("%s.%s", headerB64, body)
		verified, err := crypto.VerifyES512(publicKey, []byte(payload), signature)
		if err != nil {
			return false, errors.NewJwsError(fmt.Sprintf("verification failed: %v", err))
		}

		return verified, nil
	}

	// check and order all required headers
	orderedHeaders, err := jwsHeader.FilterHeaders(v.headers)
	if err != nil {
		return false, errors.NewJwsError(fmt.Sprintf("headers filtering failed: %v", err))
	}
	// fail if signature is missing a required header
	for _, header := range v.requiredHeaders {
		_, exists := orderedHeaders.Get(strings.ToLower(header))
		if !exists {
			return false, errors.NewJwsError(fmt.Sprintf("signature is missing required header: %s", header))
		}
	}

	// reconstruct the payload as it would have been signed
	signingPayload := sign.BuildV2SigningPayload(v.method, v.path, orderedHeaders, v.body)
	signingPayloadB64 := base64.RawURLEncoding.EncodeToString(signingPayload)
	payload := fmt.Sprintf("%s.%s", headerB64, signingPayloadB64)
	verified, err := crypto.VerifyES512(publicKey, []byte(payload), signature)
	if err != nil {
		return false, errors.NewJwsError(fmt.Sprintf("signature verification failed: %v", err))
	}

	return verified, nil
}

// Parse a tl signature header value into (header, headerBase64, signature).
func ParseTlSignature(tlSignature string) (*jws.JwsHeader, string, []byte, error) {
	splits := strings.Split(tlSignature, "..")
	if len(splits) != 2 {
		return nil, "", nil, fmt.Errorf("invalid signature format")
	}
	headerB64 := splits[0]
	signatureB64 := splits[1]
	header, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, "", nil, fmt.Errorf("jws header base64 decode failed: %v", err)
	}
	signature := make([]byte, base64.RawURLEncoding.DecodedLen(len(signatureB64)))
	length, err := base64.RawURLEncoding.Decode(signature, []byte(signatureB64))
	if err != nil {
		return nil, "", nil, fmt.Errorf("signature base64 decode failed: %v", err)
	}
	signature = signature[:length]

	var jwsHeader jws.JwsHeader
	err = json.Unmarshal(header, &jwsHeader)
	if err != nil {
		return nil, "", nil, fmt.Errorf("jws header json unmarshalling failed: %v", err)
	}

	return &jwsHeader, headerB64, signature, nil
}
