package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
)

// ParseEcPrivateKey parses the private key data and produces an elliptic curve private key
func ParseEcPrivateKey(privateKeyData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyData)
	x509Encoded := block.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		return nil, err
	}
	if privateKey.Curve.Params().Name != "P-521" {
		return nil, fmt.Errorf("the underlying elliptic curve must be P-521 to sign using ES512")
	}
	return privateKey, nil
}

// ParseEcPublicKey parses the public key data and produces an elliptic curve public key
func ParseEcPublicKey(publicKeyData []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyData)
	x509Encoded := block.Bytes
	genericPublicKey, err := x509.ParsePKIXPublicKey(x509Encoded)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("public key parsing failed: %v", err))
	}
	publicKey, ok := genericPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an ECDSA key")
	}
	if publicKey.Curve.Params().Name != "P-521" {
		return nil, fmt.Errorf("the underlying elliptic curve must be P-521 to sign using ES512")
	}
	return publicKey, nil
}

// Read JWKs json then find & parse the JWK for the given signatureKid
func FindAndParseEcJwk(signatureKid []byte, jwksData []byte) (*ecdsa.PublicKey, error) {
	var jwksStruct jwks
	err := json.Unmarshal(jwksData, &jwksStruct)
	if err != nil {
		return nil, fmt.Errorf("jwks parsing failed: %v", err)
	}

	// Find key with specified kid
	for _, v := range jwksStruct.Keys {
		if v.Kid == string(signatureKid) {
			return v.parseP521()
		}
	}

	return nil, fmt.Errorf("no jwk found for signature kid")
}

// SignES512 signs a payload using the provided private key and return the signature
// Check section A.4 of RFC7515 for the details <https://www.rfc-editor.org/rfc/rfc7515.txt>
func SignES512(key *ecdsa.PrivateKey, payload []byte) ([]byte, error) {
	sha512 := crypto.SHA512.New()
	_, err := sha512.Write(payload)
	if err != nil {
		return nil, fmt.Errorf("hashing failed: %v", err)
	}
	hash := sha512.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, key, hash)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %v", err)
	}

	// Padding to fixed length provided by FillBytes, as a zero-extended big-endian byte slice
	// representation of the big int
	rBytes := make([]byte, 66)
	rBytes = r.FillBytes(rBytes)

	sBytes := make([]byte, 66)
	sBytes = s.FillBytes(sBytes)

	signature := append(rBytes, sBytes...)

	return signature, nil
}

// VerifyES512 verifies the signature of a payload using the provided public key
func VerifyES512(key *ecdsa.PublicKey, payload []byte, signature []byte) error {
	if len(signature) != 132 {
		return fmt.Errorf("signature length != 132")
	}

	r := new(big.Int)
	r.SetBytes(signature[0:66])

	s := new(big.Int)
	s.SetBytes(signature[66:132])

	sha512 := crypto.SHA512.New()
	_, err := sha512.Write(payload)
	if err != nil {
		return fmt.Errorf("hashing failed: %v", err)
	}
	hash := sha512.Sum(nil)

	valid := ecdsa.Verify(key, hash, r, s)

	if !valid {
		return fmt.Errorf("signature not valid")
	}
	return nil
}

// JWKs json response.
type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (jwk jwk) parseP521() (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" {
		return nil, fmt.Errorf("unsupported jwk kty")
	}
	if jwk.Crv != "P-521" {
		return nil, fmt.Errorf("unsupported jwk crv")
	}

	x := new(big.Int)
	y := new(big.Int)

	// Deserialize x into BigInt
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("x base64 decoding failed: %v", err)
	}
	x = x.SetBytes(xBytes)

	// Deserialize y into BigInt
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("y base64 decoding failed: %v", err)
	}
	y = y.SetBytes(yBytes)

	// Rebuild public key from x and y
	return &ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P521()}, nil
}
