package errors

import "fmt"

// Key data is invalid
type InvalidKeyError struct {
	message string
}

func NewInvalidKeyError(msg string) *InvalidKeyError {
	return &InvalidKeyError{
		message: fmt.Sprintf("invalid key: %s", msg),
	}
}

func (e *InvalidKeyError) Error() string {
	return e.message
}

// JWS signature generation or verification failed
type JwsError struct {
	message string
}

func NewJwsError(msg string) *JwsError {
	return &JwsError{
		message: fmt.Sprintf("jws signing/verification failed: %s", msg),
	}
}

func (e *JwsError) Error() string {
	return e.message
}
