package main

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"

	tlsigning "github.com/Truelayer/truelayer-signing/go"
	"github.com/google/uuid"
)

// the base url to use
const (
	TlBaseURL = "https://api.truelayer-sandbox.com"
)

func main() {
	// Read required env vars
	kid, found := os.LookupEnv("KID")
	if !found {
		fmt.Println("Missing env var KID")
		os.Exit(1)
	}
	accessToken, found := os.LookupEnv("ACCESS_TOKEN")
	if !found {
		fmt.Println("Missing env var ACCESS_TOKEN")
		os.Exit(1)
	}
	privateKey, found := os.LookupEnv("PRIVATE_KEY")
	if !found {
		fmt.Println("Missing env var PRIVATE_KEY")
		os.Exit(1)
	}

	// A random body string is enough for this request as `/test-signature` endpoint does not
	// require any schema, it simply checks the signature is valid against what's received.
	body := fmt.Sprintf("body-%d", rand.Intn(99999999))

	idempotencyKey := uuid.New().String()

	// Generate tl-signature
	tlSignature, err := tlsigning.SignWithPem(kid, []byte(privateKey)).
		Method("POST"). // as we're sending a POST request
		Path("/test-signature").
		// Optional: /test-signature does not require any headers, but we may sign some anyway.
		// All signed headers *must* be included unmodified in the request.
		Header("Idempotency-Key", []byte(idempotencyKey)).
		Header("X-Bar-Header", []byte("abc123")).
		Body([]byte(body)). // body of our request
		Sign()

	if err != nil {
		fmt.Printf("Failed signing: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Println("Sending...")

	// Request body & any signed headers *must* exactly match what was used to generate the signature.
	client := &http.Client{}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/test-signature", TlBaseURL), strings.NewReader(body))
	if err != nil {
		fmt.Printf("Failed request creation: %s\n", err.Error())
		os.Exit(1)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Add("Idempotency-Key", idempotencyKey)
	req.Header.Add("X-Bar-Header", "abc123")
	req.Header.Add("Tl-Signature", tlSignature)
	resp, err := client.Do(req)

	statusCode := -1
	var responseBody string
	if err == nil {
		statusCode := resp.StatusCode
		if statusCode == 204 {
			responseBody = "✓"
		} else {
			defer resp.Body.Close()
			responseBodyBytes, err := io.ReadAll(resp.Body)
			if err == nil {
				responseBody = string(responseBodyBytes)
			} else {
				responseBody = fmt.Sprintf("Failed reading response body: %s", err.Error())
			}
		}
	} else {
		responseBody = fmt.Sprintf("Test signature request failed: %s", err.Error())
	}

	// 204 means success
	// 401 means either the access token is invalid, or the signature is invalid.
	fmt.Printf("%d %s\n", statusCode, responseBody)
}
