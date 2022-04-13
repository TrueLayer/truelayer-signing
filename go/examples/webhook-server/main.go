package main

import (
	"fmt"
	"io"
	"log"
	"net/http"

	tlsigning "github.com/Truelayer/truelayer-signing/go"
	"github.com/gregjones/httpcache"
)

func main() {
	http.HandleFunc("/hook/d7a2c49d-110a-4ed2-a07d-8fdb3ea6424b", handler)

	log.Println("Starting server on: 7000")

	log.Fatal(http.ListenAndServe(":7000", nil))
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
		return
	}

	verified, err := verifyHook(r)
	if verified {
		w.WriteHeader(http.StatusAccepted)
	} else {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
	}
}

func verifyHook(r *http.Request) (bool, error) {
	tlSignature := r.Header.Get("Tl-Signature")
	if len(tlSignature) == 0 {
		return false, fmt.Errorf("missing Tl-Signature header")
	}

	jwsHeader, err := tlsigning.ExtractJwsHeader(tlSignature)
	if err != nil {
		return false, fmt.Errorf("jku missing")
	}

	defer r.Body.Close()
	webhookBody, err := io.ReadAll(r.Body)
	if err != nil {
		return false, fmt.Errorf("webhook body missing")
	}

	// ensure jku is an expected TrueLayer url
	if jwsHeader.Jku != "https://webhooks.truelayer.com/.well-known/jwks" && jwsHeader.Jku != "https://webhooks.truelayer-sandbox.com/.well-known/jwks" {
		return false, fmt.Errorf("unpermitted jku %s", jwsHeader.Jku)
	}

	// fetch jwks (cached according to cache-control headers)
	tp := httpcache.NewMemoryCacheTransport()
	client := http.Client{Transport: tp}
	resp, err := client.Get(jwsHeader.Jku)
	if err != nil {
		return false, fmt.Errorf("jku missing")
	}
	defer resp.Body.Close()
	jwks, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("jwks missing")
	}

	// verify signature using the jwks
	tlsigning.VerifyWithJwks(jwks).Method("POST").Path(r.RequestURI).Headers(getHeadersMap(r.Header)).Body(webhookBody).Verify(tlSignature)

	return true, nil
}

func getHeadersMap(requestHeaders map[string][]string) map[string][]byte {
	headers := make(map[string][]byte)
	for key, values := range requestHeaders {
		for _, value := range values {
			headers[key] = []byte(value)
		}
	}
	return headers
}
