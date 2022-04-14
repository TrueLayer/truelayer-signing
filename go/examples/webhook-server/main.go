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
	tp := httpcache.NewMemoryCacheTransport()
	client := http.Client{Transport: tp}

	http.HandleFunc("/hook/d7a2c49d-110a-4ed2-a07d-8fdb3ea6424b", receiveHook(&client))

	log.Println("Starting server on: 7000")

	log.Fatal(http.ListenAndServe(":7000", nil))
}

func receiveHook(client *http.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method is not supported.", http.StatusMethodNotAllowed)
			return
		}

		err := verifyHook(client, r)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusUnauthorized)
		}

		// handle verified hook

		w.WriteHeader(http.StatusAccepted)
	}
}

func verifyHook(client *http.Client, r *http.Request) error {
	tlSignature := r.Header.Get("Tl-Signature")
	if len(tlSignature) == 0 {
		return fmt.Errorf("missing Tl-Signature header")
	}

	jwsHeader, err := tlsigning.ExtractJwsHeader(tlSignature)
	if err != nil {
		return err
	}
	if len(jwsHeader.Jku) == 0 {
		return fmt.Errorf("jku missing")
	}

	defer r.Body.Close()
	webhookBody, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("webhook body missing")
	}

	// ensure jku is an expected TrueLayer url
	if jwsHeader.Jku != "https://webhooks.truelayer.com/.well-known/jwks" && jwsHeader.Jku != "https://webhooks.truelayer-sandbox.com/.well-known/jwks" {
		return fmt.Errorf("unpermitted jku %s", jwsHeader.Jku)
	}

	// fetch jwks (cached according to cache-control headers)
	resp, err := client.Get(jwsHeader.Jku)
	if err != nil {
		return fmt.Errorf("failed to fetch jwks")
	}
	defer resp.Body.Close()
	jwks, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("jwks missing")
	}

	// verify signature using the jwks
	return tlsigning.VerifyWithJwks(jwks).Method(http.MethodPost).Path(r.RequestURI).Headers(getHeadersMap(r.Header)).Body(webhookBody).Verify(tlSignature)
}

func getHeadersMap(requestHeaders map[string][]string) map[string][]byte {
	headers := make(map[string][]byte)
	for key, values := range requestHeaders {
		// take first value
		headers[key] = []byte(values[0])
	}
	return headers
}
