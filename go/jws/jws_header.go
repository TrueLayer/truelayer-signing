package jws

import (
	"fmt"
	"strings"

	tlhttp "github.com/Truelayer/truelayer-signing/go/http"
	orderedmap "github.com/wk8/go-ordered-map"
)

// Tl-Signature header.
type JwsHeader struct {
	Alg       string `json:"alg"`        // algorithm, should be "ES512".
	Kid       string `json:"kid"`        // signing key id.
	TlVersion string `json:"tl_version"` // signing scheme version, e.g. "2", empty implies v1 aka body-only signing.
	TlHeaders string `json:"tl_headers"` // comma separated ordered headers used in the signature.
}

func NewJwsHeaderV2(kid string, headers *orderedmap.OrderedMap) JwsHeader {
	headerKeys := ""
	for pair := headers.Oldest(); pair != nil; pair = pair.Next() {
		header := pair.Value.(*tlhttp.Header)
		if len(headerKeys) > 0 {
			headerKeys += ","
		}
		headerKeys += header.Name
	}

	return JwsHeader{
		Alg:       "ES512",
		Kid:       kid,
		TlVersion: "2",
		TlHeaders: headerKeys,
	}
}

// FilterHeaders filters & orders headers to match jws header "tl_headers".
//
// Returns an error if "headers" is missing any of the declared "tl_headers".
func (j *JwsHeader) FilterHeaders(headers map[string][]byte) (*orderedmap.OrderedMap, error) {
	requiredHeaders := strings.Split(j.TlHeaders, ",")

	orderedMap := orderedmap.New()

	// populate required headers in jws-header order
	for _, headerName := range requiredHeaders {
		value, isThere := headers[strings.ToLower(headerName)]
		if isThere {
			orderedMap.Set(strings.ToLower(headerName), &tlhttp.Header{
				Name:  headerName, // need to use the original case of the header name
				Value: value,
			})
		} else {
			return nil, fmt.Errorf("Missing tl_header `%s` declared in signature", headerName)
		}
	}

	return orderedMap, nil
}
