package oauth1

import (
	"net/http"
	"time"
)

// Transport is an http.RoundTripper which makes OAuth1 HTTP requests. It
// wraps a base RoundTripper and adds an Authorization header using the
// token from a TokenSource.
//
// Transport is a low-level component, most users should use Config to create
// an http.Client instead.
type Transport struct {
	// Base is the base RoundTripper used to make HTTP requests. If nil, then
	// http.DefaultTransport is used
	Base http.RoundTripper

	consumerKey    string
	consumerSecret string
	accessToken    string
	accessSecret   string
}

// RoundTrip authorizes the request with a signed OAuth1 Authorization header
// using the credentials given.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := cloneRequest(req)
	params, err := prepareParams(req, t.consumerKey)
	if err != nil {
		return nil, err
	}
	params.Add("oauth_token", t.accessToken)
	signer := Signer{nonce(), time.Now()}
	signature, err := signer.Sign(t.consumerSecret, t.accessSecret, req, params)
	if err != nil {
		return nil, err
	}
	params.Add("oauth_signature", signature)
	req2.Header.Add("Authorization", formatOAuthHeader(params))
	return t.base().RoundTrip(req2)
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// cloneRequest returns a clone of the given *http.Request with a shallow
// copy of struct fields and a deep copy of the Header map.
func cloneRequest(req *http.Request) *http.Request {
	// shallow copy the struct
	r2 := new(http.Request)
	*r2 = *req
	// deep copy Header so setting a header on the clone does not affect original
	r2.Header = make(http.Header, len(req.Header))
	for k, s := range req.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
