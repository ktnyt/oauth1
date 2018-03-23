package oauth1

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ktnyt/oauth1/internal"
	"golang.org/x/net/context"
)

// NoContext is the default context you should supply if not using
// your own context.Context (see https://golang.org/x/net/context).
//
// Deprecated: Use context.Background() or context.TODO() instead.
var NoContext = context.TODO()

// Config describes a typical OAuth1 flow, given a Consumer Key,
// Consumer Secret, and a Callback URL.
type Config struct {
	// Context
	Context context.Context

	// Consumer Key (Client Identifier)
	ConsumerKey string

	// Consumer Secret (Client Shared-Secret)
	ConsumerSecret string

	// Callback URL
	CallbackURL string

	// Provider Endpoint specifying OAuth1 endpoint URLs
	Endpoint Endpoint
}

// Endpoint contains the OAuth 1.0 provider's request token,
// authorization, and access token URLs.
type Endpoint struct {
	// Request URL (Temporary Credential Request URI)
	RequestTokenURL string

	// Authorize URL (Resource Owner Authorization URI)
	AuthorizeURL string

	// Access Token URL (Token Request URI)
	AccessTokenURL string
}

// Client returns an HTTP client using the provided access tokens.
// HTTP transport will be obtained using the provided context.
// The returned client and its Transport should not be modified.
func (c *Config) Client(ctx context.Context, accessToken, accessSecret string) *http.Client {
	return NewClient(ctx, c.ConsumerKey, c.ConsumerSecret, accessToken, accessSecret)
}

// RequestToken obtains a Request token and secret (temporary credential) by
// POSTing a request (with oauth_callback in the auth header) to the Endpoint
// RequestTokenURL. The response body form is validated to ensure
// oauth_callback_confirmed is true. Returns the request token and secret
// (temporary credentials).
// See RFC 5849 2.1 Temporary Credentials.
func (c *Config) RequestToken() (string, string, error) {
	// Setup to request a request_token pair
	req, err := http.NewRequest("POST", c.Endpoint.RequestTokenURL, nil)
	if err != nil {
		return "", "", err
	}
	params, err := prepareParams(req, c.ConsumerKey)
	if err != nil {
		return "", "", err
	}
	params.Add("oauth_callback", c.CallbackURL)
	signer := Signer{nonce(), time.Now()}
	signature, err := signer.Sign(c.ConsumerSecret, "", req, params)
	if err != nil {
		return "", "", err
	}
	params.Add("oauth_signature", signature)
	req.Header.Add("Authorization", formatOAuthHeader(params))

	// Request a request_token pair
	res, err := internal.ContextClient(c.Context).Do(req)
	if err != nil {
		return "", "", err
	}
	defer res.Body.Close()

	// Handle request_token response
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("oauth1: Server returned unexpected status %d", res.StatusCode)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", "", err
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", "", err
	}
	requestToken := values.Get("oauth_token")
	requestSecret := values.Get("oauth_token_secret")
	if requestToken == "" || requestSecret == "" {
		return "", "", errors.New("oauth1: Response missing oauth_token or oauth_token_secret")
	}
	if values.Get("oauth_callback_confirmed") != "true" {
		return "", "", errors.New("oauth1: oauth_callback_confirmed was not true")
	}
	return requestToken, requestSecret, nil
}

// AuthorizationURL accepts a request token and returns the *url.URL to the
// Endpoint's authorization page that asks the user (resource owner) for to
// authorize the consumer to act on his/her/its behalf.
// See RFC 5849 2.2 Resource Owner Authorization.
func (c *Config) AuthorizationURL(requestToken string) (*url.URL, error) {
	authorizationURL, err := url.Parse(c.Endpoint.AuthorizeURL)
	if err != nil {
		return nil, err
	}
	values := authorizationURL.Query()
	values.Add("oauth_token", requestToken)
	authorizationURL.RawQuery = values.Encode()
	return authorizationURL, nil
}

// ParseAuthorizationCallback parses an OAuth1 authorization callback request
// from a provider server. The oauth_token and oauth_verifier parameters are
// parsed to return the request token from earlier in the flow and the
// verifier string.
// See RFC 5849 2.2 Resource Owner Authorization.
func ParseAuthorizationCallback(req *http.Request) (string, string, error) {
	err := req.ParseForm()
	if err != nil {
		return "", "", err
	}
	requestToken := req.Form.Get("oauth_token")
	verifier := req.Form.Get("oauth_verifier")
	if requestToken == "" || verifier == "" {
		return "", "", errors.New("oauth1: Request missing oauth_token or oauth_verifier")
	}
	return requestToken, verifier, nil
}

// AccessToken obtains an access token (token credential) by POSTing a
// request (with oauth_token and oauth_verifier in the auth header) to the
// Endpoint AccessTokenURL. Returns the access token and secret (token
// credentials).
// See RFC 5849 2.3 Token Credentials.
func (c *Config) AccessToken(requestToken, requestSecret, verifier string) (string, string, error) {
	// Setup to request an access_token pair
	req, err := http.NewRequest("POST", c.Endpoint.AccessTokenURL, nil)
	if err != nil {
		return "", "", err
	}
	params, err := prepareParams(req, c.ConsumerKey)
	if err != nil {
		return "", "", err
	}
	params.Add("oauth_token", requestToken)
	params.Add("oauth_verifier", verifier)
	signer := Signer{nonce(), time.Now()}
	signature, err := signer.Sign(c.ConsumerSecret, "", req, params)
	if err != nil {
		return "", "", err
	}
	params.Add("oauth_signature", signature)
	req.Header.Add("Authorization", formatOAuthHeader(params))

	// Request an access_token pair
	res, err := internal.ContextClient(c.Context).Do(req)
	if err != nil {
		return "", "", err
	}
	defer res.Body.Close()

	// Handle access_token response
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("oauth1: Server returned unexpected status %d", res.StatusCode)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", "", err
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", "", err
	}
	accessToken := values.Get("oauth_token")
	accessSecret := values.Get("oauth_token_secret")
	if accessToken == "" || accessSecret == "" {
		return "", "", errors.New("oauth1: Response missing oauth_token or oauth_token_secret")
	}
	return accessToken, accessSecret, nil
}

// HTTPClient is the context key to use with 's WithValue function
// to associate an *http.Client value with a context.
var HTTPClient internal.ContextKey

// NewClient creates an *http.Client from a Context and tokens.
// The returned client is not valid beyond the lifetime of the context.
//
// Note that if a custom *http.Client is provided via the Context it
// is used only for token acquisition and is not used to configure the
// *http.Client returned from NewClient.
func NewClient(ctx context.Context, consumerKey, consumerSecret, accessToken, accessSecret string) *http.Client {
	return &http.Client{
		Transport: &Transport{
			Base:           internal.ContextClient(ctx).Transport,
			consumerKey:    consumerKey,
			consumerSecret: consumerSecret,
			accessToken:    accessToken,
			accessSecret:   accessSecret,
		},
	}
}

// Signer provdes dyanmic data required to sign an OAuth1 signature.
type Signer struct {
	Nonce     string
	Timestamp time.Time
}

// Base returns the signature base string
func (s Signer) Base(req *http.Request, params url.Values) string {
	params.Add("oauth_nonce", s.Nonce)
	params.Add("oauth_timestamp", strconv.FormatInt(s.Timestamp.Unix(), 10))
	baseURL, _ := url.Parse(req.URL.String())
	baseURL.RawQuery = ""
	upperMethod := strings.ToUpper(req.Method)
	escapedURL := url.QueryEscape(baseURL.String())
	escapedParams := url.QueryEscape(normalizeSpace(params.Encode()))
	return strings.Join([]string{upperMethod, escapedURL, escapedParams}, "&")
}

// Sign creates a concatenated consumer and token secret key and calculates
// the HMAC digest of the message. Returns the base64 encoded digest bytes.
func (s Signer) Sign(consumerSecret, tokenSecret string, req *http.Request, params url.Values) (string, error) {
	base := s.Base(req, params)
	key := strings.Join([]string{consumerSecret, tokenSecret}, "&")
	h := hmac.New(sha1.New, []byte(key))
	if _, err := h.Write([]byte(base)); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func nonce() string {
	h := md5.New()
	now := time.Now().Unix()
	io.WriteString(h, strconv.FormatInt(now, 10))
	io.WriteString(h, strconv.FormatInt(rand.Int63(), 10))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func prepareParams(r *http.Request, consumerKey string) (url.Values, error) {
	params := make(url.Values)
	if r.Body != nil && r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return params, err
		}
		params, err = url.ParseQuery(string(b))
		if err != nil {
			return params, err
		}
		r.Body = ioutil.NopCloser(bytes.NewReader(b))
	}
	for key, values := range r.URL.Query() {
		for i := range values {
			params.Add(key, url.QueryEscape(values[i]))
		}
	}
	params.Add("oauth_consumer_key", consumerKey)
	params.Add("oauth_signature_method", "HMAC-SHA1")
	params.Add("oauth_version", "1.0")
	return params, nil
}

func formatOAuthHeader(params url.Values) string {
	joined := normalizeSpace(params.Encode())
	pairs := strings.Split(joined, "&")
	for i := range pairs {
		pair := strings.Split(pairs[i], "=")
		pairs[i] = fmt.Sprintf("%s=\"%s\"", pair[0], pair[1])
	}
	return fmt.Sprintf("OAuth %s", strings.Join(pairs, ", "))
}

func normalizeSpace(s string) string {
	return strings.Replace(s, "+", "%20", -1)
}
