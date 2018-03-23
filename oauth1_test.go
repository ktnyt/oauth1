package oauth1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

const expectedVerifier = "some_verifier"

func TestNewClient(t *testing.T) {
	expectedToken := "access_token"
	expectedConsumerKey := "consumer_key"
	config := Config{
		Context:        NoContext,
		ConsumerKey:    expectedConsumerKey,
		ConsumerSecret: "consumer_secret",
	}
	client := config.Client(NoContext, expectedToken, "access_secret")

	server := newMockServer(func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "GET", req.Method)
		params := parseOAuthParamsOrFail(t, req.Header.Get("Authorization"))
		assert.Equal(t, expectedToken, params["oauth_token"])
		assert.Equal(t, expectedConsumerKey, params["oauth_consumer_key"])
	})
	defer server.Close()
	client.Get(server.URL)
}

func TestNewClient_DefaultTransport(t *testing.T) {
	config := &Config{
		Context:        NoContext,
		ConsumerKey:    "t",
		ConsumerSecret: "s",
	}
	client := NewClient(NoContext, config.ConsumerKey, config.ConsumerSecret, "t", "s")
	// assert that the client uses the DefaultTransport
	transport, ok := client.Transport.(*Transport)
	assert.True(t, ok)
	assert.Equal(t, http.DefaultTransport, transport.base())
}

func TestNewClient_ContextClientTransport(t *testing.T) {
	baseTransport := &http.Transport{}
	baseClient := &http.Client{Transport: baseTransport}
	ctx := context.WithValue(NoContext, HTTPClient, baseClient)
	config := &Config{
		Context:        NoContext,
		ConsumerKey:    "t",
		ConsumerSecret: "s",
	}
	client := NewClient(ctx, config.ConsumerKey, config.ConsumerSecret, "t", "s")
	// assert that the client uses the ctx client's Transport as its base RoundTripper
	transport, ok := client.Transport.(*Transport)
	assert.True(t, ok)
	assert.Equal(t, baseTransport, transport.base())
}

// newRequestTokenServer returns a new httptest.Server for an OAuth1 provider
// request token endpoint.
func newRequestTokenServer(t *testing.T, data url.Values) *httptest.Server {
	return newMockServer(func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "POST", req.Method)
		assert.NotEmpty(t, req.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte(data.Encode()))
	})
}

// newAccessTokenServer returns a new httptest.Server for an OAuth1 provider
// access token endpoint.
func newAccessTokenServer(t *testing.T, data url.Values) *httptest.Server {
	return newMockServer(func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "POST", req.Method)
		assert.NotEmpty(t, req.Header.Get("Authorization"))
		params := parseOAuthParamsOrFail(t, req.Header.Get("Authorization"))
		assert.Equal(t, expectedVerifier, params["oauth_verifier"])
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte(data.Encode()))
	})
}

// newUnparseableBodyServer returns a new httptest.Server which writes
// responses with bodies that error when parsed by url.ParseQuery.
func newUnparseableBodyServer() *httptest.Server {
	return newMockServer(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		// url.ParseQuery will error, https://golang.org/src/net/url/url_test.go#L1107
		w.Write([]byte("%gh&%ij"))
	})
}

func TestConfigRequestToken(t *testing.T) {
	expectedToken := "reqest_token"
	expectedSecret := "request_secret"
	data := url.Values{}
	data.Add("oauth_token", expectedToken)
	data.Add("oauth_token_secret", expectedSecret)
	data.Add("oauth_callback_confirmed", "true")
	server := newRequestTokenServer(t, data)
	defer server.Close()

	config := &Config{
		Endpoint: Endpoint{
			RequestTokenURL: server.URL,
		},
	}
	requestToken, requestSecret, err := config.RequestToken()
	assert.Nil(t, err)
	assert.Equal(t, expectedToken, requestToken)
	assert.Equal(t, expectedSecret, requestSecret)
}

func TestConfigRequestToken_InvalidRequestTokenURL(t *testing.T) {
	config := &Config{
		Endpoint: Endpoint{
			RequestTokenURL: "http://wrong.com/oauth/request_token",
		},
	}
	requestToken, requestSecret, err := config.RequestToken()
	assert.NotNil(t, err)
	assert.Equal(t, "", requestToken)
	assert.Equal(t, "", requestSecret)
}

func TestConfigAccessToken_CannotParseBody(t *testing.T) {
	server := newUnparseableBodyServer()
	defer server.Close()

	config := &Config{
		Endpoint: Endpoint{
			AccessTokenURL: server.URL,
		},
	}
	accessToken, accessSecret, err := config.AccessToken("any_token", "any_secret", "any_verifier")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "invalid URL escape")
	}
	assert.Equal(t, "", accessToken)
	assert.Equal(t, "", accessSecret)
}

func TestConfigAccessToken_MissingTokenOrSecret(t *testing.T) {
	data := url.Values{}
	data.Add("oauth_token", "any_token")
	server := newAccessTokenServer(t, data)
	defer server.Close()

	config := &Config{
		Endpoint: Endpoint{
			AccessTokenURL: server.URL,
		},
	}
	accessToken, accessSecret, err := config.AccessToken("request_token", "request_secret", expectedVerifier)
	if assert.Error(t, err) {
		assert.Equal(t, "oauth1: Response missing oauth_token or oauth_token_secret", err.Error())
	}
	assert.Equal(t, "", accessToken)
	assert.Equal(t, "", accessSecret)
}

func TestParseAuthorizationCallback_GET(t *testing.T) {
	expectedToken := "token"
	expectedVerifier := "verifier"
	server := newMockServer(func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "GET", req.Method)
		// logic under test
		requestToken, verifier, err := ParseAuthorizationCallback(req)
		assert.Nil(t, err)
		assert.Equal(t, expectedToken, requestToken)
		assert.Equal(t, expectedVerifier, verifier)
	})
	defer server.Close()

	// OAuth1 provider calls callback url
	url, err := url.Parse(server.URL)
	assert.Nil(t, err)
	query := url.Query()
	query.Add("oauth_token", expectedToken)
	query.Add("oauth_verifier", expectedVerifier)
	url.RawQuery = query.Encode()
	http.Get(url.String())
}

func TestParseAuthorizationCallback_POST(t *testing.T) {
	expectedToken := "token"
	expectedVerifier := "verifier"
	server := newMockServer(func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "POST", req.Method)
		// logic under test
		requestToken, verifier, err := ParseAuthorizationCallback(req)
		assert.Nil(t, err)
		assert.Equal(t, expectedToken, requestToken)
		assert.Equal(t, expectedVerifier, verifier)
	})
	defer server.Close()

	// OAuth1 provider calls callback url
	form := url.Values{}
	form.Add("oauth_token", expectedToken)
	form.Add("oauth_verifier", expectedVerifier)
	http.PostForm(server.URL, form)
}

func TestParseAuthorizationCallback_MissingTokenOrVerifier(t *testing.T) {
	server := newMockServer(func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "GET", req.Method)
		// logic under test
		requestToken, verifier, err := ParseAuthorizationCallback(req)
		if assert.Error(t, err) {
			assert.Equal(t, "oauth1: Request missing oauth_token or oauth_verifier", err.Error())
		}
		assert.Equal(t, "", requestToken)
		assert.Equal(t, "", verifier)
	})
	defer server.Close()

	// OAuth1 provider calls callback url
	url, err := url.Parse(server.URL)
	assert.Nil(t, err)
	query := url.Query()
	query.Add("oauth_token", "any_token")
	query.Add("oauth_verifier", "") // missing oauth_verifier
	url.RawQuery = query.Encode()
	http.Get(url.String())
}
