package oauth1

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTransport(t *testing.T) {
	const (
		expectedToken           = "access_token"
		expectedConsumerKey     = "consumer_key"
		expectedSignatureMethod = "HMAC-SHA1"
		expectedOAuthVersion    = "1.0"
	)
	server := newMockServer(func(w http.ResponseWriter, req *http.Request) {
		params := parseOAuthParamsOrFail(t, req.Header.Get("Authorization"))
		assert.Equal(t, expectedToken, params["oauth_token"])
		assert.Equal(t, expectedConsumerKey, params["oauth_consumer_key"])
		assert.Equal(t, expectedSignatureMethod, params["oauth_signature_method"])
		assert.Equal(t, expectedOAuthVersion, params["oauth_version"])
		// oauth_signature will vary, httptest.Server uses a random port
	})
	defer server.Close()

	tr := &Transport{
		consumerKey:    expectedConsumerKey,
		consumerSecret: "consumer_secret",
		accessToken:    expectedToken,
		accessSecret:   "some_secret",
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", server.URL, nil)
	assert.Nil(t, err)
	_, err = client.Do(req)
	assert.Nil(t, err)
}

func TestTransport_defaultBaseTransport(t *testing.T) {
	tr := &Transport{
		Base: nil,
	}
	assert.Equal(t, http.DefaultTransport, tr.base())
}

func TestTransport_customBaseTransport(t *testing.T) {
	expected := &http.Transport{}
	tr := &Transport{
		Base: expected,
	}
	assert.Equal(t, expected, tr.base())
}

func parseOAuthParamsOrFail(t *testing.T, authHeader string) map[string]string {
	if !strings.HasPrefix(authHeader, "OAuth") {
		assert.Fail(t, fmt.Sprintf("Expected Authorization header to start with \"OAuth\", got \"%s\"", authHeader[:6]))
	}
	params := map[string]string{}
	for _, pairStr := range strings.Split(authHeader[6:], ", ") {
		pair := strings.Split(pairStr, "=")
		if len(pair) != 2 {
			assert.Fail(t, "Error parsing OAuth parameter %s", pairStr)
		}
		params[pair[0]] = strings.Replace(pair[1], "\"", "", -1)
	}
	return params
}

func newMockServer(handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handler))
}
