package oauth1

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	expectedVersion         = "1.0"
	expectedSignatureMethod = "HMAC-SHA1"
)

func TestTwitterRequestTokenAuthHeader(t *testing.T) {
	// example from https://dev.twitter.com/web/sign-in/implementing
	var unixTimestamp int64 = 1318467427
	expectedConsumerKey := "cChZNFj6T5R0TigYB9yd1w"
	expectedCallback := "http%3A%2F%2Flocalhost%2Fsign-in-with-twitter%2F"
	expectedSignature := "F1Li3tvehgcraF8DMJ7OyxO4w9Y%3D"
	expectedTimestamp := "1318467427"
	expectedNonce := "ea9ec8429b68d6b77cd5600adbbb0456"
	config := &Config{
		ConsumerKey:    expectedConsumerKey,
		ConsumerSecret: "L8qq9PZyRg6ieKGEKhZolGC0vJWLw8iEJ88DRdyOg",
		CallbackURL:    "http://localhost/sign-in-with-twitter/",
		Endpoint: Endpoint{
			RequestTokenURL: "https://api.twitter.com/oauth/request_token",
			AuthorizeURL:    "https://api.twitter.com/oauth/authorize",
			AccessTokenURL:  "https://api.twitter.com/oauth/access_token",
		},
	}

	req, err := http.NewRequest("POST", config.Endpoint.RequestTokenURL, nil)
	assert.Nil(t, err)
	data, err := prepareParams(req, config.ConsumerKey)
	assert.Nil(t, err)
	data.Add("oauth_callback", config.CallbackURL)
	signer := Signer{expectedNonce, time.Unix(unixTimestamp, 0)}
	signature, err := signer.Sign(config.ConsumerSecret, "", req, data)
	assert.Nil(t, err)
	data.Add("oauth_signature", signature)
	req.Header.Add("Authorization", formatOAuthHeader(data))
	// assert the request for a request token is signed and has an oauth_callback
	assert.Nil(t, err)
	params := parseOAuthParamsOrFail(t, req.Header.Get("Authorization"))
	assert.Equal(t, expectedCallback, params["oauth_callback"])
	assert.Equal(t, expectedSignature, params["oauth_signature"])
	// additional OAuth parameters
	assert.Equal(t, expectedConsumerKey, params["oauth_consumer_key"])
	assert.Equal(t, expectedNonce, params["oauth_nonce"])
	assert.Equal(t, expectedTimestamp, params["oauth_timestamp"])
	assert.Equal(t, expectedVersion, params["oauth_version"])
	assert.Equal(t, expectedSignatureMethod, params["oauth_signature_method"])
}

func TestTwitterAccessTokenAuthHeader(t *testing.T) {
	// example from https://dev.twitter.com/web/sign-in/implementing
	var unixTimestamp int64 = 1318467427
	expectedConsumerKey := "cChZNFj6T5R0TigYB9yd1w"
	expectedRequestToken := "NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0"
	requestTokenSecret := "veNRnAWe6inFuo8o2u8SLLZLjolYDmDP7SzL0YfYI"
	expectedVerifier := "uw7NjWHT6OJ1MpJOXsHfNxoAhPKpgI8BlYDhxEjIBY"
	expectedSignature := "39cipBtIOHEEnybAR4sATQTpl2I%3D"
	expectedTimestamp := "1318467427"
	expectedNonce := "a9900fe68e2573b27a37f10fbad6a755"
	config := &Config{
		ConsumerKey:    expectedConsumerKey,
		ConsumerSecret: "L8qq9PZyRg6ieKGEKhZolGC0vJWLw8iEJ88DRdyOg",
		Endpoint: Endpoint{
			RequestTokenURL: "https://api.twitter.com/oauth/request_token",
			AuthorizeURL:    "https://api.twitter.com/oauth/authorize",
			AccessTokenURL:  "https://api.twitter.com/oauth/access_token",
		},
	}

	req, err := http.NewRequest("POST", config.Endpoint.AccessTokenURL, nil)
	assert.Nil(t, err)
	data, err := prepareParams(req, config.ConsumerKey)
	assert.Nil(t, err)
	data.Add("oauth_token", expectedRequestToken)
	data.Add("oauth_verifier", expectedVerifier)
	signer := Signer{expectedNonce, time.Unix(unixTimestamp, 0)}
	signature, err := signer.Sign(config.ConsumerSecret, requestTokenSecret, req, data)
	assert.Nil(t, err)
	data.Add("oauth_signature", signature)
	req.Header.Add("Authorization", formatOAuthHeader(data))
	// assert the request for an access token is signed and has an oauth_token and verifier
	assert.Nil(t, err)
	params := parseOAuthParamsOrFail(t, req.Header.Get("Authorization"))
	assert.Equal(t, expectedRequestToken, params["oauth_token"])
	assert.Equal(t, expectedVerifier, params["oauth_verifier"])
	assert.Equal(t, expectedSignature, params["oauth_signature"])
	// additional OAuth parameters
	assert.Equal(t, expectedConsumerKey, params["oauth_consumer_key"])
	assert.Equal(t, expectedNonce, params["oauth_nonce"])
	assert.Equal(t, expectedTimestamp, params["oauth_timestamp"])
	assert.Equal(t, expectedVersion, params["oauth_version"])
	assert.Equal(t, expectedSignatureMethod, params["oauth_signature_method"])
}

// example from https://dev.twitter.com/oauth/overview/authorizing-requests,
// https://dev.twitter.com/oauth/overview/creating-signatures, and
// https://dev.twitter.com/oauth/application-only
var unixTimestampOfRequest int64 = 1318622958
var expectedTwitterConsumerKey = "xvz1evFS4wEEPTGEFPHBog"
var expectedTwitterOAuthToken = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"
var expectedNonce = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"
var twitterConfig = &Config{
	ConsumerKey:    expectedTwitterConsumerKey,
	ConsumerSecret: "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
	Endpoint: Endpoint{
		RequestTokenURL: "https://api.twitter.com/oauth/request_token",
		AuthorizeURL:    "https://api.twitter.com/oauth/authorize",
		AccessTokenURL:  "https://api.twitter.com/oauth/access_token",
	},
}

func TestTwitterParameterString(t *testing.T) {
	values := url.Values{}
	values.Add("status", "Hello Ladies + Gentlemen, a signed OAuth request!")
	// note: the reference example is old and uses api v1 in the URL
	req, err := http.NewRequest("post", "https://api.twitter.com/1/statuses/update.json?include_entities=true", strings.NewReader(values.Encode()))
	assert.Nil(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	params, err := prepareParams(req, twitterConfig.ConsumerKey)
	assert.Nil(t, err)
	params.Add("oauth_nonce", expectedNonce)
	params.Add("oauth_timestamp", strconv.FormatInt(unixTimestampOfRequest, 10))
	params.Add("oauth_token", expectedTwitterOAuthToken)
	// assert that the parameter string matches the reference
	expectedParameterString := "include_entities=true&oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0&status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21"
	assert.Equal(t, expectedParameterString, normalizeSpace(params.Encode()))
}

func TestTwitterSignatureBase(t *testing.T) {
	values := url.Values{}
	values.Add("status", "Hello Ladies + Gentlemen, a signed OAuth request!")
	// note: the reference example is old and uses api v1 in the URL
	req, err := http.NewRequest("post", "https://api.twitter.com/1/statuses/update.json?include_entities=true", strings.NewReader(values.Encode()))
	assert.Nil(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	params, err := prepareParams(req, twitterConfig.ConsumerKey)
	assert.Nil(t, err)
	params.Add("oauth_token", expectedTwitterOAuthToken)
	signer := Signer{expectedNonce, time.Unix(unixTimestampOfRequest, 0)}
	signatureBase := signer.Base(req, params)
	// assert that the signature base string matches the reference
	// checks that method is uppercased, url is encoded, parameter string is added, all joined by &
	expectedSignatureBase := "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"
	assert.Nil(t, err)
	assert.Equal(t, expectedSignatureBase, signatureBase)
}

func TestTwitterRequestAuthHeader(t *testing.T) {
	oauthTokenSecret := "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"
	expectedSignature := url.QueryEscape("tnnArxj06cWHq44gCs1OSKk/jLY=")
	expectedTimestamp := "1318622958"

	values := url.Values{}
	values.Add("status", "Hello Ladies + Gentlemen, a signed OAuth request!")

	req, err := http.NewRequest("post", "https://api.twitter.com/1/statuses/update.json?include_entities=true", strings.NewReader(values.Encode()))
	assert.Nil(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	data, err := prepareParams(req, twitterConfig.ConsumerKey)
	assert.Nil(t, err)
	data.Add("oauth_token", expectedTwitterOAuthToken)
	signer := Signer{expectedNonce, time.Unix(unixTimestampOfRequest, 0)}
	signature, err := signer.Sign(twitterConfig.ConsumerSecret, oauthTokenSecret, req, data)
	assert.Nil(t, err)
	data.Add("oauth_signature", signature)
	req.Header.Set("Authorization", formatOAuthHeader(data))
	// assert that request is signed and has an access token token
	assert.Nil(t, err)
	params := parseOAuthParamsOrFail(t, req.Header.Get("Authorization"))
	assert.Equal(t, expectedTwitterOAuthToken, params["oauth_token"])
	assert.Equal(t, expectedSignature, params["oauth_signature"])
	// additional OAuth parameters
	assert.Equal(t, expectedTwitterConsumerKey, params["oauth_consumer_key"])
	assert.Equal(t, expectedNonce, params["oauth_nonce"])
	assert.Equal(t, expectedSignatureMethod, params["oauth_signature_method"])
	assert.Equal(t, expectedTimestamp, params["oauth_timestamp"])
	assert.Equal(t, expectedVersion, params["oauth_version"])
}
