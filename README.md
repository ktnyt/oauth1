![CircleCI](https://circleci.com/gh/ktnyt/oauth1.svg?style=shield&circle-token=a718fab78379159949983c4c681066406c6aafc3)
[![Go Report Card](https://goreportcard.com/badge/github.com/ktnyt/oauth1)](https://goreportcard.com/report/github.com/ktnyt/oauth1)

# oauth1
OAauth1 is a Go implementation of the [OAuth 1 spec](https://tools.ietf.org/html/rfc5849).

The design of the library interface is almost entirely based on https:/github.com/dghubble/oauth1.
About my rationale on why I created this codebase is written below.

## Install
```
$ go get github.com/dghubble/oauth1
```

## Docs
A basic usage example is available below. For in-depth documentation consult the [GoDoc](https://godoc.org/github.com/ktnyt/oauth1).

## Usage
This package provides two core functionalities: authorization using the OAuth1 protocol and sending HTTP requests using the authorization data.

### Authorization Flow
The OAuth1 authorization flow consists of three steps:
1. Request temporary credentials to handle authorization.
2. Direct the user to the authorization URL.
3. Request access tokens using given credentials.

Below are the steps required to obtain the access tokens for a Twitter user.

#### Configuration
Populate the `oauth1.Config` object with necessary details, which are the *Consumer Key*, *Consumer Secret*, *Callback URL*, and *Endpoint*.

An `Endpoint` is a set of predefined URLs required to perform the three step OAuth1 authorization process. Some `Endpoint`s for popular web services are provided in a sub-package.

```go
import (
	"github.com/ktnyt/oauth1"
	"github.com/ktnyt/oauth1/twitter"
)
...


config = oauth1.Config{
	ConsumerKey:    consumerKey,
	ConsumerSecret: consumerSecret,
	CallbackURL:    "https://example.com/oauth/twitter/callback",
	Endpoint:       twitter.AuthorizeEndpoint,
}
```

#### 1. Getting the temporary credentials
When the user, say, clicks on a 'Login with XXX' button, the first step to authorization is to issue a pair of temporary credentials to authorize the authorization process itself these credentials may be referred to as *request token*s.

```go
requestToken, requestSecret, err := config.RequestToken()
// handle error
```

Before issuing the redirect URL, do not forget that these credentials will be required in the later steps of the authorization flow.
Make sure that these values will be accessible after the user has been Redirected.
A common method will be to use HTTP Cookies to store the values on the client's browser.

#### 2. Redirect the user to the authorization page
Construct the authorization URL using the credentials obtained from above.
How to point the user to the given URL is up to the implementation (e.g. server redirect, client redirect, etc.).

```go
authorizationURL, err := config.AuthorizationURL(requestToken)
// handle error
// redirection using redirect HTTP response
http.Redirect(w, r, authorizationURL.String(), http.StatusSeeOther)
```

#### 3. Getting the access token pair
Once the user authorizes the application's access to their account, the client will be redirected to the provided callback URL.
Some URL query parameters will be provided in the callback, which is needed to acquire the access token pair.

```go
requestToken, verifier, err := oauth1.ParseAuthorizationCallback(req)
// handle error
```

Using these values, the access token pair can finally be obtained.

```go
accessToken, accessSecret, err := config.AccessToken(requestToken, requestSecret, verifier)
```

These credentials can then be used to call APIs on the user's behalf.

### Authorized Requests
Use the access token pair to create a `*http.Client` instance to automatically sign your requests.

```go
import (
	"github.com/ktnyt/oauth1"
)

func main() {
	config := oauth1.NewConfig("consumerKey", "consumerSecret")
	accessToken = "accessToken"
	accessSecret = "accessSecret"

	// httpClient will automatically authorize http.Request's
	httpClient := config.Client(oauth1.NoContext, accessToken, accessSecret)

	// example Twitter API request
	path := "https://api.twitter.com/1.1/statuses/home_timeline.json?count=2"
	resp, _ := httpClient.Get(path)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("Raw Response Body:\n%v\n", string(body))
}
```

If you want to call APIs to specific services, [dghubble](https://github.com/dghubble) has a handful of very useful wrappers which are interoperable.
Pass the `*http.Client` to the wrappers and you should be able to call the APIs.

## Why Another Library so Similar?
TL;DR: Google App Engine

I must admit that dghubble's codebase is spectacular, and everybody should use his library if it weren't for Google App Engine (GAE).
I've started to use GAE for a personal project and stumbled across a problem where the `http.DefaultClient` cannot be used.
The [OAuth2](https://github.com/golang/oauth2) circumvents this issue by providing the `urlfetch.Client` from "google.golang.org/appengine/urlfetch" when the `appengine` build tag is present.
That is pretty much all it takes to patch this problem: but unfortunately the codebase has not been touched on for 10 months (at the time of writing Mar. 23, 2018).
This is why I thought it might be a good opportunity to dive in to the code and write a client for myself.
I do intend to maintain the codebase as much as possible, but if dghubble's codebase becomes active again I would point the users there instead.
That said, I tried to implement the OAuth1 authorization flow reusing the Go standard library functionalities as much as possible.
As a result, the coding of the internal logic is somewhat cluttered and while I am eager to do extensive housekeeping suggestions on the implementation are more than welcome.

## License
[MIT License](https://github.com/ktnyt/oauth1/blob/master/LICENSE)

## Acknowledgements
- [dghubble](https://github.com/dghubble)
