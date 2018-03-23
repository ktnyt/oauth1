package internal

import (
	"net/http"

	"golang.org/x/net/context"
)

// HTTPClient is the context key to use with context's WithValue function
// to associate an *http.Client value with a context.
var HTTPClient ContextKey

// ContextKey is just an empty struct. It exists so HTTPClient can be
// an immutable public variable with a unique type. It's immutable
// because nobody else can create a ContextKey, being unexported.
type ContextKey struct{}

var appengineClientHook func(context.Context) *http.Client

// ContextClient returns a proper *http.Client depending on the context
// and runtime environment.
func ContextClient(ctx context.Context) *http.Client {
	if ctx != nil {
		if hc, ok := ctx.Value(HTTPClient).(*http.Client); ok {
			return hc
		}
	}
	if appengineClientHook != nil {
		return appengineClientHook(ctx)
	}
	return http.DefaultClient
}
