// +build appengine

package internal

import "google.golang.org/appengine/urlfetch"

func init() {
	appengineClientHook = urlfetch.Client
}
