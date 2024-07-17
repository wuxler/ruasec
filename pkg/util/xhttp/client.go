package xhttp

import "net/http"

// Client is the interface of a http client.
type Client interface {
	Do(*http.Request) (*http.Response, error)
}
