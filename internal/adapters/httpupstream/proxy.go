// Package httpupstream forwards gateway requests to one upstream service.
package httpupstream

import (
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// NewProxy forwards every request to target through transport.
// The proxy does not retry: a lost response to a write stays an unknown outcome.
func NewProxy(target *url.URL, transport http.RoundTripper) (*httputil.ReverseProxy, error) {
	if target == nil || transport == nil {
		return nil, errors.New("upstream proxy requires target and transport")
	}
	if (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" ||
		target.User != nil || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" {
		return nil, errors.New("upstream target must be http(s) URL with host and without credentials, query or fragment")
	}
	return &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(target)
			request.SetXForwarded()
		},
		Transport: transport,
	}, nil
}
