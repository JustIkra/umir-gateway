package httpupstream

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JustIkra/umir-gateway/internal/httpapi"
)

type ScopedTarget struct {
	URL        *url.URL
	ServiceKey string
}
type ScopedClient struct {
	targets   map[string]ScopedTarget
	transport http.RoundTripper
	timeout   time.Duration
}

func NewScopedClient(targets map[string]ScopedTarget, transport http.RoundTripper, timeout time.Duration) (*ScopedClient, error) {
	if transport == nil || timeout <= 0 {
		return nil, errors.New("scoped upstream requires transport and positive timeout")
	}
	c := &ScopedClient{targets: map[string]ScopedTarget{}, transport: transport, timeout: timeout}
	for _, service := range []string{"warehouse", "serving", "feedback"} {
		target := targets[service]
		if target.URL == nil || target.URL.Host == "" || target.URL.User != nil || target.URL.RawQuery != "" || target.URL.ForceQuery || target.URL.Fragment != "" || (target.URL.Path != "" && target.URL.Path != "/") || (target.URL.Scheme != "http" && target.URL.Scheme != "https") || target.ServiceKey == "" || strings.ContainsAny(target.ServiceKey, " \t\r\n") {
			return nil, errors.New("scoped upstream requires an origin and distinct private credentials")
		}
		u := *target.URL
		target.URL = &u
		c.targets[service] = target
	}
	return c, nil
}

func (c *ScopedClient) Do(ctx context.Context, input httpapi.BusinessRequest) (httpapi.BusinessResponse, error) {
	target, ok := c.targets[input.Service]
	if !ok || !strings.HasPrefix(input.Path, "/internal/"+input.Service+"/v2/") {
		return httpapi.BusinessResponse{}, errors.New("unknown scoped target")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	u := *target.URL
	u.Path, u.RawPath, u.RawQuery = input.Path, "", input.RawQuery
	r, err := http.NewRequestWithContext(ctx, input.Method, u.String(), bytes.NewReader(input.Body))
	if err != nil {
		return httpapi.BusinessResponse{}, err
	}
	r.Header = input.Header.Clone()
	r.Header.Set("X-Umir-Service-Key", target.ServiceKey)
	r.GetBody = nil
	response, err := c.transport.RoundTrip(r)
	if err != nil {
		return httpapi.BusinessResponse{}, httpapi.Classed(httpapi.ClassTransport, err)
	}
	if response == nil || response.Body == nil {
		return httpapi.BusinessResponse{}, errors.New("missing scoped response")
	}
	result := httpapi.BusinessResponse{Status: response.StatusCode, Header: response.Header.Clone()}
	limit := int64(8 << 20)
	if input.MaxBytes > 0 {
		limit = min(limit, input.MaxBytes)
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	closeErr := response.Body.Close()
	if int64(len(data)) > limit && input.MaxBytes > 0 && limit == input.MaxBytes {
		return result, errors.Join(closeErr, httpapi.ErrResponseTooLarge)
	}
	if readErr != nil || closeErr != nil || int64(len(data)) > limit {
		return result, errors.Join(readErr, closeErr, errors.New("scoped response unavailable"))
	}
	result.Body = data
	return result, nil
}
