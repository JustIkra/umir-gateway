package clientaddr

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var result []netip.Prefix
	for _, cidr := range cidrs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, p)
	}
	return result
}

func request(remote string, forwarded ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = remote
	for _, value := range forwarded {
		r.Header.Add("X-Forwarded-For", value)
	}
	return r
}

func TestClient(t *testing.T) {
	trusted := []string{"10.0.0.0/8", "fd00::/8"}
	for name, tc := range map[string]struct {
		trusted   []string
		remote    string
		forwarded []string
		want      string
	}{
		"no configuration ignores the header":   {nil, "192.0.2.1:1234", []string{"203.0.113.9"}, "192.0.2.1"},
		"untrusted peer ignores the header":     {trusted, "192.0.2.1:1234", []string{"203.0.113.9"}, "192.0.2.1"},
		"trusted peer, single header":           {trusted, "10.1.2.3:80", []string{"203.0.113.9"}, "203.0.113.9"},
		"forged entry left of the real client":  {trusted, "10.1.2.3:80", []string{"198.51.100.7, 203.0.113.9"}, "203.0.113.9"},
		"trusted hop right of the client":       {trusted, "10.1.2.3:80", []string{"203.0.113.9, 10.9.9.9"}, "203.0.113.9"},
		"compound header across lines":          {trusted, "10.1.2.3:80", []string{"198.51.100.7", "203.0.113.9, 10.9.9.9"}, "203.0.113.9"},
		"empty header":                          {trusted, "10.1.2.3:80", []string{""}, "10.1.2.3"},
		"missing header":                        {trusted, "10.1.2.3:80", nil, "10.1.2.3"},
		"unreadable entry":                      {trusted, "10.1.2.3:80", []string{"203.0.113.9, not-an-address"}, "10.1.2.3"},
		"unreadable entry left of the client":   {trusted, "10.1.2.3:80", []string{"garbage, 203.0.113.9"}, "203.0.113.9"},
		"every hop trusted":                     {trusted, "10.1.2.3:80", []string{"10.4.4.4, 10.5.5.5"}, "10.1.2.3"},
		"client with a port":                    {trusted, "10.1.2.3:80", []string{"203.0.113.9:5555"}, "203.0.113.9"},
		"ipv6 peer aggregated by /64":           {nil, "[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:1", nil, "2001:db8:1:2::/64"},
		"ipv6 in another /64":                   {nil, "[2001:db8:1:3::1]:1", nil, "2001:db8:1:3::/64"},
		"ipv6 client behind a trusted proxy":    {trusted, "10.1.2.3:80", []string{"2001:db8:5:6:1:2:3:4"}, "2001:db8:5:6::/64"},
		"ipv6 trusted peer":                     {trusted, "[fd00::1]:80", []string{"2001:db8:5:6:1:2:3:4"}, "2001:db8:5:6::/64"},
		"ipv4-mapped peer is ipv4":              {trusted, "[::ffff:10.1.2.3]:80", []string{"203.0.113.9"}, "203.0.113.9"},
		"unreadable peer address":               {nil, "garbage", nil, "unknown"},
		"empty peer address":                    {trusted, "", []string{"203.0.113.9"}, "unknown"},
		"peer without a port":                   {nil, "192.0.2.1", nil, "192.0.2.1"},
		"forwarded header never read from peer": {nil, "192.0.2.1:1", []string{"10.0.0.1"}, "192.0.2.1"},
	} {
		t.Run(name, func(t *testing.T) {
			resolver := Resolver{Trusted: prefixes(t, tc.trusted...)}
			if got := resolver.Client(request(tc.remote, tc.forwarded...)); got != tc.want {
				t.Fatalf("Client = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestZeroResolverUsesThePeer(t *testing.T) {
	if got := (Resolver{}).Client(request("192.0.2.1:1", "203.0.113.9")); got != "192.0.2.1" {
		t.Fatalf("Client = %q", got)
	}
}
