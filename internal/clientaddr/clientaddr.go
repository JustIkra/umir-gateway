// Package clientaddr resolves the address of the browser behind the trusted proxies of a request.
package clientaddr

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Unknown is the key of a request whose peer address cannot be read.
const Unknown = "unknown"

// Resolver finds the client of a request. A peer outside Trusted is the client itself and its
// forwarding headers are ignored; behind a trusted peer the client is the first address of
// X-Forwarded-For, read right to left, that is not trusted. The zero value trusts nobody.
type Resolver struct {
	Trusted []netip.Prefix
}

// Client returns a normalized key of the client: an IPv4 address as is, an IPv6 address as its /64
// network. An unreadable peer is Unknown; an empty or unreadable header, or one made only of trusted
// hops, yields the peer.
func (r Resolver) Client(req *http.Request) string {
	peer, ok := parsePeer(req.RemoteAddr)
	if !ok {
		return Unknown
	}
	if !r.trusts(peer) {
		return key(peer)
	}
	entries := strings.Split(strings.Join(req.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(entries) - 1; i >= 0; i-- {
		hop, ok := parseHop(strings.TrimSpace(entries[i]))
		if !ok {
			return key(peer)
		}
		if !r.trusts(hop) {
			return key(hop)
		}
	}
	return key(peer)
}

func (r Resolver) trusts(addr netip.Addr) bool {
	for _, prefix := range r.Trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func parsePeer(remote string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	return parseHop(host)
}

// parseHop reads an address with an optional port, as proxies write them.
func parseHop(raw string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(raw); err == nil {
		return addr.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(raw); err == nil {
		return ap.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

func key(addr netip.Addr) string {
	addr = addr.WithZone("")
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().String()
	}
	return addr.String()
}
