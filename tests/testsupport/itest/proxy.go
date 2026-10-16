// Source: umir-factory reference/durable/itest@26166c8ba197 (adapted: repository name gateway, no PostgreSQL and no cache Redis helpers)

package itest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Direction names one half of a proxied connection.
type Direction int

const (
	// ToServer is the stream from the client to the proxied server.
	ToServer Direction = iota
	// ToClient is the stream from the proxied server to the client.
	ToClient
)

const (
	proxyDialTimeout = 5 * time.Second
	proxyBufferSize  = 32 * 1024
)

// TCPProxy is a fault-injecting TCP proxy on 127.0.0.1. Tests point a client
// at Addr and arm one-shot faults: cut every connection after N client bytes or
// right after a byte pattern, pause the transfer, or swallow the replies. A
// fault fires once; connections made after it work normally again.
//
// The proxy owns every goroutine it starts. Close stops them and waits; it is
// registered with t.Cleanup by NewTCPProxy.
type TCPProxy struct {
	ln     net.Listener
	target string
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once

	mu            sync.Mutex
	pipes         map[*pipe]struct{}
	cutBytesArmed bool
	cutBytes      int64
	match         matchTrigger
	matchGen      uint64
	resume        chan struct{} // non-nil while paused; closed by Resume
	dropToClient  bool
}

type matchTrigger struct {
	armed   bool
	dir     Direction
	pattern []byte
}

// pipe is one proxied connection. tails and gens belong to the pumps and are
// guarded by TCPProxy.mu.
type pipe struct {
	client, server net.Conn
	severed        atomic.Bool
	done           chan struct{}
	once           sync.Once
	tails          [2][]byte
	gens           [2]uint64
}

func (pp *pipe) close() {
	pp.once.Do(func() {
		close(pp.done)
		ignoreErr(pp.client.Close())
		ignoreErr(pp.server.Close())
	})
}

// NewTCPProxy starts a proxy to target (host:port) on 127.0.0.1:0.
func NewTCPProxy(tb testing.TB, target string) *TCPProxy {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("start TCP proxy: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &TCPProxy{ln: ln, target: target, ctx: ctx, cancel: cancel, pipes: map[*pipe]struct{}{}}
	p.wg.Go(p.acceptLoop)
	tb.Cleanup(p.Close)
	return p
}

// Addr returns the address clients connect to, as host:port.
func (p *TCPProxy) Addr() string { return p.ln.Addr().String() }

// CutAfterBytes arms a one-shot fault: after n more bytes have passed from
// clients to the server (counted over all connections from this call on), the
// proxy forwards exactly those n bytes and cuts every open connection. With
// n <= 0 it cuts the open connections immediately.
func (p *TCPProxy) CutAfterBytes(n int64) {
	if n <= 0 {
		p.mu.Lock()
		pipes := p.severAllLocked()
		p.mu.Unlock()
		closeAll(pipes)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cutBytesArmed = true
	p.cutBytes = n
}

// CutAfterMatch arms a one-shot fault: as soon as pattern appears in the stream
// of the given direction (also when split over several reads), the proxy
// forwards the stream up to and including the pattern and cuts every open
// connection. Nothing that follows the pattern, and nothing from the other
// direction after that moment, is delivered.
func (p *TCPProxy) CutAfterMatch(dir Direction, pattern []byte) {
	if len(pattern) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.matchGen++
	p.match = matchTrigger{armed: true, dir: dir, pattern: bytes.Clone(pattern)}
}

// Pause holds back all data in both directions until Resume. Connections stay
// open and nothing is lost.
func (p *TCPProxy) Pause() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.resume == nil {
		p.resume = make(chan struct{})
	}
}

// Resume releases the data held back by Pause.
func (p *TCPProxy) Resume() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.resume != nil {
		close(p.resume)
		p.resume = nil
	}
}

// DropToClient makes the proxy swallow everything the server sends while on,
// for example publisher confirms or acknowledgements. Requests still reach the
// server.
func (p *TCPProxy) DropToClient(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dropToClient = on
}

// Close stops the listener, cuts all connections and waits for every goroutine
// of the proxy. It is safe to call more than once.
func (p *TCPProxy) Close() {
	p.once.Do(func() {
		p.cancel()
		ignoreErr(p.ln.Close())
		p.mu.Lock()
		pipes := make([]*pipe, 0, len(p.pipes))
		for pp := range p.pipes {
			pipes = append(pipes, pp)
		}
		p.mu.Unlock()
		closeAll(pipes)
		p.wg.Wait()
	})
}

func (p *TCPProxy) acceptLoop() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return // listener closed by Close
		}
		p.wg.Go(func() { p.handle(c) })
	}
}

func (p *TCPProxy) handle(client net.Conn) {
	dialer := net.Dialer{Timeout: proxyDialTimeout}
	server, err := dialer.DialContext(p.ctx, "tcp", p.target)
	if err != nil {
		ignoreErr(client.Close())
		return
	}
	pp := &pipe{client: client, server: server, done: make(chan struct{})}
	p.mu.Lock()
	if p.ctx.Err() != nil {
		p.mu.Unlock()
		pp.close()
		return
	}
	p.pipes[pp] = struct{}{}
	p.mu.Unlock()

	var pumps sync.WaitGroup
	pumps.Go(func() { p.pump(pp, client, server, ToServer) })
	pumps.Go(func() { p.pump(pp, server, client, ToClient) })
	pumps.Wait()
	pp.close()
	p.mu.Lock()
	delete(p.pipes, pp)
	p.mu.Unlock()
}

func (p *TCPProxy) pump(pp *pipe, src, dst net.Conn, dir Direction) {
	buf := make([]byte, proxyBufferSize)
	for {
		n, err := src.Read(buf)
		if n > 0 && !p.forward(pp, dst, dir, buf[:n]) {
			return
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if tc, ok := dst.(*net.TCPConn); ok {
					ignoreErr(tc.CloseWrite())
				}
				return
			}
			pp.close()
			return
		}
	}
}

// waitResume blocks while the proxy is paused. It reports false when the
// connection or the proxy is closed meanwhile.
func (p *TCPProxy) waitResume(pp *pipe) bool {
	for {
		p.mu.Lock()
		ch := p.resume
		p.mu.Unlock()
		if ch == nil {
			return true
		}
		select {
		case <-ch:
		case <-pp.done:
			return false
		case <-p.ctx.Done():
			return false
		}
	}
}

// forward passes one chunk on, applying the armed faults. It reports whether the
// pump should keep going.
func (p *TCPProxy) forward(pp *pipe, dst net.Conn, dir Direction, data []byte) bool {
	if !p.waitResume(pp) || pp.severed.Load() {
		return false
	}
	p.mu.Lock()
	if dir == ToClient && p.dropToClient {
		p.mu.Unlock()
		return true
	}
	cutAt, byBytes, byMatch := -1, false, false
	if dir == ToServer && p.cutBytesArmed && int64(len(data)) >= p.cutBytes {
		cutAt, byBytes = int(p.cutBytes), true
	}
	if p.match.armed && p.match.dir == dir {
		if end := p.matchEndLocked(pp, dir, data); end >= 0 && (cutAt < 0 || end < cutAt) {
			cutAt, byBytes, byMatch = end, false, true
		}
	}
	if cutAt < 0 {
		if dir == ToServer && p.cutBytesArmed {
			p.cutBytes -= int64(len(data))
		}
		p.mu.Unlock()
		return p.write(pp, dst, data)
	}
	if byBytes {
		p.cutBytesArmed = false
	}
	if byMatch {
		p.match.armed = false
		if dir == ToServer && p.cutBytesArmed {
			p.cutBytes -= int64(cutAt)
		}
	}
	pipes := p.severAllLocked()
	p.mu.Unlock()
	// The final bytes go out before the connections are closed; the other
	// direction is already severed, so no reply can overtake the cut.
	if cutAt > 0 {
		_, err := dst.Write(data[:cutAt])
		ignoreErr(err)
	}
	closeAll(pipes)
	return false
}

func (p *TCPProxy) write(pp *pipe, dst net.Conn, data []byte) bool {
	if _, err := dst.Write(data); err != nil {
		pp.close()
		return false
	}
	return true
}

// matchEndLocked returns the offset in data just past the armed pattern, or -1.
// It keeps the last len(pattern)-1 bytes so that a pattern split over reads is
// found. The caller holds p.mu.
func (p *TCPProxy) matchEndLocked(pp *pipe, dir Direction, data []byte) int {
	if pp.gens[dir] != p.matchGen {
		pp.gens[dir] = p.matchGen
		pp.tails[dir] = nil
	}
	pattern := p.match.pattern
	tail := pp.tails[dir]
	joined := make([]byte, 0, len(tail)+len(data))
	joined = append(joined, tail...)
	joined = append(joined, data...)
	if idx := bytes.Index(joined, pattern); idx >= 0 {
		return idx + len(pattern) - len(tail)
	}
	keep := min(len(pattern)-1, len(joined))
	pp.tails[dir] = bytes.Clone(joined[len(joined)-keep:])
	return -1
}

// severAllLocked marks every open connection as cut and returns them. The
// caller holds p.mu and closes the returned pipes after unlocking.
func (p *TCPProxy) severAllLocked() []*pipe {
	pipes := make([]*pipe, 0, len(p.pipes))
	for pp := range p.pipes {
		pp.severed.Store(true)
		pipes = append(pipes, pp)
	}
	return pipes
}

func closeAll(pipes []*pipe) {
	for _, pp := range pipes {
		pp.close()
	}
}
