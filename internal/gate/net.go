package gate

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	agentctx "github.com/SuperMarioYL/agentgate/internal/context"
	"github.com/SuperMarioYL/agentgate/internal/policy"
)

// NetGate gates network egress per host. It runs a localhost HTTP/HTTPS proxy
// that the wrapped agent's environment points at (HTTP_PROXY/HTTPS_PROXY); each
// CONNECT or request is resolved against the policy by host before it is
// forwarded. This is the libpcap-free egress path: we mediate at the proxy
// boundary rather than capturing raw packets.
type NetGate struct {
	engine *Engine
	agent  string

	mu  sync.Mutex
	ln  net.Listener
	srv *http.Server
}

// NewNetGate builds a network egress gate over an Engine.
func NewNetGate(e *Engine, agent string) *NetGate {
	return &NetGate{engine: e, agent: agent}
}

// CheckHost resolves a net_egress decision for host:port without doing any I/O.
// It is the unit-testable core of the proxy path.
func (g *NetGate) CheckHost(hostport, intent string) (bool, error) {
	req := agentctx.GateRequest{
		Action: agentctx.ActionNetEgress,
		Target: hostport,
		Intent: intent,
		Agent:  g.agent,
	}
	dec, err := g.engine.Decide(req)
	if err != nil {
		return false, err
	}
	return dec == policy.Allow, nil
}

// Listen starts the redirect proxy on a free localhost port and returns the
// address (host:port) the wrapped env should use as HTTP_PROXY.
func (g *NetGate) Listen() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	g.mu.Lock()
	g.ln = ln
	g.srv = &http.Server{Handler: http.HandlerFunc(g.handle)}
	g.mu.Unlock()
	go func() { _ = g.srv.Serve(ln) }()
	return ln.Addr().String(), nil
}

// Close stops the proxy.
func (g *NetGate) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.srv != nil {
		return g.srv.Close()
	}
	return nil
}

func (g *NetGate) handle(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	if r.Method == http.MethodConnect {
		host, _, _ = net.SplitHostPort(r.Host)
		g.handleConnect(w, r, host)
		return
	}
	intent := fmt.Sprintf("agent wants to reach %s via %s", host, r.Method)
	ok, _ := g.CheckHost(r.Host, intent)
	if !ok {
		http.Error(w, "AgentGate: egress to "+host+" denied by policy", http.StatusForbidden)
		return
	}
	g.forward(w, r)
}

func (g *NetGate) handleConnect(w http.ResponseWriter, r *http.Request, host string) {
	intent := fmt.Sprintf("agent wants to open a TLS tunnel to %s", host)
	ok, _ := g.CheckHost(r.Host, intent)
	if !ok {
		http.Error(w, "AgentGate: egress to "+host+" denied by policy", http.StatusForbidden)
		return
	}
	dst, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy does not support hijacking", http.StatusInternalServerError)
		_ = dst.Close()
		return
	}
	src, _, err := hij.Hijack()
	if err != nil {
		_ = dst.Close()
		return
	}
	_, _ = src.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go func() { _, _ = io.Copy(dst, src); _ = dst.Close() }()
	go func() { _, _ = io.Copy(src, dst); _ = src.Close() }()
}

func (g *NetGate) forward(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = ""
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
