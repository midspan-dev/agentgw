package proxy

import (
	"bufio"
	"bytes"
	"context"
	stdjson "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

// noRedirect makes a 3xx an upstream error: forwarded calls carry credentials and must stay on Route.URL.
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// Route maps a path prefix on the gateway to one upstream Streamable HTTP
// endpoint. Name becomes Call.Server.
type Route struct{ Name, Path, URL string }

// HTTP serves the routes on listen until ctx is done. The server is
// stateless (no Mcp-Session-Id), matching the 2026-07-28 protocol.
func HTTP(ctx context.Context, listen string, routes []Route, i contracts.Interceptor) error {
	mux := http.NewServeMux()
	for _, r := range routes {
		target, err := url.Parse(r.URL)
		if err != nil {
			return fmt.Errorf("proxy: route %s: %w", r.Name, err)
		}
		h := &routeHandler{route: r, i: i, rp: &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) { // exactly Route.URL, whatever path was requested
				u := *target
				pr.Out.URL = &u
				pr.Out.Host = ""
			},
			ModifyResponse: func(r *http.Response) error { // a 3xx is an upstream error, never relayed or followed
				if r.StatusCode >= 300 && r.StatusCode < 400 {
					return fmt.Errorf("upstream redirect (%d) refused", r.StatusCode)
				}
				return nil
			},
			FlushInterval: -1, // SSE
		}}
		p := strings.TrimSuffix(r.Path, "/")
		if p == "" {
			mux.Handle("/", h)
			continue
		}
		mux.Handle(p, h)
		mux.Handle(p+"/", h)
	}
	srv := &http.Server{Addr: listen, Handler: mux}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if srv.Shutdown(sctx) != nil {
			srv.Close()
		}
		return nil
	}
}

type routeHandler struct {
	route Route
	i     contracts.Interceptor
	rp    *httputil.ReverseProxy
	next  atomic.Int64 // proxy-owned request ids
}

// reject answers a malformed request; nothing is forwarded.
func reject(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	w.Write(rpcError(nil, -32600, text))
}

func (h *routeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		if r.Method != http.MethodGet && r.Method != http.MethodDelete {
			w.Header().Set("Allow", "GET, DELETE, POST")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body, r.ContentLength = http.NoBody, 0 // client bytes never go upstream
		h.rp.ServeHTTP(w, r)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<20)) // shortcut: fixed 32 MiB request cap, upgrade if a deployment needs more
	if err != nil {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	// Exactly one JSON-RPC object: batches, duplicate or differently-cased keys never reach upstream.
	m, err := parse(body, true)
	if err != nil {
		reject(w, "invalid request: "+err.Error())
		return
	}
	// The client's routing headers must describe the message we forward, not another one.
	if r.Header.Get("Mcp-Method") != "" {
		r.Header.Set("Mcp-Method", m.Method)
	}

	if !m.isToolsCall() {
		out, err := json.Marshal(m) // re-serialized from the parse
		if err != nil {
			reject(w, err.Error())
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(out))
		r.ContentLength = int64(len(out))
		r.Header.Set("Content-Length", strconv.Itoa(len(out)))
		h.rp.ServeHTTP(w, r)
		return
	}

	// The response is plain JSON unless a notification precedes it, then SSE.
	var mu sync.Mutex
	streaming := false
	event := func(b []byte) { // caller holds mu
		if !streaming {
			streaming = true
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)
		}
		fmt.Fprintf(w, "data: %s\n\n", b)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	notify := func(b []byte) { mu.Lock(); defer mu.Unlock(); event(b) }

	send := func(ctx context.Context, tool string, params jsontext.Value) (stdjson.RawMessage, error) {
		pid := h.next.Add(1)
		pidv := jsontext.Value(strconv.FormatInt(pid, 10))
		notSent := func(err error) error { return fmt.Errorf("%w: %w", contracts.ErrNotSent, err) }
		out, err := json.Marshal(&msg{JSONRPC: "2.0", ID: pidv, Method: "tools/call", Params: params})
		if err != nil {
			return nil, notSent(err)
		}
		if err := ctx.Err(); err != nil {
			return nil, notSent(err)
		}
		// "The write began" is acquiring a connection (GotConn): a failure before it is a
		// dial, DNS or TLS failure or ctx done while connecting, so nothing was written.
		var gotConn atomic.Bool
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { gotConn.Store(true) }})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.route.URL, bytes.NewReader(out))
		if err != nil {
			return nil, notSent(err)
		}
		req.Header = r.Header.Clone()
		req.Header.Del("Content-Length")
		req.Header.Del("Accept-Encoding") // let the transport negotiate and decode gzip itself
		req.Header.Set("Mcp-Method", "tools/call")
		req.Header.Set("Mcp-Name", tool)
		resp, err := noRedirect.Do(req)
		if err != nil {
			if !gotConn.Load() {
				return nil, notSent(err)
			}
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 && resp.StatusCode < 400 { // whatever the body says
			return nil, fmt.Errorf("upstream redirect (%d) refused", resp.StatusCode)
		}
		if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
			b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			if err != nil {
				return nil, err
			}
			um, perr := parse(b, false)
			if perr != nil || !um.isResponse() || canon(um.ID) != string(pidv) {
				return nil, fmt.Errorf("upstream HTTP %d: unexpected reply: %.200s", resp.StatusCode, b)
			}
			return um.result()
		}
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(nil, 32<<20)
		var data []string
		for sc.Scan() {
			l := sc.Text()
			if rest, ok := strings.CutPrefix(l, "data:"); ok {
				data = append(data, strings.TrimPrefix(rest, " "))
			}
			if l != "" {
				continue
			}
			b := []byte(strings.Join(data, "\n"))
			data = nil
			um, perr := parse(b, false)
			if perr != nil {
				continue
			}
			if !um.isResponse() {
				notify(relay(um)) // upstream notification or request, re-serialized
			} else if canon(um.ID) == string(pidv) {
				return um.result()
			} // responses to other ids are dropped
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("upstream stream ended without a response")
	}

	resp := intercept(r.Context(), h.i, h.route.Name, m, send, notify)
	if resp == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if streaming {
		event(resp)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}
