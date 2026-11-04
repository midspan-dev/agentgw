package proxy_test

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/proxy"
)

// startOn runs the proxy on bindHost and returns its loopback host:port.
func startOn(t *testing.T, bindHost, upURL string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	listen := fmt.Sprintf("%s:%d", bindHost, port)
	go proxy.HTTP(t.Context(), listen, []proxy.Route{{Name: "up", Path: "/mcp/up", URL: upURL}}, &fn{f: pass})
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for range 100 {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("proxy did not start")
	return ""
}

func TestBrowserGuard(t *testing.T) {
	cases := []struct {
		name, bind, method, host, origin string // host and origin: $ADDR, $PORT expand; host "" keeps the dial address
		want                             int
	}{
		{"mcp client, no origin", "127.0.0.1", "POST", "", "", 200},
		{"localhost host", "127.0.0.1", "POST", "localhost:$PORT", "", 200},
		{"same origin", "127.0.0.1", "POST", "", "http://$ADDR", 200},
		{"rebound host", "127.0.0.1", "POST", "evil.example:$PORT", "", 403},
		{"rebound host and matching origin", "127.0.0.1", "POST", "evil.example:$PORT", "http://evil.example:$PORT", 403},
		{"rebound host opening a stream", "127.0.0.1", "GET", "evil.example:$PORT", "", 403},
		{"foreign origin", "127.0.0.1", "POST", "", "https://evil.example", 403},
		{"foreign origin opening a stream", "127.0.0.1", "GET", "", "https://evil.example", 403},
		{"sandboxed page", "127.0.0.1", "POST", "", "null", 403},
		{"other local port", "127.0.0.1", "POST", "", "http://127.0.0.1:1", 403},
		{"public listener, named host", "0.0.0.0", "POST", "gw.example:$PORT", "", 200},
		{"public listener, same origin", "0.0.0.0", "POST", "gw.example:$PORT", "https://gw.example:$PORT", 200},
		{"public listener, foreign origin", "0.0.0.0", "POST", "gw.example:$PORT", "https://evil.example", 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			up := newRecordingUpstream(t)
			addr := startOn(t, c.bind, up.URL)
			_, port, _ := net.SplitHostPort(addr)
			expand := strings.NewReplacer("$ADDR", addr, "$PORT", port).Replace

			body := strings.NewReader("")
			if c.method == "POST" {
				body = strings.NewReader(listBody)
			}
			req, err := http.NewRequestWithContext(t.Context(), c.method, "http://"+addr+"/mcp/up", body)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = expand(c.host)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
			req.Header.Set("Mcp-Method", "tools/list")
			if c.origin != "" {
				req.Header.Set("Origin", expand(c.origin))
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != c.want {
				t.Errorf("status %d, want %d", resp.StatusCode, c.want)
			}
			if forwarded := len(up.seen()) > 0; forwarded != (c.want == 200) {
				t.Errorf("forwarded upstream = %v with status %d", forwarded, resp.StatusCode)
			}
		})
	}
}
