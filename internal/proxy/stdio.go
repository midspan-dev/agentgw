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
	"os"
	"os/exec"
	"strconv"
	"sync"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

// Stdio spawns cmd as the upstream MCP server named server and serves MCP on
// the process's own stdin/stdout. It returns when the client closes stdin,
// the upstream exits, or ctx is done.
func Stdio(ctx context.Context, server string, cmd []string, i contracts.Interceptor) error {
	return stdio(ctx, server, cmd, os.Stdin, os.Stdout, i)
}

// maxLine bounds one client line.
const maxLine = 32 << 20

// entry is one request forwarded upstream under a proxy-owned id.
type entry struct {
	key string         // the client's id, as sent
	id  jsontext.Value // the client's id, echoed back in the response
	ch  chan *msg      // tools/call waiter (buffered 1); nil for passthrough requests
}

func stdio(ctx context.Context, server string, cmd []string, in io.Reader, out io.Writer, i contracts.Interceptor) error {
	if len(cmd) == 0 {
		return errors.New("proxy: empty upstream command")
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c := exec.CommandContext(cctx, cmd[0], cmd[1:]...)
	c.Stderr = os.Stderr
	up, err := c.StdinPipe()
	if err != nil {
		return err
	}
	upOut, err := c.StdoutPipe()
	if err != nil {
		return err
	}
	if err := c.Start(); err != nil {
		return err
	}

	// Lines must not interleave on either sink.
	var outMu, upMu sync.Mutex
	line := func(mu *sync.Mutex, w io.Writer, b []byte) error {
		mu.Lock()
		defer mu.Unlock()
		n, err := w.Write(append(bytes.TrimRight(b, "\n"), '\n'))
		if err != nil && n == 0 { // not one byte left the gateway
			return fmt.Errorf("%w: %w", contracts.ErrNotSent, err)
		}
		return err
	}
	toClient := func(b []byte) { line(&outMu, out, b) }
	toUp := func(m *msg) error {
		m.JSONRPC = "2.0"
		b, err := json.Marshal(m)
		if err != nil {
			return fmt.Errorf("%w: %w", contracts.ErrNotSent, err)
		}
		return line(&upMu, up, b)
	}

	var mu sync.Mutex
	var next int64
	pending := map[int64]*entry{}  // proxy id -> waiter
	byClient := map[string]int64{} // client id -> proxy id, for every in-flight client request
	cancels := map[string]func(){} // client id -> cancel of an in-flight tools/call
	upDone := make(chan struct{})

	// claim reserves a proxy-owned id for a client request, refusing a client id already in flight.
	claim := func(m *msg, ch chan *msg) (int64, bool) {
		mu.Lock()
		defer mu.Unlock()
		key := canon(m.ID)
		if _, dup := byClient[key]; dup {
			return 0, false
		}
		next++
		pending[next], byClient[key] = &entry{key: key, id: m.ID, ch: ch}, next
		return next, true
	}
	release := func(pid int64) {
		mu.Lock()
		defer mu.Unlock()
		if e := pending[pid]; e != nil {
			delete(byClient, e.key)
		}
		delete(pending, pid)
	}

	go func() { // upstream -> client
		defer close(upDone)
		r := bufio.NewReader(upOut)
		for {
			b, err := r.ReadBytes('\n')
			if len(bytes.TrimSpace(b)) > 0 {
				if m, perr := parse(bytes.TrimSpace(b), false); perr == nil {
					if !m.isResponse() {
						toClient(relay(m)) // upstream-originated request or notification, re-serialized
					} else if pid, perr := strconv.ParseInt(canon(m.ID), 10, 64); perr == nil {
						mu.Lock()
						e := pending[pid]
						delete(pending, pid) // a second response for this id finds nothing and is dropped
						if e != nil && e.ch == nil {
							delete(byClient, e.key)
						}
						mu.Unlock()
						if e != nil && e.ch != nil {
							e.ch <- m // buffered 1, and only the first response gets here
						} else if e != nil {
							m.ID = e.id
							m.JSONRPC = "2.0"
							if rb, merr := json.Marshal(m); merr == nil {
								toClient(rb)
							}
						}
					}
				} // anything else from upstream is dropped, never relayed
			}
			if err != nil {
				return
			}
		}
	}()

	// startCall claims the id and registers the cancel func before returning, so a
	// cancellation read right after the request always finds it.
	startCall := func(m *msg) {
		ch := make(chan *msg, 1)
		pid, ok := claim(m, ch)
		if !ok {
			toClient(rpcError(m.ID, -32600, "request id already in flight"))
			return
		}
		key := canon(m.ID)
		callCtx, stop := context.WithCancel(cctx)
		mu.Lock()
		cancels[key] = stop
		mu.Unlock()
		go func() {
			defer func() {
				mu.Lock()
				delete(cancels, key)
				mu.Unlock()
				release(pid)
				stop()
			}()
			send := func(ctx context.Context, _ string, params jsontext.Value) (stdjson.RawMessage, error) {
				// "The write began" is the first Write to the upstream's stdin: ctx done before it,
				// or a Write that wrote nothing, is provably not sent. After it, any error may mean the tool ran.
				if err := ctx.Err(); err != nil {
					return nil, fmt.Errorf("%w: %w", contracts.ErrNotSent, err)
				}
				if err := toUp(&msg{ID: jsontext.Value(strconv.FormatInt(pid, 10)), Method: "tools/call", Params: params}); err != nil {
					return nil, err
				}
				select {
				case r := <-ch:
					return r.result()
				case <-upDone:
					return nil, errors.New("proxy: upstream closed")
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			if resp := intercept(callCtx, i, server, m, send, toClient); resp != nil {
				toClient(resp)
			}
		}()
	}

	handle := func(b []byte) {
		// One object per line: a bare \r is a separator to some decoders, so it is never accepted.
		if bytes.ContainsRune(b, '\r') {
			toClient(rpcError(nil, -32600, "invalid request: carriage return"))
			return
		}
		m, err := parse(b, true)
		if err != nil {
			toClient(rpcError(nil, -32600, "invalid request: "+err.Error()))
			return
		}
		switch {
		case m.isToolsCall():
			startCall(m)
		case m.isRequest():
			pid, ok := claim(m, nil)
			if !ok {
				toClient(rpcError(m.ID, -32600, "request id already in flight"))
				return
			}
			fwd := *m
			fwd.ID = jsontext.Value(strconv.FormatInt(pid, 10))
			if err := toUp(&fwd); err != nil {
				release(pid)
				toClient(rpcError(m.ID, -32603, err.Error()))
			}
		case m.isResponse(): // the client answering an upstream request; ids are upstream's own
			toUp(m)
		case m.Method == "notifications/cancelled":
			var p map[string]jsontext.Value
			if json.Unmarshal(m.Params, &p) != nil {
				return
			}
			key := canon(p["requestId"])
			mu.Lock()
			stop, pid := cancels[key], byClient[key]
			mu.Unlock()
			if stop != nil {
				stop() // unblocks a held call whose client gave up
			}
			if pid != 0 { // only cancellations of requests this client really has in flight go upstream
				p["requestId"] = jsontext.Value(strconv.FormatInt(pid, 10))
				m.Params, _ = json.Marshal(p)
				toUp(m)
			}
		default:
			toUp(m)
		}
	}

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		sc := bufio.NewScanner(in) // also strips a trailing \r; a bare \r inside a line is rejected by handle
		sc.Buffer(nil, maxLine)
		for sc.Scan() {
			if b := sc.Bytes(); len(bytes.TrimSpace(b)) > 0 {
				handle(append([]byte(nil), b...))
			}
		}
		// shortcut: a line over maxLine ends the session (Scanner error), no error reply; upgrade if clients need one
	}()

	select {
	case <-clientDone:
	case <-upDone:
	case <-ctx.Done():
	}
	cancel() // kills the upstream; shortcut: no grace period for a clean upstream exit, upgrade if upstreams need flush time
	<-upDone
	c.Wait()
	return ctx.Err()
}
