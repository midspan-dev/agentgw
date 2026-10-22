// Package proxy is a transparent MCP proxy with one hook: every tools/call
// goes through a contracts.Interceptor, everything else is forwarded
// unchanged in meaning.
//
// Rule: the upstream only ever receives bytes the proxy produced from what it
// parsed (strictly: case-sensitive, no duplicate names, one object per
// message), never the client's raw bytes, so the upstream cannot act on a
// message the interceptor did not see.
package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	stdjson "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"sync"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

// msg is the JSON-RPC envelope; params and results stay raw (but validated).
type msg struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      jsontext.Value `json:"id,omitzero"`
	Method  string         `json:"method,omitzero"`
	Params  jsontext.Value `json:"params,omitzero"`
	Result  jsontext.Value `json:"result,omitzero"`
	Error   *rpcErr        `json:"error,omitzero"`
}

type rpcErr struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    jsontext.Value `json:"data,omitzero"`
}

// parse decodes exactly one JSON-RPC 2.0 object. strict also rejects unknown
// top-level members (used for client input; upstream replies are lenient).
func parse(b []byte, strict bool) (*msg, error) {
	var m msg
	var opts []json.Options
	if strict {
		opts = append(opts, json.RejectUnknownMembers(true))
	}
	if err := json.Unmarshal(b, &m, opts...); err != nil {
		return nil, err
	}
	if m.JSONRPC != "2.0" {
		return nil, errors.New("jsonrpc must be \"2.0\"")
	}
	if len(m.ID) > 0 && !validID(m.ID) {
		return nil, errors.New("id must be a string or number")
	}
	switch {
	case m.Method != "":
		if m.Result != nil || m.Error != nil {
			return nil, errors.New("request with result or error")
		}
	case len(m.ID) == 0 || (m.Result == nil) == (m.Error == nil):
		return nil, errors.New("not a request, notification or response")
	}
	return &m, nil
}

// canon is the canonical form of an id (RFC 8785), so 9 and 9.0 are the same id.
func canon(id jsontext.Value) string {
	v := append(jsontext.Value(nil), id...)
	if v.Canonicalize() != nil {
		return string(id)
	}
	return string(v)
}

// relay re-serializes an upstream-originated message for the client, dropping members we did not parse.
func relay(m *msg) []byte {
	b, _ := json.Marshal(m)
	return b
}

func validID(id jsontext.Value) bool { return id.Kind() == '"' || id.Kind() == '0' }

func (m *msg) isRequest() bool   { return m.Method != "" && len(m.ID) > 0 }
func (m *msg) isResponse() bool  { return m.Method == "" }
func (m *msg) isToolsCall() bool { return m.Method == "tools/call" && len(m.ID) > 0 }

// result returns the upstream result, or an error for a JSON-RPC error response.
func (m *msg) result() (stdjson.RawMessage, error) {
	if m.Error != nil {
		return nil, fmt.Errorf("upstream error %d: %s", m.Error.Code, m.Error.Message)
	}
	return stdjson.RawMessage(m.Result), nil
}

func rpcError(id jsontext.Value, code int, text string) []byte {
	if len(id) == 0 {
		id = jsontext.Value("null")
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": rpcErr{Code: code, Message: text}})
	return b
}

// intercept runs one tools/call through i and returns the JSON-RPC response
// to send, or nil when the request is dropped. send performs the upstream call
// with the given tool and params; notify delivers a notification to the client.
func intercept(ctx context.Context, i contracts.Interceptor, server string, m *msg,
	send func(ctx context.Context, tool string, params jsontext.Value) (stdjson.RawMessage, error), notify func([]byte)) []byte {
	var params map[string]jsontext.Value
	if json.Unmarshal(m.Params, &params) != nil || params == nil {
		return rpcError(m.ID, -32602, "invalid tools/call params")
	}
	for k := range params { // the complete CallToolParams of the pinned SDK; anything else (e.g. task) is refused
		switch k {
		case "name", "arguments", "_meta", "inputResponses", "requestState":
		default:
			return rpcError(m.ID, -32602, "invalid tools/call params: unexpected member "+k)
		}
	}
	var name string
	if json.Unmarshal(params["name"], &name) != nil || name == "" {
		return rpcError(m.ID, -32602, "invalid tools/call params: name")
	}
	args := params["arguments"]
	if len(args) == 0 || args.Kind() == 'n' {
		args = jsontext.Value(`{}`)
	}
	if args.Kind() != '{' {
		return rpcError(m.ID, -32602, "invalid tools/call params: arguments must be an object")
	}
	if err := ValidateParams(stdjson.RawMessage(args), stdjson.RawMessage(params["inputResponses"])); err != nil {
		return rpcError(m.ID, -32602, "invalid tools/call params: "+err.Error())
	}
	var inputResponses stdjson.RawMessage
	if ir := params["inputResponses"]; len(ir) > 0 && ir.Kind() != 'n' {
		if ir.Kind() != '{' {
			return rpcError(m.ID, -32602, "invalid tools/call params: inputResponses")
		}
		inputResponses = stdjson.RawMessage(ir)
	}
	var requestState string
	if rs := params["requestState"]; len(rs) > 0 && rs.Kind() != 'n' && json.Unmarshal(rs, &requestState) != nil {
		return rpcError(m.ID, -32602, "invalid tools/call params: requestState")
	}
	var meta struct {
		ProgressToken jsontext.Value `json:"progressToken"`
	}
	if len(params["_meta"]) > 0 && json.Unmarshal(params["_meta"], &meta) != nil {
		return rpcError(m.ID, -32602, "invalid tools/call params: _meta")
	}

	id := make([]byte, 16)
	rand.Read(id)
	call := &contracts.Call{
		ID: hex.EncodeToString(id), Server: server, Tool: name, Args: stdjson.RawMessage(args),
		InputResponses: inputResponses, RequestState: requestState,
		Progress: func(string) {},
	}
	call.Forward = func(ctx context.Context) (stdjson.RawMessage, error) {
		// Rebuilt from the Call, so upstream runs exactly what the interceptor saw.
		out := map[string]jsontext.Value{"arguments": jsontext.Value(call.Args)}
		out["name"], _ = json.Marshal(call.Tool)
		if m := params["_meta"]; len(m) > 0 {
			out["_meta"] = m
		}
		if len(call.InputResponses) > 0 {
			out["inputResponses"] = jsontext.Value(call.InputResponses)
		}
		if call.RequestState != "" {
			out["requestState"], _ = json.Marshal(call.RequestState)
		}
		pb, err := json.Marshal(out)
		if err != nil {
			return nil, err
		}
		return send(ctx, call.Tool, pb)
	}
	if token := meta.ProgressToken; validID(token) {
		var mu sync.Mutex
		var n int
		call.Progress = func(text string) {
			mu.Lock() // held across notify so progress numbers arrive in order
			defer mu.Unlock()
			n++
			b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/progress",
				"params": map[string]any{"progressToken": token, "progress": n, "message": text}})
			notify(b)
		}
	}

	res, err := i.Intercept(ctx, call)
	var ce *contracts.CallError
	switch {
	case err == nil && len(res) == 0:
		return rpcError(m.ID, -32603, "interceptor returned no result")
	case err == nil:
		b, merr := json.Marshal(&msg{JSONRPC: "2.0", ID: m.ID, Result: jsontext.Value(res)})
		if merr != nil {
			return rpcError(m.ID, -32603, "invalid result from interceptor: "+merr.Error())
		}
		return b
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return nil
	case errors.As(err, &ce) && ce.Outcome() != contracts.EntryError:
		cp := *ce // do not mutate the interceptor's error
		if cp.CallID == "" {
			cp.CallID = call.ID
		}
		return refusal(m.ID, &cp)
	}
	return rpcError(m.ID, -32603, err.Error())
}

// refusal is the tool-level error for a refused call (contracts/cost-meta.md section 2).
func refusal(id jsontext.Value, ce *contracts.CallError) []byte {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
		"content": []any{map[string]any{"type": "text", "text": ce.Error()}},
		"isError": true,
		"_meta": map[string]any{"agentgw": contracts.GatewayMeta{
			Outcome: ce.Outcome(), Reason: ce.Reason, RuleID: ce.RuleID, CallID: ce.CallID}},
	}})
	return b
}
