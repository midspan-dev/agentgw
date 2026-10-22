package ledger

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

var builtinFields = []string{"password", "passwd", "secret", "token", "api_key", "apikey",
	"authorization", "access_token", "refresh_token", "private_key"}

var builtinPatterns = []string{`(?i)bearer\s+[A-Za-z0-9._~+/=-]+`, `sk-[A-Za-z0-9_-]{8,}`, `AKIA[0-9A-Z]{16}`, `\b[0-9a-fA-F]{32,}\b`}

var failClosed = json.RawMessage(`"` + contracts.Redacted + `"`)

type redactor struct {
	fields map[string]bool
	pats   []*regexp.Regexp
}

func newRedactor(c contracts.RedactionConfig) (*redactor, error) {
	r := &redactor{fields: map[string]bool{}}
	for _, f := range append(append([]string{}, builtinFields...), c.Fields...) {
		r.fields[strings.ToLower(f)] = true
	}
	for _, p := range append(append([]string{}, builtinPatterns...), c.Patterns...) {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		r.pats = append(r.pats, re)
	}
	return r, nil
}

// redact returns a redacted copy of raw; input that cannot be parsed becomes the JSON string "[REDACTED]".
func (r *redactor) redact(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep number text exact
	var v any
	if dec.Decode(&v) != nil {
		return failClosed // unparseable or too deep: never return it raw
	}
	out, err := json.Marshal(r.walk(v))
	if err != nil {
		return failClosed
	}
	return out
}

// redactText applies the secret patterns (not the field rules) to s.
func (r *redactor) redactText(s string) string {
	for _, p := range r.pats {
		s = p.ReplaceAllLiteralString(s, contracts.Redacted)
	}
	return s
}

func (r *redactor) walk(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if r.fields[strings.ToLower(k)] {
				x[k] = contracts.Redacted
			} else {
				x[k] = r.walk(e)
			}
		}
	case []any:
		for i, e := range x {
			x[i] = r.walk(e)
		}
	case string:
		return r.redactText(x)
	}
	return v
}

// StripEnvelope removes the protocol envelope from a CallToolResult
// (docs/adr/0008): top-level resultType and _meta members keyed
// io.modelcontextprotocol/*; an emptied _meta goes too. Invalid JSON, or JSON
// that is not an object, is returned unchanged.
func StripEnvelope(raw json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return raw
	}
	delete(m, "resultType")
	var meta map[string]json.RawMessage
	if json.Unmarshal(m["_meta"], &meta) == nil && meta != nil {
		for k := range meta {
			if strings.HasPrefix(k, "io.modelcontextprotocol/") {
				delete(meta, k)
			}
		}
		if len(meta) == 0 {
			delete(m, "_meta")
		} else {
			m["_meta"], _ = json.Marshal(meta)
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}
