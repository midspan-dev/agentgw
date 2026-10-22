// Package budget implements contracts.Pricer and contracts.Budget.
package budget

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/midspan-dev/agentgw/pkg/contracts"
	"golang.org/x/text/unicode/norm"
)

// glob matches s against pattern where `*` matches any run of characters.
func glob(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(s, p)
		if i < 0 {
			return false
		}
		s = s[i+len(p):]
	}
	return strings.HasSuffix(s, last)
}

// toMicros is the one float->micros boundary.
func toMicros(x float64) int64 { return int64(math.Round(x * contracts.MicrosPerUnit)) }

type pricer struct {
	table    []contracts.Price
	perCall  []int64 // micros, converted once at the config boundary
	currency string
}

// NewPricer returns a Pricer over table; the first matching row wins.
func NewPricer(table []contracts.Price, currency string) contracts.Pricer {
	p := &pricer{table: table, currency: currency}
	for _, r := range table {
		p.perCall = append(p.perCall, max(toMicros(r.PerCall), 0))
	}
	return p
}

// argMicros converts the agent-controlled arg term. Negative terms count as 0;
// NaN or out-of-range terms saturate so the call is blocked, never free.
func argMicros(x float64) int64 {
	switch {
	case math.IsNaN(x):
		return math.MaxInt64
	case x <= 0:
		return 0
	case x*contracts.MicrosPerUnit >= math.MaxInt64:
		return math.MaxInt64
	}
	return toMicros(x)
}

// numStr is the RFC 8259 number grammar a JSON string must match whole to count as a number.
var numStr = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// argValue returns the numeric value of args[field]: the exact key, else the
// first key equal under EqualFold after NFC. Missing is 0; anything present
// that is not a non-negative finite number (or its strict string form) is an error.
func argValue(args map[string]json.RawMessage, field string) (float64, error) {
	raw, ok := args[field]
	if !ok {
		for k, v := range args {
			if strings.EqualFold(norm.NFC.String(k), norm.NFC.String(field)) {
				raw, ok = v, true
				break
			}
		}
	}
	if !ok {
		return 0, nil
	}
	bad := func(why string) error { return fmt.Errorf("unpriceable argument %s: %s", field, why) }
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, bad("not a finite number")
	}
	var f float64
	switch x := v.(type) {
	case float64:
		f = x
	case string:
		if !numStr.MatchString(x) {
			return 0, bad("string is not a plain decimal number")
		}
		var err error
		if f, err = strconv.ParseFloat(x, 64); err != nil || math.IsInf(f, 0) {
			return 0, bad("not a finite number")
		}
	default:
		return 0, bad("not a number")
	}
	if f < 0 {
		return 0, bad("negative")
	}
	return f, nil
}

func (p *pricer) Estimate(_ context.Context, server, tool string, args json.RawMessage) (contracts.Money, error) {
	var a map[string]json.RawMessage
	if len(args) > 0 {
		if err := json.Unmarshal(args, &a); err != nil {
			return contracts.Money{}, err
		}
	}
	for i, r := range p.table {
		if !glob(r.Server, server) || !glob(r.Tool, tool) {
			continue
		}
		m := p.perCall[i]
		if r.ArgField != "" {
			v, err := argValue(a, r.ArgField)
			if err != nil {
				return contracts.Money{}, err
			}
			m = satAdd(m, argMicros(v*r.ArgMultiplier))
		}
		return contracts.Money{Micros: m, Currency: p.currency}, nil
	}
	return contracts.Money{Currency: p.currency}, nil
}

// satAdd adds non-negative values, saturating at MaxInt64.
func satAdd(a, b int64) int64 {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// CostFromResult reads _meta.cost from a raw CallToolResult
// (contracts/cost-meta.md section 1). False when absent or invalid.
func CostFromResult(result json.RawMessage, currency string) (contracts.Money, bool) {
	var r struct {
		Meta struct {
			Cost struct {
				Amount   *float64 `json:"amount"`
				Currency string   `json:"currency"`
			} `json:"cost"`
		} `json:"_meta"`
	}
	if json.Unmarshal(result, &r) != nil {
		return contracts.Money{}, false
	}
	c := r.Meta.Cost
	if c.Amount == nil || c.Currency != currency || math.IsNaN(*c.Amount) || math.IsInf(*c.Amount, 0) ||
		*c.Amount < 0 || *c.Amount*contracts.MicrosPerUnit >= math.MaxInt64 {
		return contracts.Money{}, false
	}
	return contracts.Money{Micros: toMicros(*c.Amount), Currency: currency}, true
}
