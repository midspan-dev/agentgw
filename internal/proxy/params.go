package proxy

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode"

	stdjson "encoding/json"

	"golang.org/x/text/unicode/norm"
)

// ParamsError is returned by ValidateParams. Keys is set for a key collision.
type ParamsError struct {
	Reason string
	Keys   [2]string
}

func (e *ParamsError) Error() string { return e.Reason }

// ValidateParams checks the tools/call members the gateway cannot safely
// interpret: a number that is not a finite IEEE-754 double (I-JSON; 1e400), and
// two keys of one object (an exact duplicate included, which encoding/json would resolve to the last), at any depth and through arrays, that are
// equal under strings.EqualFold(NFC(k1), NFC(k2)) (a case-insensitive or
// normalising upstream could read either). Empty values are valid. Safe for
// concurrent use; needs no proxy instance. The error is a *ParamsError.
func ValidateParams(args, inputResponses stdjson.RawMessage) error {
	if err := validate(jsontext.Value(args)); err != nil {
		return err
	}
	return validate(jsontext.Value(inputResponses))
}

func validate(v jsontext.Value) error {
	type level struct {
		obj       bool
		expectKey bool
		seen      map[string]string // folded NFC key -> first original key
	}
	var stack []*level
	d := jsontext.NewDecoder(bytes.NewReader(v), jsontext.AllowDuplicateNames(true)) // duplicates are collisions below, with both keys named
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].obj {
			stack[n-1].expectKey = true
		}
	}
	for {
		tok, err := d.ReadToken()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return &ParamsError{Reason: "invalid JSON: " + err.Error()}
		}
		top := (*level)(nil)
		if n := len(stack); n > 0 {
			top = stack[n-1]
		}
		switch tok.Kind() {
		case '{':
			stack = append(stack, &level{obj: true, expectKey: true, seen: map[string]string{}})
		case '[':
			stack = append(stack, &level{})
		case '}', ']':
			stack = stack[:len(stack)-1]
			valueDone()
		case '"':
			if top != nil && top.obj && top.expectKey {
				k := tok.String()
				fk := fold(norm.NFC.String(k))
				if first, dup := top.seen[fk]; dup {
					return &ParamsError{Reason: "argument keys collide: " + first + ", " + k, Keys: [2]string{first, k}}
				}
				top.seen[fk], top.expectKey = k, false
				continue
			}
			valueDone()
		case '0':
			if f, err := strconv.ParseFloat(tok.String(), 64); err != nil || math.IsInf(f, 0) {
				return &ParamsError{Reason: "numbers must be finite IEEE-754 doubles"}
			}
			valueDone()
		default:
			valueDone()
		}
	}
}

// fold maps a string to a canonical representative of its strings.EqualFold
// class (the smallest rune of each simple-fold orbit), so equal folds and
// EqualFold agree and a map lookup replaces a pairwise scan.
func fold(s string) string {
	return strings.Map(func(r rune) rune {
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < m {
				m = f
			}
		}
		return m
	}, s)
}
