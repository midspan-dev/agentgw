package proxy_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/proxy"
)

func TestValidateParams(t *testing.T) {
	for _, tc := range []struct {
		name, args, ir string
		bad            bool
		keys           [2]string
	}{
		{"empty", ``, ``, false, [2]string{}},
		{"plain", `{"a":1,"b":{"c":[1,2,{"d":"x"}]}}`, `{"k":{"action":"accept"}}`, false, [2]string{}},
		{"large finite", `{"n":1e300,"m":-1e300}`, ``, false, [2]string{}},
		{"underflow is finite", `{"n":1e-400}`, ``, false, [2]string{}},
		{"same key in different objects", `{"a":{"x":1},"b":{"x":2}}`, ``, false, [2]string{}},
		{"same key in array elements", `{"a":[{"k":1},{"k":2}]}`, ``, false, [2]string{}},
		{"overflow", `{"n":1e400}`, ``, true, [2]string{}},
		{"negative overflow nested in inputResponses", `{}`, `{"k":{"c":[-1e400]}}`, true, [2]string{}},
		{"top-level collision", `{"Amount":1,"amount":2}`, ``, true, [2]string{"Amount", "amount"}},
		{"nested collision", `{"a":{"X":1,"x":2}}`, ``, true, [2]string{"X", "x"}},
		{"collision in array element", `{"a":[{"k":1},{"k":1,"K":2}]}`, ``, true, [2]string{"k", "K"}},
		{"collision in inputResponses", `{}`, `{"k":{"A":1,"a":2}}`, true, [2]string{"A", "a"}},
		{"NFC-only collision", "{\"\u00e9\":1,\"e\u0301\":2}", ``, true, [2]string{"\u00e9", "e\u0301"}},
		{"case and NFC", "{\"\u00c9\":1,\"e\u0301\":2}", ``, true, [2]string{"\u00c9", "e\u0301"}},
		{"exact duplicate", `{"amount":0,"amount":120}`, ``, true, [2]string{"amount", "amount"}},
		{"exact duplicate nested in array", `{"a":[{"k":1,"k":2}]}`, ``, true, [2]string{"k", "k"}},
		{"exact duplicate in inputResponses", `{}`, `{"k":{"z":1,"z":2}}`, true, [2]string{"z", "z"}},
		{"unrelated keys", `{"amount":1,"amounts":2}`, ``, false, [2]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := proxy.ValidateParams([]byte(tc.args), []byte(tc.ir))
			if (err != nil) != tc.bad {
				t.Fatalf("err = %v, want bad=%v", err, tc.bad)
			}
			var pe *proxy.ParamsError
			if err != nil && !errors.As(err, &pe) {
				t.Fatalf("%T is not *ParamsError", err)
			}
			if tc.keys != ([2]string{}) && pe.Keys != tc.keys {
				t.Errorf("keys = %q, want %q (%v)", pe.Keys, tc.keys, err)
			}
		})
	}
}

// fold must agree with strings.EqualFold, and a huge object must validate in linear time.
func TestValidateParamsManyKeysIsFast(t *testing.T) {
	obj := func(n int) []byte {
		var b strings.Builder
		b.WriteString("{")
		for i := range n {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `"k%d":1`, i)
		}
		b.WriteString("}")
		return []byte(b.String())
	}
	// Best of 3 runs; a ratio, not a wall-clock limit, so a loaded machine cannot fail it.
	best := func(params []byte) time.Duration {
		m := time.Duration(1<<63 - 1)
		for range 3 {
			start := time.Now()
			if err := proxy.ValidateParams(params, nil); err != nil {
				t.Fatal(err)
			}
			m = min(m, time.Since(start))
		}
		return m
	}
	small, big := obj(15000), obj(60000)
	if ds, db := best(small), best(big); db > 8*ds {
		t.Errorf("4x the keys took %.1fx the time (%v vs %v); linear is ~4x, quadratic ~16x", float64(db)/float64(ds), db, ds)
	}
	// Last key collides with the first by case only.
	bad := strings.TrimSuffix(string(big), "}") + `,"K0":2}`
	if err := proxy.ValidateParams([]byte(bad), nil); err == nil {
		t.Error("collision at the end of a big object not found")
	}
	// Simple case folding beyond ToLower: long s and Kelvin sign.
	for _, pair := range [][2]string{{"s", "\u017f"}, {"k", "\u212a"}} {
		if err := proxy.ValidateParams([]byte(`{"`+pair[0]+`":1,"`+pair[1]+`":2}`), nil); err == nil {
			t.Errorf("%q and %q should collide", pair[0], pair[1])
		}
	}
}
