package budget

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/pkg/contracts"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func usd(m int64) contracts.Money { return contracts.Money{Micros: m, Currency: "USD"} }

func open(t *testing.T, limits ...contracts.BudgetLimit) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "b.db"), limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func lim(w contracts.Window, m int64) contracts.BudgetLimit {
	return contracts.BudgetLimit{Agent: "*", Tool: "*", Window: w, Limit: usd(m)}
}

var sc = contracts.BudgetScope{AgentID: "a", RunID: "r1", Server: "s", Tool: "t"}

func TestConcurrentReserve(t *testing.T) {
	s := open(t, lim(contracts.WindowPerRun, 10_000))
	var ok atomic.Int64
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Reserve(t.Context(), sc, usd(1000)); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 10 {
		t.Fatalf("succeeded %d, want 10", ok.Load())
	}
}

func TestCostFromResult(t *testing.T) {
	for _, bad := range []string{
		`{}`, `{"_meta":{"cost":"x"}}`, `{"_meta":{"cost":{"amount":NaN,"currency":"USD"}}}`,
		`{"_meta":{"cost":{"amount":1e999,"currency":"USD"}}}`, `{"_meta":{"cost":{"amount":-1,"currency":"USD"}}}`,
		`{"_meta":{"cost":{"amount":"1","currency":"USD"}}}`, `{"_meta":{"cost":{"amount":1,"currency":"EUR"}}}`,
		`{"_meta":{"cost":{"amount":1e300,"currency":"USD"}}}`,
	} {
		if _, ok := CostFromResult(json.RawMessage(bad), "USD"); ok {
			t.Errorf("accepted %s", bad)
		}
	}
	m, ok := CostFromResult(json.RawMessage(`{"_meta":{"cost":{"amount":0.005,"currency":"USD"}}}`), "USD")
	if !ok || m != usd(5000) {
		t.Fatalf("got %v %v", m, ok)
	}
}

func TestPricer(t *testing.T) {
	p := NewPricer([]contracts.Price{
		{Server: "s", Tool: "ref*", PerCall: 0.001, ArgField: "amount", ArgMultiplier: 0.5},
		{Server: "*", Tool: "*", PerCall: 0.002},
	}, "USD")
	got, _ := p.Estimate(t.Context(), "s", "refund", json.RawMessage(`{"amount":2}`))
	if got != usd(1_001_000) {
		t.Fatalf("got %v", got)
	}
	got, _ = p.Estimate(t.Context(), "s", "refund", json.RawMessage(`{}`))
	if got != usd(1000) {
		t.Fatalf("missing key: %v", got)
	}
	got, _ = p.Estimate(t.Context(), "z", "other", nil)
	if got != usd(2000) {
		t.Fatalf("fallback: %v", got)
	}
	if _, err := p.Estimate(t.Context(), "s", "x", json.RawMessage(`{`)); err == nil {
		t.Fatal("want error for malformed args")
	}
	got, _ = NewPricer(nil, "USD").Estimate(t.Context(), "s", "x", nil)
	if got != usd(0) {
		t.Fatalf("no match: %v", got)
	}
}

func TestRemainingSettleRelease(t *testing.T) {
	ctx := context.Background()
	s := open(t, lim(contracts.WindowPerRun, 10_000), lim(contracts.WindowDaily, 4_000))
	id, err := s.Reserve(ctx, sc, usd(3000))
	if err != nil {
		t.Fatal(err)
	}
	rem, _ := s.Remaining(ctx, sc)
	if rem[contracts.WindowPerRun] != usd(7000) || rem[contracts.WindowDaily] != usd(1000) || len(rem) != 2 {
		t.Fatalf("remaining %v", rem)
	}
	var ce *contracts.CallError
	_, err = s.Reserve(ctx, sc, usd(2000))
	if !errors.As(err, &ce) || ce.Window != contracts.WindowDaily || ce.Error() != "agentgw: budget exceeded: daily budget exceeded" {
		t.Fatalf("err %v", err)
	}
	id2, _ := s.Reserve(ctx, sc, usd(500))
	if err := s.Release(ctx, id2); err != nil {
		t.Fatal(err)
	}
	if err := s.Settle(ctx, id, usd(9000)); err != nil { // above estimate and daily limit
		t.Fatal(err)
	}
	rem, _ = s.Remaining(ctx, sc)
	if rem[contracts.WindowDaily].Micros != 0 {
		t.Fatalf("clamp %v", rem)
	}
	if _, err := s.Reserve(ctx, sc, usd(0)); err == nil {
		t.Fatal("reserve after overshoot should fail")
	}
	if s.Settle(ctx, id, usd(1)) == nil || s.Release(ctx, id) == nil || s.Release(ctx, "nope") == nil {
		t.Fatal("closed/unknown id must error")
	}
	// A different run has its own per_run window.
	rem, _ = s.Remaining(ctx, contracts.BudgetScope{AgentID: "a", RunID: "r2", Server: "s", Tool: "t"})
	if rem[contracts.WindowPerRun] != usd(10_000) {
		t.Fatalf("r2 %v", rem)
	}
}

func TestPersistenceAndRollover(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "b.db")
	limits := []contracts.BudgetLimit{lim(contracts.WindowDaily, 1000)}
	s, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 1, 1, 23, 59, 0, 0, time.UTC)
	s.now = func() time.Time { return day }
	if _, err := s.Reserve(ctx, sc, usd(1000)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.now = func() time.Time { return day }
	if _, err := s.Reserve(ctx, sc, usd(1)); err == nil {
		t.Fatal("reservation from previous process not counted")
	}
	s.now = func() time.Time { return day.Add(2 * time.Minute) }
	if _, err := s.Reserve(ctx, sc, usd(1000)); err != nil {
		t.Fatalf("new UTC day should reset: %v", err)
	}
}

func TestE2E_HarnessSearchBudget(t *testing.T) {
	store := open(t, lim(contracts.WindowPerRun, 10_000))
	tools := harness.DefaultTools(t)
	for i := range tools {
		if tools[i].Name != "search" {
			continue
		}
		fixture := tools[i].Cost
		tools[i].Handler = func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			scope := contracts.BudgetScope{AgentID: "a", RunID: "r1", Server: "harness", Tool: "search"}
			est := usd(5000)
			id, err := store.Reserve(ctx, scope, est)
			if err != nil {
				var ce *contracts.CallError
				if !errors.As(err, &ce) {
					return nil, err
				}
				return harness.Refuse(contracts.GatewayMeta{Outcome: contracts.EntryBudgetExceeded, Reason: ce.Reason}, ce.Error()), nil
			}
			res, err := harness.Echo(ctx, req)
			if err != nil {
				store.Release(ctx, id)
				return nil, err
			}
			res.Meta = mcp.Meta{"cost": map[string]any{"amount": fixture.Amount, "currency": fixture.Currency}}
			raw, _ := json.Marshal(res)
			actual, ok := CostFromResult(raw, "USD")
			if !ok {
				actual = est
			}
			return res, store.Settle(ctx, id, actual)
		}
	}
	c := harness.NewClient(t, harness.StartServer(t, harness.Options{Tools: tools}))
	for i := range 3 {
		res, err := c.Call("search", map[string]any{"query": "x"})
		if err != nil {
			t.Fatal(err)
		}
		if i < 2 && res.IsError {
			t.Fatalf("call %d refused", i)
		}
		if i == 2 {
			m, ok := harness.MetaOf(res)
			if !res.IsError || !ok || m.Outcome != contracts.EntryBudgetExceeded || m.Reason != "per_run budget exceeded" {
				t.Fatalf("third call: %+v %+v", res, m)
			}
		}
	}
}

func TestPricerAgentControlledArgs(t *testing.T) {
	p := NewPricer([]contracts.Price{{Server: "*", Tool: "*", PerCall: 1, ArgField: "n", ArgMultiplier: 0.001}}, "USD")
	for _, c := range []struct {
		args string
		want int64
	}{{`{"n":1e17}`, math.MaxInt64}, {`{"n":1e308}`, math.MaxInt64}} {
		got, err := p.Estimate(t.Context(), "s", "t", json.RawMessage(c.args))
		if err != nil || got.Micros != c.want {
			t.Errorf("%s: got %v %v, want %d", c.args, got, err, c.want)
		}
	}
}

func TestOverflowSafe(t *testing.T) {
	ctx := context.Background()
	s := open(t, lim(contracts.WindowPerRun, 10_000))
	a, _ := s.Reserve(ctx, sc, usd(0))
	b, _ := s.Reserve(ctx, sc, usd(0))
	big := usd(9_000_000_000_000_000_000)
	if s.Settle(ctx, a, big) != nil || s.Settle(ctx, b, big) != nil {
		t.Fatal("settle")
	}
	if _, err := s.Reserve(ctx, sc, usd(1_000_000_000)); err == nil {
		t.Fatal("wrapped sum admitted a reserve")
	}
	s2 := open(t, lim(contracts.WindowPerRun, 10_000))
	if _, err := s2.Reserve(ctx, sc, usd(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Reserve(ctx, sc, usd(math.MaxInt64)); err == nil {
		t.Fatal("MaxInt64 admitted")
	}
}

func TestRejectBadMoneyAndLimits(t *testing.T) {
	ctx := context.Background()
	s := open(t, lim(contracts.WindowPerRun, 10_000))
	for _, m := range []contracts.Money{{Micros: 1, Currency: "EUR"}, {}, usd(-1_000_000)} {
		if _, err := s.Reserve(ctx, sc, m); err == nil {
			t.Errorf("Reserve accepted %v", m)
		}
	}
	id, _ := s.Reserve(ctx, sc, usd(1))
	for _, m := range []contracts.Money{{Micros: 1, Currency: "EUR"}, usd(-1)} {
		if s.Settle(ctx, id, m) == nil {
			t.Errorf("Settle accepted %v", m)
		}
	}
	if _, err := Open(filepath.Join(t.TempDir(), "w.db"), []contracts.BudgetLimit{lim("weekly", 1)}); err == nil {
		t.Error("unknown window accepted at Open")
	}
}

func TestPricerGap006(t *testing.T) {
	p := NewPricer([]contracts.Price{{Server: "*", Tool: "*", PerCall: 0, ArgField: "amount", ArgMultiplier: 1}}, "USD")
	est := func(args string) (contracts.Money, error) {
		return p.Estimate(t.Context(), "s", "t", json.RawMessage(args))
	}
	for args, want := range map[string]int64{
		`{"amount":"120"}`:     120_000_000,
		`{"amount":"1.5e2"}`:   150_000_000,
		`{"amount":"0"}`:       0,
		`{"amount":"-0"}`:      0,
		`{"Amount":120}`:       120_000_000, // case-variant key alone
		`{"AMOUNT":"2"}`:       2_000_000,
		`{"amount":1,"x":"y"}`: 1_000_000,
		`{}`:                   0,
	} {
		if got, err := est(args); err != nil || got.Micros != want {
			t.Errorf("%s: got %v %v, want %d", args, got, err, want)
		}
	}
	if got, _ := est(`{"amount":1e300}`); got.Micros != math.MaxInt64 {
		t.Errorf("finite overflow must still saturate: %v", got)
	}
	for _, args := range []string{
		`{"amount":" 120"}`, `{"amount":"120 "}`, `{"amount":"+1"}`, `{"amount":"0x10"}`, `{"amount":"inf"}`,
		`{"amount":"NaN"}`, `{"amount":"1,000"}`, `{"amount":""}`, `{"amount":"01"}`, `{"amount":"-1"}`,
		`{"amount":"1e999"}`, `{"amount":true}`, `{"amount":null}`, `{"amount":[1]}`, `{"amount":{"a":1}}`,
		`{"amount":-1}`, `{"amount":1e999}`, `{"Amount":"abc"}`,
	} {
		_, err := est(args)
		if err == nil || !strings.Contains(err.Error(), "unpriceable argument amount") {
			t.Errorf("%s: err %v, want unpriceable", args, err)
		}
	}
}

func TestExclusiveNoOverlap(t *testing.T) {
	s := open(t)
	var in, maxIn atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Exclusive(t.Context(), func() error {
				n := in.Add(1)
				if n > maxIn.Load() {
					maxIn.Store(n)
				}
				time.Sleep(5 * time.Millisecond)
				in.Add(-1)
				return nil
			})
		}()
	}
	wg.Wait()
	if maxIn.Load() != 1 {
		t.Fatalf("overlap: %d inside fn at once", maxIn.Load())
	}
}

func TestExclusiveCancelledWaiter(t *testing.T) {
	s := open(t)
	held, release := make(chan struct{}), make(chan struct{})
	go s.Exclusive(t.Context(), func() error { close(held); <-release; return nil })
	<-held
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	ran := false
	err := s.Exclusive(ctx, func() error { ran = true; return nil })
	close(release)
	if !errors.Is(err, context.Canceled) || ran {
		t.Fatalf("err %v ran %v", err, ran)
	}
}

func TestExclusiveReturnsErrorAndReleases(t *testing.T) {
	s := open(t)
	boom := errors.New("boom")
	if err := s.Exclusive(t.Context(), func() error { return boom }); err != boom {
		t.Fatalf("got %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	ran := false
	if err := s.Exclusive(ctx, func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("lock not released: %v", err)
	}
}

func TestNFCAndNFDShareLimit(t *testing.T) {
	ctx := context.Background()
	l := lim(contracts.WindowPerRun, 1000)
	l.Tool = "harness.cafe\u0301" // NFD glob: Open normalises it
	s := open(t, l)
	nfc := contracts.BudgetScope{AgentID: "a", RunID: "r", Server: "harness", Tool: "caf\u00e9"}
	nfd := contracts.BudgetScope{AgentID: "a", RunID: "r", Server: "harness", Tool: "cafe\u0301"}
	if _, err := s.Reserve(ctx, nfc, usd(1000)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reserve(ctx, nfd, usd(1)); err == nil {
		t.Fatal("NFD spelling escaped the limit")
	}
	if rem, _ := s.Remaining(ctx, nfd); rem[contracts.WindowPerRun].Micros != 0 {
		t.Fatalf("remaining %v", rem)
	}
}
