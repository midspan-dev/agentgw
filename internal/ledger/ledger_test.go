package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

func openT(t *testing.T, cfg contracts.LedgerConfig, red contracts.RedactionConfig) (*Ledger, ed25519.PrivateKey) {
	t.Helper()
	if cfg.Path == "" {
		cfg.Path = filepath.Join(t.TempDir(), "ledger.jsonl")
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	l, err := Open(cfg, key, red)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, key
}

func entry(n int, args, content string) *contracts.Entry {
	e := &contracts.Entry{CallID: "c", Outcome: contracts.EntryOK,
		Action: contracts.EntryAction{Server: "s", Tool: "echo", Args: json.RawMessage(args)},
		Result: contracts.EntryResult{Content: json.RawMessage(content)}}
	e.Decision.Outcome, e.Decision.RuleID = contracts.OutcomeAllow, "allow-all"
	return e
}

// build writes 12 entries with a checkpoint after 10 and returns the lines.
func build(t *testing.T) (lines []string, key ed25519.PrivateKey) {
	l, key := openT(t, contracts.LedgerConfig{CheckpointEvery: 10}, contracts.RedactionConfig{})
	for i := 1; i <= 12; i++ {
		if err := l.Append(t.Context(), entry(i, `{"n":`+string(rune('0'+i%10))+`}`, `{"content":[]}`)); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(l.cfg.Path)
	lines = strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 13 {
		t.Fatalf("lines = %d, want 13", len(lines))
	}
	return lines, key
}

func check(lines []string, pub ed25519.PublicKey) contracts.VerifyReport {
	return Verify(strings.NewReader(strings.Join(lines, "\n")+"\n"), pub)
}

func TestVerifyTamper(t *testing.T) {
	lines, key := build(t)
	pub := key.Public().(ed25519.PublicKey)
	if r := check(lines, pub); !r.OK || r.Entries != 12 || r.Checkpoints != 1 {
		t.Fatalf("clean ledger: %+v", r)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	cp := func(mod func(l []string) []string) []string { return mod(append([]string{}, lines...)) }

	cases := []struct {
		name   string
		lines  []string
		line   int
		reason string
	}{
		{"flip byte in entry", cp(func(l []string) []string { l[3] = strings.Replace(l[3], `"tool":"echo"`, `"tool":"ecko"`, 1); return l }), 4, "bad_signature"},
		{"flip byte in sig", cp(func(l []string) []string {
			i := strings.Index(l[4], `"sig":"`) + 7
			c := byte('0')
			if l[4][i] == '0' {
				c = '1'
			}
			l[4] = l[4][:i] + string(c) + l[4][i+1:]
			return l
		}), 5, "bad_signature"},
		{"delete entry 3", cp(func(l []string) []string { return append(l[:2], l[3:]...) }), 3, "chain_break"},
		{"swap 5 and 6", cp(func(l []string) []string { l[4], l[5] = l[5], l[4]; return l }), 5, "chain_break"},
		{"resign entry 7", cp(func(l []string) []string {
			var e contracts.Entry
			json.Unmarshal([]byte(l[6]), &e)
			e.Signer = hex.EncodeToString(other.Public().(ed25519.PublicKey))
			b, _, _ := seal(&e, other)
			l[6] = string(b)
			return l
		}), 7, "wrong_signer"},
		{"edit checkpoint root", cp(func(l []string) []string {
			var c contracts.Checkpoint
			json.Unmarshal([]byte(l[10]), &c)
			c.Root = strings.Repeat("ab", 32)
			b, _, _ := seal(&c, key)
			l[10] = string(b)
			return l
		}), 11, "bad_checkpoint_root"},
		{"edit checkpoint range", cp(func(l []string) []string {
			var c contracts.Checkpoint
			json.Unmarshal([]byte(l[10]), &c)
			c.Range.Count = 9
			b, _, _ := seal(&c, key)
			l[10] = string(b)
			return l
		}), 11, "bad_checkpoint_range"},
		{"bad version", cp(func(l []string) []string { l[0] = strings.Replace(l[0], `"version":"1"`, `"version":"2"`, 1); return l }), 1, "bad_version"},
		{"bad json", cp(func(l []string) []string { l[0] = "{nope"; return l }), 1, "bad_json"},
	}
	for _, c := range cases {
		r := check(c.lines, pub)
		if r.OK || r.Line != c.line || r.Reason != c.reason {
			t.Errorf("%s: got %+v, want line %d %s", c.name, r, c.line, c.reason)
		}
	}
}

func TestCheckpointMerkleAndEmpty(t *testing.T) {
	l, key := openT(t, contracts.LedgerConfig{}, contracts.RedactionConfig{})
	if cp, err := l.Checkpoint(t.Context()); cp != nil || err != nil {
		t.Fatalf("empty checkpoint: %v %v", cp, err)
	}
	for i := 0; i < 3; i++ { // odd count exercises the carried node
		l.Append(t.Context(), entry(i, `{}`, `null`))
	}
	cp, err := l.Checkpoint(t.Context())
	if err != nil || cp.Range.Count != 3 {
		t.Fatalf("checkpoint: %+v %v", cp, err)
	}
	if again, _ := l.Checkpoint(t.Context()); again != nil {
		t.Fatal("second checkpoint should be nil")
	}
	rep, err := l.Verify(t.Context())
	if err != nil || !rep.OK || rep.Checkpoints != 1 {
		t.Fatalf("verify: %+v %v", rep, err)
	}
	_ = key
}

func TestReopenContinuesChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	for i := 0; i < 2; i++ {
		l, err := Open(contracts.LedgerConfig{Path: path, CheckpointEvery: 3}, key, contracts.RedactionConfig{})
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 2; j++ {
			if err := l.Append(t.Context(), entry(j, `{}`, `null`)); err != nil {
				t.Fatal(err)
			}
		}
		l.Close()
	}
	b, _ := os.ReadFile(path)
	if r := Verify(bytes.NewReader(b), key.Public().(ed25519.PublicKey)); !r.OK || r.Entries != 4 || r.Checkpoints != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestRedactionCorpus(t *testing.T) {
	b, err := os.ReadFile("testdata/redaction.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name     string
		In, Want json.RawMessage
		Fields   []string
		Patterns []string
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		l, _ := openT(t, contracts.LedgerConfig{}, contracts.RedactionConfig{Fields: c.Fields, Patterns: c.Patterns})
		got := l.Redact(c.In)
		var g, w any
		json.Unmarshal(got, &g)
		json.Unmarshal(c.Want, &w)
		if !reflect.DeepEqual(g, w) {
			t.Errorf("%s: got %s want %s", c.Name, got, c.Want)
		}
		e := entry(0, string(c.In), `{"content":[]}`)
		if err := l.Append(t.Context(), e); err != nil {
			t.Fatal(err)
		}
		if h, _ := canonHash(c.In); e.Action.ArgsHash != h {
			t.Errorf("%s: args_hash changed by redaction", c.Name)
		}
		changed := !reflect.DeepEqual(w, mustAny(t, c.In))
		if changed && bytes.Equal(e.Action.Args, c.In) {
			t.Errorf("%s: redacted equals raw", c.Name)
		}
	}
	l, _ := openT(t, contracts.LedgerConfig{}, contracts.RedactionConfig{})
	if got := l.Redact(json.RawMessage(`{bad "password":"hunter2"`)); string(got) != `"[REDACTED]"` {
		t.Errorf("invalid JSON not failed closed: %s", got)
	}
}

func TestRedactionLeavesHashesAndVerifies(t *testing.T) {
	l, key := openT(t, contracts.LedgerConfig{}, contracts.RedactionConfig{})
	raw := `{"password":"hunter2","n":1}`
	e := entry(1, raw, `{"content":[{"type":"text","text":"key sk-abcdEFGH12345678"}]}`)
	if err := l.Append(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	want, _ := canonHash([]byte(raw))
	if e.Action.ArgsHash != want {
		t.Error("args_hash is not over raw args")
	}
	if strings.Contains(string(e.Action.Args), "hunter2") || strings.Contains(string(e.Result.Content), "sk-") {
		t.Errorf("stored copies not redacted: %s %s", e.Action.Args, e.Result.Content)
	}
	if wantRes, _ := canonHash([]byte(`{"content":[{"type":"text","text":"key sk-abcdEFGH12345678"}]}`)); e.Result.ResultHash != wantRes {
		t.Error("result_hash is not over raw content")
	}
	b, _ := os.ReadFile(l.cfg.Path)
	if r := Verify(bytes.NewReader(b), key.Public().(ed25519.PublicKey)); !r.OK {
		t.Fatalf("%+v", r)
	}
}

func TestStripEnvelope(t *testing.T) {
	full := json.RawMessage(`{"resultType":"complete","content":[],"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"x"},"cost":{"amount":1}}}`)
	if got := StripEnvelope(full); string(got) != `{"_meta":{"cost":{"amount":1}},"content":[]}` {
		t.Errorf("got %s", got)
	}
	only := json.RawMessage(`{"content":[],"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"x"}}}`)
	if got := StripEnvelope(only); string(got) != `{"content":[]}` {
		t.Errorf("got %s", got)
	}
	if got := StripEnvelope(json.RawMessage(`nope`)); string(got) != `nope` {
		t.Errorf("invalid changed: %s", got)
	}
	a, _ := canonHash(StripEnvelope(only))
	b, _ := canonHash(StripEnvelope(json.RawMessage(`{"content":[],"resultType":"complete"}`)))
	if a != b {
		t.Error("hashes differ for envelope-only difference")
	}
}

func TestKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	pub, err := GenerateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	k, err := LoadKey(path)
	if err != nil || !k.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatalf("load: %v", err)
	}
	if _, err := GenerateKey(path); err == nil {
		t.Error("overwrote existing key")
	}
}

func TestE2EHarnessAllow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	l, key := openT(t, contracts.LedgerConfig{Path: path, CheckpointEvery: 10}, contracts.RedactionConfig{})
	c := harness.NewClient(t, harness.StartServer(t, harness.Options{Tools: harness.DefaultTools(t)}))
	for i := 1; i <= 5; i++ {
		args := map[string]any{"n": i}
		res, err := c.Call("echo", args)
		if err != nil {
			t.Fatal(err)
		}
		content, _ := json.Marshal(res) // the result exactly as the client received it
		if !bytes.Contains(content, []byte("resultType")) {
			t.Fatalf("client result carries no envelope: %s", content)
		}
		rawArgs, _ := json.Marshal(args)
		e := entry(0, string(rawArgs), string(content))
		e.Action.Server = "harness"
		e.Principal = contracts.Principal{AgentID: "test-agent", Owner: "test@example.com", RunID: "run-1"}
		e.Decision.PolicyVersion = strings.Repeat("c", 64)
		e.Cost = contracts.EntryCost{Estimated: contracts.Money{Currency: "USD"}, Actual: contracts.Money{Currency: "USD"}}
		if err := l.Append(t.Context(), e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.Checkpoint(t.Context()); err != nil {
		t.Fatal(err)
	}
	rep, err := l.Verify(t.Context())
	if err != nil || !rep.OK || rep.Entries != 5 || rep.Checkpoints != 1 {
		t.Fatalf("verify: %+v %v", rep, err)
	}
	if r := check(mustLines(t, path), key.Public().(ed25519.PublicKey)); !r.OK {
		t.Fatalf("offline verify: %+v", r)
	}
	harness.Golden(t, "allow", path)
}

func mustLines(t *testing.T, path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func mustAny(t *testing.T, b []byte) any {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func fileOf(t *testing.T, l *Ledger) []byte {
	b, err := os.ReadFile(l.cfg.Path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRecoverTornAndMissingNewline(t *testing.T) {
	for _, tc := range []struct {
		name string
		cut  int // bytes removed from the end of a 2-entry file
	}{{"torn line", 20}, {"newline only", 1}} {
		path := filepath.Join(t.TempDir(), "l.jsonl")
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		cfg := contracts.LedgerConfig{Path: path}
		l, _ := Open(cfg, key, contracts.RedactionConfig{})
		l.Append(t.Context(), entry(1, `{}`, `null`))
		l.Append(t.Context(), entry(2, `{}`, `null`))
		l.Close()
		b, _ := os.ReadFile(path)
		os.WriteFile(path, b[:len(b)-tc.cut], 0o600)
		l, err := Open(cfg, key, contracts.RedactionConfig{})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if err := l.Append(t.Context(), entry(3, `{}`, `null`)); err != nil {
			t.Fatal(err)
		}
		l.Close()
		b, _ = os.ReadFile(path)
		if r := Verify(bytes.NewReader(b), key.Public().(ed25519.PublicKey)); !r.OK || r.Entries != 2 {
			t.Errorf("%s: %+v", tc.name, r)
		}
	}
}

func TestWriteFailureRollsBack(t *testing.T) {
	l, key := openT(t, contracts.LedgerConfig{}, contracts.RedactionConfig{})
	l.Append(t.Context(), entry(1, `{}`, `null`))
	before := fileOf(t, l)
	n := 0
	l.syncFn = func(f *os.File) error { // fails the append's sync only; the rollback sync works
		if n++; n == 1 {
			return errors.New("EIO")
		}
		return f.Sync()
	}
	if err := l.Append(t.Context(), entry(2, `{}`, `null`)); err == nil {
		t.Fatal("want error")
	}
	if !bytes.Equal(before, fileOf(t, l)) {
		t.Fatal("failed append left bytes behind")
	}
	l.syncFn = (*os.File).Sync
	if err := l.Append(t.Context(), entry(3, `{}`, `null`)); err != nil {
		t.Fatal(err)
	}
	if r := Verify(bytes.NewReader(fileOf(t, l)), key.Public().(ed25519.PublicKey)); !r.OK || r.Entries != 2 {
		t.Fatalf("%+v", r)
	}
}

func TestWriteFailureSticky(t *testing.T) {
	l, _ := openT(t, contracts.LedgerConfig{}, contracts.RedactionConfig{})
	l.syncFn = func(*os.File) error { return errors.New("EIO") }
	l.truncFn = func(*os.File, int64) error { return errors.New("stuck") }
	if err := l.Append(t.Context(), entry(1, `{}`, `null`)); err == nil {
		t.Fatal("want error")
	}
	l.syncFn = (*os.File).Sync
	if err := l.Append(t.Context(), entry(2, `{}`, `null`)); err == nil || !strings.Contains(err.Error(), "unrecoverable") {
		t.Fatalf("append after sticky: %v", err)
	}
	if _, err := l.Checkpoint(t.Context()); err == nil {
		t.Fatal("checkpoint after sticky should fail")
	}
}

func TestAutoCheckpointFailureKeepsEntryAcknowledged(t *testing.T) {
	l, _ := openT(t, contracts.LedgerConfig{CheckpointEvery: 1}, contracts.RedactionConfig{})
	calls := 0
	l.syncFn = func(f *os.File) error {
		if calls++; calls == 2 { // the checkpoint line
			return errors.New("EIO")
		}
		return f.Sync()
	}
	if err := l.Append(t.Context(), entry(1, `{}`, `null`)); err != nil {
		t.Fatalf("entry was written, Append must succeed: %v", err)
	}
	rep, _ := l.Verify(t.Context())
	if !rep.OK || rep.Entries != 1 || rep.Checkpoints != 0 {
		t.Fatalf("%+v", rep)
	}
}

func TestVerifyRequiresCanonicalLines(t *testing.T) {
	lines, key := build(t)
	pub := key.Public().(ed25519.PublicKey)
	dup := append([]string{}, lines...)
	dup[12] = strings.Replace(dup[12], `"type":"entry"`, `"type":"entry","outcome":"denied","type":"entry"`, 1)
	if r := check(dup, pub); r.OK || r.Line != 13 || r.Reason != "bad_json" {
		t.Errorf("duplicate key: %+v", r)
	}
	var out bytes.Buffer
	json.Indent(&out, []byte(lines[12]), "", " ")
	re := append(append([]string{}, lines[:12]...), out.String())
	if r := check(re, pub); r.OK || r.Line != 13 || r.Reason != "bad_json" {
		t.Errorf("reformatted: %+v", r)
	}
}

func TestRedactFailsClosedOnDepth(t *testing.T) {
	l, _ := openT(t, contracts.LedgerConfig{}, contracts.RedactionConfig{})
	deep := `{"password":"hunter2","x":` + strings.Repeat("[", 10001) + strings.Repeat("]", 10001) + `}`
	got := l.Redact(json.RawMessage(deep))
	if string(got) != `"[REDACTED]"` {
		t.Errorf("got %.40s", got)
	}
}

func TestLoadKeyRejectsMismatchedHalf(t *testing.T) {
	_, a, _ := ed25519.GenerateKey(rand.Reader)
	_, b, _ := ed25519.GenerateKey(rand.Reader)
	bad := append(append([]byte{}, a[:32]...), b[32:]...)
	p := filepath.Join(t.TempDir(), "k")
	os.WriteFile(p, []byte(hex.EncodeToString(bad)+"\n"), 0o600)
	if _, err := LoadKey(p); err == nil {
		t.Fatal("mismatched key accepted")
	}
}

func TestRollbackSyncFailureSticky(t *testing.T) {
	l, _ := openT(t, contracts.LedgerConfig{}, contracts.RedactionConfig{})
	l.syncFn = func(*os.File) error { return errors.New("EIO") } // rollback sync fails too
	l.Append(t.Context(), entry(1, `{}`, `null`))
	l.syncFn = (*os.File).Sync
	if err := l.Append(t.Context(), entry(2, `{}`, `null`)); err == nil || !strings.Contains(err.Error(), "unrecoverable") {
		t.Fatalf("want sticky error, got %v", err)
	}
}

func TestOpenLeavesNonLedgerFileIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	orig := []byte("rules:\n  - id: a\n  - id: b")
	os.WriteFile(path, orig, 0o600)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	if l, err := Open(contracts.LedgerConfig{Path: path}, key, contracts.RedactionConfig{}); err == nil {
		l.Close()
		t.Fatal("Open accepted a YAML file")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, orig) {
		t.Fatalf("file modified: %q", got)
	}
}

func TestOpenNoNewlineFiles(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	for _, in := range []string{`{"agent":{"id":"a"}}`, "plain text no newline"} {
		path := filepath.Join(t.TempDir(), "f")
		os.WriteFile(path, []byte(in), 0o600)
		if l, err := Open(contracts.LedgerConfig{Path: path}, key, contracts.RedactionConfig{}); err == nil {
			l.Close()
			t.Errorf("%q: Open succeeded", in)
		}
		if got, _ := os.ReadFile(path); string(got) != in {
			t.Errorf("%q: file modified to %q", in, got)
		}
	}
}

func TestTornFirstEntryRecovers(t *testing.T) {
	l, key := openT(t, contracts.LedgerConfig{}, contracts.RedactionConfig{})
	l.Append(t.Context(), entry(1, `{}`, `null`))
	b := fileOf(t, l)
	if !bytes.HasPrefix(b, []byte(firstLinePrefix)) {
		t.Fatalf("first line %.40s does not start with firstLinePrefix", b)
	}
	l.Close()
	os.WriteFile(l.cfg.Path, b[:len(b)/2], 0o600)
	l2, err := Open(l.cfg, key, contracts.RedactionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if fi, _ := os.Stat(l.cfg.Path); fi.Size() != 0 {
		t.Errorf("size %d, want 0", fi.Size())
	}
	if err := l2.Append(t.Context(), entry(2, `{}`, `null`)); err != nil {
		t.Fatal(err)
	}
}

type errAfter struct {
	data string
	pos  int
}

func (r *errAfter) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, errors.New("disk on fire")
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func TestVerifyReadError(t *testing.T) {
	lines, key := build(t)
	// error partway through line 3
	cut := len(lines[0]) + len(lines[1]) + 2 + 10
	r := Verify(&errAfter{data: strings.Join(lines, "\n")[:cut]}, key.Public().(ed25519.PublicKey))
	if r.OK || r.Line != 3 || r.Reason != "read_error" {
		t.Fatalf("%+v", r)
	}
}

func TestAppendInputResponses(t *testing.T) {
	l, key := openT(t, contracts.LedgerConfig{}, contracts.RedactionConfig{})
	raw := `{"q1":{"password":"hunter2","ok":1}}`
	e := entry(1, `{}`, `null`)
	e.Action.InputResponses, e.Action.RequestState = json.RawMessage(raw), "state-xyz"
	if err := l.Append(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	if want, _ := canonHash([]byte(raw)); e.Action.InputResponsesHash != want {
		t.Error("input_responses_hash is not over raw value")
	}
	if strings.Contains(string(e.Action.InputResponses), "hunter2") || e.Action.RequestState != "state-xyz" {
		t.Errorf("stored: %s %q", e.Action.InputResponses, e.Action.RequestState)
	}
	plain := entry(2, `{}`, `null`)
	if err := l.Append(t.Context(), plain); err != nil {
		t.Fatal(err)
	}
	lines := mustLines(t, l.cfg.Path)
	for _, k := range []string{"input_responses", "input_responses_hash", "request_state"} {
		if !strings.Contains(lines[0], `"`+k+`"`) || strings.Contains(lines[1], `"`+k+`"`) {
			t.Errorf("%s: present/absent wrong", k)
		}
	}
	if r := check(lines, key.Public().(ed25519.PublicKey)); !r.OK {
		t.Fatalf("%+v", r)
	}
}

func TestErrStickyAndStderrOnce(t *testing.T) {
	l, _ := openT(t, contracts.LedgerConfig{}, contracts.RedactionConfig{})
	var buf bytes.Buffer
	l.stderr = &buf
	if l.Err() != nil {
		t.Fatal("healthy ledger has Err")
	}
	l.syncFn = func(*os.File) error { return errors.New("EIO") }
	l.truncFn = func(*os.File, int64) error { return errors.New("stuck") }
	l.Append(t.Context(), entry(1, `{}`, `null`))
	if l.Err() == nil || !strings.Contains(l.Err().Error(), "unrecoverable") {
		t.Fatalf("Err = %v", l.Err())
	}
	first := buf.String()
	if !strings.HasPrefix(first, "agentgw ledger: unrecoverable write failure, refusing all calls: ") || strings.Count(first, "\n") != 1 {
		t.Fatalf("stderr = %q", first)
	}
	l.Append(t.Context(), entry(2, `{}`, `null`))
	l.Checkpoint(t.Context())
	if buf.String() != first || l.Err() == nil {
		t.Fatalf("later calls wrote stderr or cleared Err: %q", buf.String())
	}
}

func TestResultErrorRedaction(t *testing.T) {
	l, _ := openT(t, contracts.LedgerConfig{}, contracts.RedactionConfig{})
	e := entry(1, `{}`, `null`)
	e.Result.Error = "upstream said: Bearer abc.def-123 rejected"
	fixed := entry(2, `{}`, `null`)
	fixed.Result.Error = "agentgw: denied by policy: denied by rule no-destructive"
	for _, x := range []*contracts.Entry{e, fixed} {
		if err := l.Append(t.Context(), x); err != nil {
			t.Fatal(err)
		}
	}
	if e.Result.Error != "upstream said: [REDACTED] rejected" {
		t.Errorf("got %q", e.Result.Error)
	}
	if fixed.Result.Error != "agentgw: denied by policy: denied by rule no-destructive" {
		t.Errorf("fixed text changed: %q", fixed.Result.Error)
	}
}
