package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaBase = "https://agentgw.dev/schemas/v1/"

// Each document schema, its example, and the Go type that must mirror it.
var documents = []struct {
	name string
	typ  any
}{
	{"decision-input", &DecisionInput{}},
	{"decision-output", &DecisionOutput{}},
	{"ledger-entry", &Entry{}},
	{"checkpoint", &Checkpoint{}},
	{"config", &Config{}},
	{"policy", &PolicyFile{}},
}

func compiler(t *testing.T) *jsonschema.Compiler {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	files, err := filepath.Glob("../../contracts/schemas/*.schema.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob schemas: %v (%d files)", err, len(files))
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytesReader(raw))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if err := c.AddResource(schemaBase+filepath.Base(f), doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	return c
}

func TestExamplesValidateAndRoundTrip(t *testing.T) {
	c := compiler(t)
	for _, d := range documents {
		t.Run(d.name, func(t *testing.T) {
			schema, err := c.Compile(schemaBase + d.name + ".schema.json")
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			raw, err := os.ReadFile("../../contracts/examples/" + d.name + ".example.json")
			if err != nil {
				t.Fatal(err)
			}
			doc, err := jsonschema.UnmarshalJSON(bytesReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(doc); err != nil {
				t.Fatalf("example does not validate: %v", err)
			}

			// Go type must mirror the schema: example -> type -> JSON must be identical.
			if err := json.Unmarshal(raw, d.typ); err != nil {
				t.Fatalf("unmarshal into %T: %v", d.typ, err)
			}
			back, err := json.Marshal(d.typ)
			if err != nil {
				t.Fatal(err)
			}
			var want, got any
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(back, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("round trip through %T changed the document:\nwant %s\ngot  %s", d.typ, raw, back)
			}
			backDoc, err := jsonschema.UnmarshalJSON(bytesReader(back))
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(backDoc); err != nil {
				t.Fatalf("Go-marshalled form does not validate: %v", err)
			}
		})
	}
}

func TestCallErrorOutcome(t *testing.T) {
	cases := map[EntryOutcome]error{
		EntryDenied: ErrDenied, EntryBudgetExceeded: ErrBudgetExceeded,
		EntryApprovalDenied: ErrApprovalDenied, EntryApprovalTimeout: ErrApprovalTimeout,
		EntryError: os.ErrNotExist,
	}
	for want, err := range cases {
		if got := (&CallError{Err: err}).Outcome(); got != want {
			t.Errorf("%v: got %s want %s", err, got, want)
		}
	}
}
