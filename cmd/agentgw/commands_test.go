package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRegisteredCommand(t *testing.T) {
	commands["fake"] = func(_ context.Context, args []string, out io.Writer) error {
		_, err := out.Write([]byte("fake " + strings.Join(args, ",")))
		return err
	}
	old := extraUsage
	extraUsage = append(extraUsage, "  agentgw fake")
	t.Cleanup(func() { delete(commands, "fake"); extraUsage = old })

	var buf bytes.Buffer
	if err := run(context.Background(), []string{"fake", "a", "b"}, &buf); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "fake a,b" {
		t.Fatalf("got %q", buf.String())
	}
	if err := run(context.Background(), []string{"nope"}, &buf); !errors.Is(err, errUsage) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(usageText(), "  agentgw fake\n") {
		t.Fatalf("usage missing extra line: %q", usageText())
	}
}
