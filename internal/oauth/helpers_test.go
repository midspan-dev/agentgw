package oauth

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

// passthrough is an Interceptor that forwards every call.
type passthrough struct{}

func (passthrough) Intercept(ctx context.Context, c *contracts.Call) (json.RawMessage, error) {
	return c.Forward(ctx)
}

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func waitFor(t *testing.T, addr string) {
	for range 100 {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("proxy did not start")
}
