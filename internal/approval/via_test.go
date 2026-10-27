package approval

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

func TestApproveDenyVia(t *testing.T) {
	s, pub := open(t)
	ctx := context.Background()
	via := contracts.DecisionVia{Surface: "github", User: "alice", URL: "https://github.com/o/r/issues/1#issuecomment-2"}

	id, _ := s.Request(ctx, req(60))
	if err := s.ApproveVia(ctx, id, "h1", via); err != nil {
		t.Fatal(err)
	}
	d, err := s.Wait(ctx, id, func(string) {})
	if err != nil || d.Via == nil || *d.Via != via || d.Grant != nil {
		t.Fatalf("approve via: %+v %v", d, err)
	}
	verify(t, pub, d)

	id, _ = s.Request(ctx, req(60))
	if err := s.DenyVia(ctx, id, "bad", "no", via); !errors.Is(err, ErrArgsHashMismatch) {
		t.Fatalf("hash: %v", err)
	}
	if err := s.DenyVia(ctx, id, "h1", "no", via); err != nil {
		t.Fatal(err)
	}
	d, err = s.Wait(ctx, id, func(string) {})
	if !errors.Is(err, contracts.ErrApprovalDenied) || d.Via == nil || *d.Via != via || d.Reason != "no" {
		t.Fatalf("deny via: %+v %v", d, err)
	}
	verify(t, pub, d)

	id, _ = s.Request(ctx, req(60))
	if err := s.Approve(ctx, id, "h1", "", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if d, _ = s.Wait(ctx, id, func(string) {}); d.Via != nil {
		t.Fatalf("Approve must leave Via nil: %+v", d.Via)
	}
}
