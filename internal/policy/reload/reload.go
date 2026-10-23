// Package reload wraps a compiled policy so that an edited policy file takes
// effect on the next Decide call (docs/cli.md "Policy reload").
package reload

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/midspan-dev/agentgw/internal/policy"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

type stamp struct {
	mtime time.Time
	size  int64
}

// Decider implements contracts.Decider over the policy file at path.
type Decider struct {
	path     string
	stderr   io.Writer
	currency string
	limits   []contracts.BudgetLimit // startup limits: the only ones the budget store knows

	active atomic.Pointer[policy.Policy]

	mu        sync.Mutex // guards the fields below; never held across Decide
	seen      stamp
	warnedVer string
}

var _ contracts.Decider = (*Decider)(nil)

// Option configures a Decider.
type Option func(*Decider)

// WithCurrency sets the config currency; a reloaded policy with a limit in
// another currency gets the "budgets changed" line.
func WithCurrency(c string) Option { return func(d *Decider) { d.currency = c } }

// New wraps initial, the policy gateway() compiled from path at startup. It
// stats path once and does no other I/O. now is unused: change detection is by
// file stat, not by time; the parameter keeps the constructor shape stable.
func New(path string, initial *policy.Policy, stderr io.Writer, now func() time.Time, opts ...Option) *Decider {
	d := &Decider{path: path, stderr: stderr, limits: initial.Limits()}
	for _, o := range opts {
		o(d)
	}
	d.active.Store(initial)
	if fi, err := os.Stat(path); err == nil {
		d.seen = stamp{fi.ModTime(), fi.Size()}
	}
	return d
}

// Active returns the policy currently deciding.
func (d *Decider) Active() *policy.Policy { return d.active.Load() }

// Decide implements contracts.Decider.
func (d *Decider) Decide(ctx context.Context, in contracts.DecisionInput) (contracts.DecisionOutput, error) {
	d.check()
	return d.active.Load().Decide(ctx, in)
}

func (d *Decider) check() {
	d.mu.Lock()
	defer d.mu.Unlock()
	fi, err := os.Stat(d.path)
	var cur stamp
	if err == nil {
		cur = stamp{fi.ModTime(), fi.Size()}
		if cur == d.seen {
			return
		}
	} else if d.seen == (stamp{}) {
		return // this absence was already reported
	}
	d.seen = cur
	if err != nil {
		d.invalid(err)
		return
	}
	// shortcut: change detection is mtime+size, upgrade to a content hash if editors that preserve mtime show up
	src, err := os.ReadFile(d.path)
	var p *policy.Policy
	if err == nil {
		if filepath.Ext(d.path) == ".cedar" {
			p, err = policy.LoadCedar(src)
		} else {
			p, err = policy.Compile(src)
		}
	}
	if err != nil {
		d.invalid(err)
		return
	}
	d.active.Store(p)
	fmt.Fprintf(d.stderr, "agentgw: policy reloaded: version %.8s from %s\n", p.Version(), d.path)
	d.checkBudgets(p)
}

func (d *Decider) invalid(err error) {
	fmt.Fprintf(d.stderr, "agentgw: %s invalid, keeping version %.8s: %v\n", filepath.Base(d.path), d.active.Load().Version(), err)
}

func (d *Decider) checkBudgets(p *policy.Policy) {
	changed := !reflect.DeepEqual(p.Limits(), d.limits)
	for _, l := range p.Limits() {
		changed = changed || (d.currency != "" && l.Limit.Currency != d.currency)
	}
	if changed && d.warnedVer != p.Version() {
		d.warnedVer = p.Version()
		fmt.Fprintln(d.stderr, "agentgw: policy budgets changed; restart the gateway to apply them")
	}
}
