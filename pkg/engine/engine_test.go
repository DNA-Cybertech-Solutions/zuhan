package engine_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/engine"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/report"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
)

type fake struct {
	id     string
	status sources.Status
	key    bool
	panics bool
	sleep  time.Duration
}

func (f *fake) ID() string               { return f.id }
func (f *fake) Name() string             { return f.id }
func (f *fake) Supports(t ioc.Type) bool { return true }
func (f *fake) RequiresKey() bool        { return f.key }
func (f *fake) Configured() bool         { return false }
func (f *fake) Query(ctx context.Context, i ioc.IOC) sources.Result {
	if f.panics {
		panic("boom")
	}
	if f.sleep > 0 {
		select {
		case <-time.After(f.sleep):
		case <-ctx.Done():
			return sources.Result{Status: sources.StatusError, Error: "timeout"}
		}
	}
	return sources.Result{Status: f.status, Summary: "ok"}
}

func TestScan(t *testing.T) {
	srcs := []sources.Source{
		&fake{id: "a", status: sources.StatusClean},
		&fake{id: "b", status: sources.StatusMalicious},
		&fake{id: "c", key: true},
		&fake{id: "d", panics: true},
		&fake{id: "e", sleep: time.Second},
	}
	reps := engine.Scan(context.Background(), srcs, []ioc.IOC{ioc.Parse("8.8.8.8"), ioc.Parse("evil.com")},
		engine.Options{Timeout: 50 * time.Millisecond})
	if len(reps) != 2 {
		t.Fatal("want 2 reports")
	}
	r := reps[0]
	if r.Verdict != sources.StatusMalicious || r.Flagged != 1 || r.Queried != 2 {
		t.Fatalf("verdict %v flagged %d queried %d", r.Verdict, r.Flagged, r.Queried)
	}
	want := []sources.Status{sources.StatusClean, sources.StatusMalicious, sources.StatusSkipped, sources.StatusError, sources.StatusError}
	for k, res := range r.Results {
		if res.Status != want[k] || res.Source != srcs[k].Name() {
			t.Errorf("result %d: %+v", k, res)
		}
	}

	for _, f := range report.Formats {
		var buf bytes.Buffer
		if err := report.Write(&buf, f, reps, report.Options{Verbose: true, Version: "test"}); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if !strings.Contains(buf.String(), "evil.com") {
			t.Errorf("%s output missing IOC", f)
		}
	}
}

func TestVerdictAllErrors(t *testing.T) {
	v, _, _ := engine.Verdict([]sources.Result{{Status: sources.StatusError}, {Status: sources.StatusSkipped}})
	if v != sources.StatusError {
		t.Fatalf("got %v", v)
	}
}
