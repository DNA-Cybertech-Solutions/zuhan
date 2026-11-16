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

func TestAnalyze(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	recent, old := now.Add(-48*time.Hour), now.AddDate(-1, 0, 0)
	opt := engine.Options{Now: func() time.Time { return now }}
	an := func(rs ...sources.Result) engine.Report {
		rep := engine.Report{Results: rs}
		engine.Analyze(&rep, opt)
		return rep
	}

	rep := an(sources.Result{Source: "A", Status: sources.StatusMalicious, FirstSeen: &old,
		Techniques: []sources.Technique{{ID: "T1105"}}},
		sources.Result{Source: "B", Status: sources.StatusMalicious, FirstSeen: &recent,
			Techniques: []sources.Technique{{ID: "T1105"}, {ID: "T1059.001"}}})
	if rep.New || !rep.FirstSeen.Equal(old) {
		t.Fatalf("earliest first seen wins: new=%v first=%v", rep.New, rep.FirstSeen)
	}
	if len(rep.Attack) != 2 {
		t.Fatalf("attack %+v", rep.Attack)
	}
	for _, h := range rep.Attack {
		if h.ID == "T1105" && len(h.Sources) != 2 {
			t.Fatalf("sources merged: %+v", h)
		}
	}

	if rep = an(sources.Result{Status: sources.StatusMalicious, FirstSeen: &recent}); !rep.New {
		t.Fatal("recent malicious should be NEW")
	}
	if rep = an(sources.Result{Status: sources.StatusInfo, FirstSeen: &recent}); rep.New {
		t.Fatal("NEW needs a malicious/suspicious verdict")
	}
	if rep := (func() engine.Report {
		r := engine.Report{Results: []sources.Result{{Status: sources.StatusMalicious, FirstSeen: &recent}}}
		engine.Analyze(&r, engine.Options{Now: opt.Now, NewDays: -1})
		return r
	})(); rep.New {
		t.Fatal("NewDays<0 disables NEW")
	}

	rep = an(sources.Result{Status: sources.StatusSuspicious}, sources.Result{Status: sources.StatusInfo, Benign: "public DNS"})
	if rep.Verdict != sources.StatusClean || !rep.Downgraded {
		t.Fatalf("suspicious+benign → clean: %+v", rep)
	}
	rep = an(sources.Result{Status: sources.StatusMalicious}, sources.Result{Status: sources.StatusInfo, Benign: "public DNS"})
	if rep.Verdict != sources.StatusClean || !rep.Downgraded {
		t.Fatal("a single malicious source on an allow-listed IOC is a false positive")
	}
	rep = an(sources.Result{Status: sources.StatusMalicious}, sources.Result{Status: sources.StatusMalicious},
		sources.Result{Status: sources.StatusInfo, Benign: "public DNS"})
	if rep.Verdict != sources.StatusMalicious || rep.Downgraded {
		t.Fatal("two malicious sources win over an allow-list")
	}

	rep = an(sources.Result{Status: sources.StatusNotFound}, sources.Result{Status: sources.StatusNotFound, LocalOnly: true})
	if !rep.Unknown {
		t.Fatal("not found everywhere → unknown")
	}
	if rep = an(sources.Result{Status: sources.StatusNotFound, LocalOnly: true}); rep.Unknown {
		t.Fatal("local-only misses alone are not 'unknown'")
	}
	if rep = an(sources.Result{Status: sources.StatusNotFound}, sources.Result{Status: sources.StatusInfo, Context: "Tor exit node"}); rep.Unknown {
		t.Fatal("context means it is known")
	}
	if rep = an(sources.Result{Status: sources.StatusNotFound}, sources.Result{Status: sources.StatusError}); !rep.Unknown {
		t.Fatal("errors do not prevent unknown")
	}

	var buf bytes.Buffer
	reps := []engine.Report{an(sources.Result{Source: "A", Status: sources.StatusMalicious, FirstSeen: &recent,
		Techniques: []sources.Technique{{ID: "T1059.001"}}})}
	reps[0].IOC = ioc.Parse("evil.com")
	for _, f := range []string{"table", "md", "html", "csv", "json"} {
		buf.Reset()
		if err := report.Write(&buf, f, reps, report.Options{Generated: now}); err != nil {
			t.Fatal(f, err)
		}
		if !strings.Contains(buf.String(), "T1059.001") {
			t.Fatalf("%s report lacks ATT&CK: %s", f, buf.String())
		}
		if f != "json" && f != "csv" && !strings.Contains(buf.String(), "NEW") {
			t.Fatalf("%s report lacks NEW", f)
		}
	}
}
