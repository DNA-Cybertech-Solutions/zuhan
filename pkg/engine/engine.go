// Package engine fans IOC lookups out to all sources concurrently.
package engine

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/attack"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
)

// Report is the combined result for one IOC.
type Report struct {
	IOC       ioc.IOC          `json:"ioc"`
	Verdict   sources.Status   `json:"verdict"`
	Flagged   int              `json:"flagged"`
	Queried   int              `json:"queried"`
	Results   []sources.Result `json:"results"`
	QueriedAt time.Time        `json:"queried_at"`
	// LocalDB describes what happened in the local IOC database after the
	// scan: "added", "updated", "matched", "skipped_benign",
	// "skipped_threshold" or "" (set by zuhan.Scanner).
	LocalDB string `json:"local_db,omitempty"`

	// FirstSeen is the earliest time any source reported the IOC.
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	// New: first reported within Options.NewDays and flagged malicious or
	// suspicious — a fresh threat worth attention.
	New bool `json:"new,omitempty"`
	// Unknown: every intel source that answered had no record of it and no
	// list gave it any context.
	Unknown bool `json:"unknown,omitempty"`
	// Benign lists allow-list hits (warninglists, OTX allow-list,
	// GreyNoise RIOT). With an allow-list hit, a suspicious verdict or a
	// malicious one from a single source is lowered to clean
	// (Downgraded=true); two or more sources saying malicious still win.
	Benign     []string `json:"benign,omitempty"`
	Downgraded bool     `json:"downgraded,omitempty"`
	// Context lists neutral labels (Tor exit node, scanner, newly
	// registered domain…).
	Context []string `json:"context,omitempty"`
	// Attack is the MITRE ATT&CK techniques sources associated with it.
	Attack []attack.Hit `json:"attack,omitempty"`
}

// Options tunes a scan.
type Options struct {
	Timeout  time.Duration // per source request
	Parallel int           // IOCs processed at once
	Progress func(done, total int)
	// NewDays is the window for Report.New (default 7; negative disables).
	NewDays int
	Now     func() time.Time
}

// Scan queries every supporting source for every IOC. Order of the
// returned reports matches iocs; order of results matches srcs.
func Scan(ctx context.Context, srcs []sources.Source, iocs []ioc.IOC, opt Options) []Report {
	if opt.Parallel < 1 {
		opt.Parallel = 4
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 25 * time.Second
	}
	reports := make([]Report, len(iocs))
	sem := make(chan struct{}, opt.Parallel)
	var wg sync.WaitGroup
	var done int32
	for idx, i := range iocs {
		wg.Add(1)
		go func(idx int, i ioc.IOC) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			reports[idx] = scanOne(ctx, srcs, i, opt)
			if opt.Progress != nil {
				opt.Progress(int(atomic.AddInt32(&done, 1)), len(iocs))
			}
		}(idx, i)
	}
	wg.Wait()
	return reports
}

func scanOne(ctx context.Context, srcs []sources.Source, i ioc.IOC, opt Options) Report {
	timeout := opt.Timeout
	rep := Report{IOC: i, QueriedAt: time.Now().UTC()}
	var applicable []sources.Source
	for _, s := range srcs {
		if s.Supports(i.Type) {
			applicable = append(applicable, s)
		}
	}
	results := make([]sources.Result, len(applicable))
	var wg sync.WaitGroup
	for k, s := range applicable {
		if s.RequiresKey() && !s.Configured() {
			results[k] = sources.Result{Source: s.Name(), Status: sources.StatusSkipped, Summary: "API key not configured"}
			continue
		}
		wg.Add(1)
		go func(k int, s sources.Source) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			start := time.Now()
			r := safeQuery(cctx, s, i)
			r.DurationMS = time.Since(start).Milliseconds()
			if r.Source == "" {
				r.Source = s.Name()
			}
			if l, ok := s.(sources.LocalOnly); ok && l.LocalOnly() {
				r.LocalOnly = true
			}
			results[k] = r
		}(k, s)
	}
	wg.Wait()
	rep.Results = results
	Analyze(&rep, opt)
	return rep
}

// Analyze derives the verdict and every summary field of rep from its
// results. Scan calls it; it is exported for callers that build reports
// themselves.
func Analyze(rep *Report, opt Options) {
	rep.Verdict, rep.Flagged, rep.Queried = Verdict(rep.Results)
	rep.FirstSeen, rep.New, rep.Unknown, rep.Downgraded = nil, false, false, false
	rep.Benign, rep.Context, rep.Attack = nil, nil, nil

	var col attack.Collector
	known, notFound := false, 0
	for _, r := range rep.Results {
		switch r.Status {
		case sources.StatusMalicious, sources.StatusSuspicious, sources.StatusClean:
			known = true
		case sources.StatusNotFound:
			if !r.LocalOnly {
				notFound++
			}
		}
		if r.Benign != "" {
			rep.Benign = addOnce(rep.Benign, r.Benign)
		}
		if r.Context != "" {
			rep.Context = addOnce(rep.Context, r.Context)
		}
		if r.FirstSeen != nil && (rep.FirstSeen == nil || r.FirstSeen.Before(*rep.FirstSeen)) {
			t := *r.FirstSeen
			rep.FirstSeen = &t
		}
		for _, t := range r.Techniques {
			col.Add(t.ID, t.Name, r.Source, "")
		}
	}
	rep.Attack = col.Hits()
	if len(rep.Attack) == 0 {
		rep.Attack = nil
	}

	// Allow-listed: a suspicious verdict, or a malicious one from a single
	// source, is treated as a false positive. Two or more sources calling
	// it malicious still win (a hijacked well-known host).
	if len(rep.Benign) > 0 && (rep.Verdict == sources.StatusSuspicious ||
		(rep.Verdict == sources.StatusMalicious && rep.Flagged <= 1)) {
		rep.Verdict = sources.StatusClean
		rep.Downgraded = true
	}
	rep.Unknown = !known && notFound > 0 && len(rep.Benign) == 0 && len(rep.Context) == 0

	days := opt.NewDays
	if days == 0 {
		days = 7
	}
	if days > 0 && rep.FirstSeen != nil &&
		(rep.Verdict == sources.StatusMalicious || rep.Verdict == sources.StatusSuspicious) {
		now := time.Now()
		if opt.Now != nil {
			now = opt.Now()
		}
		rep.New = now.Sub(*rep.FirstSeen) <= time.Duration(days)*24*time.Hour
	}
}

// AgeDays is how many whole days ago the IOC was first reported (-1 if unknown).
func (r Report) AgeDays(now time.Time) int {
	if r.FirstSeen == nil {
		return -1
	}
	return int(now.Sub(*r.FirstSeen).Hours() / 24)
}

func addOnce(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func safeQuery(ctx context.Context, s sources.Source, i ioc.IOC) (r sources.Result) {
	defer func() {
		if p := recover(); p != nil {
			r = sources.Result{Source: s.Name(), Status: sources.StatusError, Error: fmt.Sprintf("internal error: %v", p)}
		}
	}()
	return s.Query(ctx, i)
}

// Verdict picks the most severe status among results and counts
// sources that flagged the IOC and sources that answered.
func Verdict(results []sources.Result) (v sources.Status, flagged, queried int) {
	best := -1
	errs := 0
	for _, r := range results {
		switch r.Status {
		case sources.StatusSkipped:
			continue
		case sources.StatusError:
			errs++
			continue
		case sources.StatusMalicious, sources.StatusSuspicious:
			flagged++
		}
		queried++
		if sev := r.Status.Severity(); sev > best {
			best, v = sev, r.Status
		}
	}
	if best < 0 {
		if errs > 0 {
			return sources.StatusError, 0, 0
		}
		return sources.StatusSkipped, 0, 0
	}
	return v, flagged, queried
}
