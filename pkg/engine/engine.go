// Package engine fans IOC lookups out to all sources concurrently.
package engine

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

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
	// scan: "added", "updated", "matched" or "" (set by zuhan.Scanner).
	LocalDB string `json:"local_db,omitempty"`
}

// Options tunes a scan.
type Options struct {
	Timeout  time.Duration // per source request
	Parallel int           // IOCs processed at once
	Progress func(done, total int)
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
			reports[idx] = scanOne(ctx, srcs, i, opt.Timeout)
			if opt.Progress != nil {
				opt.Progress(int(atomic.AddInt32(&done, 1)), len(iocs))
			}
		}(idx, i)
	}
	wg.Wait()
	return reports
}

func scanOne(ctx context.Context, srcs []sources.Source, i ioc.IOC, timeout time.Duration) Report {
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
			results[k] = r
		}(k, s)
	}
	wg.Wait()
	rep.Results = results
	rep.Verdict, rep.Flagged, rep.Queried = Verdict(results)
	return rep
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
