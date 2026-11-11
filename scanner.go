// Package zuhan is a small framework for looking up Indicators of
// Compromise in many threat-intelligence sources at once, keeping a local
// list of known-bad IOCs, and pulling IOCs out of raw dumps.
//
// Extension points (all plain Go interfaces):
//
//   - sources.Source — add a new intel provider (Scanner.Use)
//   - store.Store    — swap the local IOC list backend (FileStore is bundled)
//
// Typical use:
//
//	st, _ := store.Open("iocdb.json")
//	sc := zuhan.New(sources.Keys{VirusTotal: "..."}, st)
//	sc.Use(&MyCustomSource{})
//	reports, skipped, err := sc.ScanValues(ctx, "8.8.8.8", "evil.com")
package zuhan

import (
	"context"
	"io"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/engine"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/extract"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/store"
)

// SavePolicy controls what gets written to the local list after a scan.
type SavePolicy struct {
	Enabled           bool // add IOCs that external sources flagged as malicious
	IncludeSuspicious bool // also add suspicious ones
}

// Scanner ties sources, the local store and the scan engine together.
type Scanner struct {
	Sources []sources.Source
	Store   store.Store // nil = no local list
	Engine  engine.Options
	Save    SavePolicy
	Now     func() time.Time // for tests; defaults to time.Now
}

// New returns a Scanner with the local list (if st != nil) as the first
// source, followed by every built-in provider, and auto-save enabled.
func New(keys sources.Keys, st store.Store) *Scanner {
	s := &Scanner{Store: st, Save: SavePolicy{Enabled: true}}
	if st != nil {
		s.Sources = append(s.Sources, &store.LocalSource{Store: st})
	}
	s.Sources = append(s.Sources, sources.All(keys)...)
	return s
}

// Use registers additional sources (custom providers).
func (s *Scanner) Use(src ...sources.Source) { s.Sources = append(s.Sources, src...) }

// Scan looks up already-parsed IOCs and records results in the local list.
func (s *Scanner) Scan(ctx context.Context, iocs []ioc.IOC) ([]engine.Report, error) {
	reps := engine.Scan(ctx, s.Sources, iocs, s.Engine)
	if s.Store == nil {
		return reps, nil
	}
	return reps, Record(s.Store, reps, s.Save, s.now())
}

// ScanValues parses raw strings, scans the valid ones and returns the ones
// it could not recognise in skipped.
func (s *Scanner) ScanValues(ctx context.Context, values ...string) (reps []engine.Report, skipped []string, err error) {
	var iocs []ioc.IOC
	seen := map[string]bool{}
	for _, v := range values {
		i := ioc.Parse(v)
		if !i.Type.Valid() {
			skipped = append(skipped, v)
			continue
		}
		if !seen[i.Key()] {
			seen[i.Key()] = true
			iocs = append(iocs, i)
		}
	}
	reps, err = s.Scan(ctx, iocs)
	return reps, skipped, err
}

// ScanDump extracts IOCs from a raw dump (sandbox trace, log, API
// response…) and scans them.
func (s *Scanner) ScanDump(ctx context.Context, r io.Reader, opt extract.Options) ([]engine.Report, extract.Result, error) {
	ex, err := extract.FromReader(r, opt)
	if err != nil {
		return nil, ex, err
	}
	reps, err := s.Scan(ctx, ex.IOCs)
	return reps, ex, err
}

func (s *Scanner) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

// Record updates the local list from scan reports and sets
// Report.LocalDB on each one:
//
//   - "added"/"updated": external sources (anything but the local list)
//     flagged the IOC malicious (or suspicious, if the policy allows) and
//     it was written to the list, together with any MD5/SHA1/SHA256
//     siblings computed for a file;
//   - "matched": the IOC was already listed and only its hit counter and
//     last-seen time were updated.
//
// Entries are never removed or downgraded automatically.
func Record(st store.Store, reps []engine.Report, p SavePolicy, now time.Time) error {
	var put []store.Entry
	var touch []ioc.IOC
	type pending struct {
		idx int
		key string
	}
	var pend []pending

	existing := map[string]bool{}
	for k := range reps {
		rep := &reps[k]
		var ext []sources.Result
		localHit := false
		for _, r := range rep.Results {
			if r.Source == store.LocalSourceName {
				localHit = r.Status == sources.StatusMalicious || r.Status == sources.StatusSuspicious
				continue
			}
			ext = append(ext, r)
		}
		v, _, _ := engine.Verdict(ext)
		save := p.Enabled && (v == sources.StatusMalicious || (p.IncludeSuspicious && v == sources.StatusSuspicious))
		if !save {
			if localHit {
				if _, ok, _ := st.Get(rep.IOC.Type, rep.IOC.Value); ok {
					touch = append(touch, rep.IOC)
					rep.LocalDB = "matched"
				}
			}
			continue
		}

		var flaggedBy []string
		for _, r := range ext {
			if r.Status == sources.StatusMalicious || r.Status == sources.StatusSuspicious {
				flaggedBy = append(flaggedBy, r.Source)
			}
		}
		base := store.Entry{
			Verdict: v, Origin: store.OriginAuto, Sources: flaggedBy,
			FirstSeen: now, LastSeen: now, Hits: 1,
		}
		e := base
		e.Value, e.Type = rep.IOC.Value, rep.IOC.Type
		if _, ok, _ := st.Get(e.Type, e.Value); ok {
			existing[e.Key()] = true
		}
		put = append(put, e)
		pend = append(pend, pending{k, e.Key()})

		// a scanned file: also list its other hashes
		for _, h := range []struct {
			k string
			t ioc.Type
		}{{"md5", ioc.MD5}, {"sha1", ioc.SHA1}, {"sha256", ioc.SHA256}} {
			if val := rep.IOC.Meta[h.k]; val != "" && val != rep.IOC.Value {
				sib := base
				sib.Value, sib.Type = val, h.t
				sib.Note = "same file as " + rep.IOC.Value
				put = append(put, sib)
			}
		}
	}

	if len(put) > 0 {
		if _, _, err := st.Put(put...); err != nil {
			return err
		}
		for _, p := range pend {
			if existing[p.key] {
				reps[p.idx].LocalDB = "updated"
			} else {
				reps[p.idx].LocalDB = "added"
			}
		}
	}
	if len(touch) > 0 {
		return st.Touch(now, touch...)
	}
	return nil
}
