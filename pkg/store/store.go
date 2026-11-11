// Package store keeps a persistent, local list of known-bad IOCs.
//
// The Store interface is the extension point: the bundled FileStore keeps
// everything in one JSON file, but any backend (SQLite, Redis, a MISP
// instance, …) can be plugged in by implementing the same five methods.
package store

import (
	"sort"
	"strings"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
)

// Origin tells how an entry got into the list.
type Origin string

const (
	OriginManual Origin = "manual" // added by a person (db add)
	OriginAuto   Origin = "auto"   // added automatically after a malicious scan result
	OriginImport Origin = "import" // bulk import from a file / dump
)

// Entry is one IOC in the local list.
type Entry struct {
	Value     string         `json:"value"`
	Type      ioc.Type       `json:"type"`
	Verdict   sources.Status `json:"verdict"`
	Origin    Origin         `json:"origin"`
	Tags      []string       `json:"tags,omitempty"`
	Sources   []string       `json:"sources,omitempty"` // which intel sources flagged it
	Note      string         `json:"note,omitempty"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
	Hits      int            `json:"hits"` // how many times it was looked up / re-reported
}

// Key is the unique identity of the entry.
func (e Entry) Key() string { return string(e.Type) + ":" + e.Value }

// IOC returns the entry as an ioc.IOC.
func (e Entry) IOC() ioc.IOC { return ioc.IOC{Raw: e.Value, Value: e.Value, Type: e.Type} }

// Filter narrows List results. Zero value = everything.
type Filter struct {
	Types  []ioc.Type
	Origin Origin
	Search string // case-insensitive substring of value, tags or note
}

// Match reports whether e passes the filter.
func (f Filter) Match(e Entry) bool {
	if len(f.Types) > 0 {
		ok := false
		for _, t := range f.Types {
			if e.Type == t {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if f.Origin != "" && e.Origin != f.Origin {
		return false
	}
	if f.Search != "" {
		q := strings.ToLower(f.Search)
		hay := strings.ToLower(e.Value + " " + strings.Join(e.Tags, " ") + " " + e.Note + " " + strings.Join(e.Sources, " "))
		if !strings.Contains(hay, q) {
			return false
		}
	}
	return true
}

// Store is a persistent IOC list.
type Store interface {
	// Get returns the entry for (t, value), if present.
	Get(t ioc.Type, value string) (Entry, bool, error)
	// Put inserts entries or merges them into existing ones (see Merge).
	Put(entries ...Entry) (added, updated int, err error)
	// Touch records a lookup hit on existing entries (Hits++, LastSeen=now).
	// Unknown IOCs are ignored.
	Touch(at time.Time, iocs ...ioc.IOC) error
	// Delete removes entries; returns how many existed.
	Delete(iocs ...ioc.IOC) (int, error)
	// List returns matching entries sorted by type, then value.
	List(f Filter) ([]Entry, error)
}

// Merge combines an incoming entry into an existing one:
// tags/sources are unioned, the most severe verdict wins, a non-empty
// note replaces the old one, first/last seen widen, hits add up, and
// the original origin is kept.
func Merge(old, in Entry) Entry {
	out := old
	if in.Verdict.Severity() > old.Verdict.Severity() {
		out.Verdict = in.Verdict
	}
	out.Tags = union(old.Tags, in.Tags)
	out.Sources = union(old.Sources, in.Sources)
	if in.Note != "" {
		out.Note = in.Note
	}
	if !in.FirstSeen.IsZero() && (out.FirstSeen.IsZero() || in.FirstSeen.Before(out.FirstSeen)) {
		out.FirstSeen = in.FirstSeen
	}
	if in.LastSeen.After(out.LastSeen) {
		out.LastSeen = in.LastSeen
	}
	out.Hits += in.Hits
	if out.Origin == "" {
		out.Origin = in.Origin
	}
	return out
}

// Normalize validates and fills defaults; ok=false if the value is not a
// supported IOC.
func Normalize(e Entry, now time.Time) (Entry, bool) {
	p := ioc.Parse(e.Value)
	if !p.Type.Valid() {
		return e, false
	}
	e.Value, e.Type = p.Value, p.Type
	if e.Verdict != sources.StatusSuspicious {
		e.Verdict = sources.StatusMalicious
	}
	if e.Origin == "" {
		e.Origin = OriginManual
	}
	if e.FirstSeen.IsZero() {
		e.FirstSeen = now
	}
	if e.LastSeen.IsZero() {
		e.LastSeen = e.FirstSeen
	}
	e.Tags = union(nil, e.Tags)
	e.Sources = union(nil, e.Sources)
	return e, true
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		s = strings.TrimSpace(s)
		k := strings.ToLower(s)
		if s == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}

func sortEntries(es []Entry) {
	order := map[ioc.Type]int{}
	for i, t := range ioc.Types {
		order[t] = i
	}
	sort.Slice(es, func(i, j int) bool {
		if es[i].Type != es[j].Type {
			return order[es[i].Type] < order[es[j].Type]
		}
		return es[i].Value < es[j].Value
	})
}
