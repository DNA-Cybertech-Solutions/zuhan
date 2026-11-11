package store

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
)

// LocalSourceName is the display name of the local list in scan results.
const LocalSourceName = "Local IOC DB"

// LocalSource exposes a Store as a regular intel source, so the local list
// is checked in every scan alongside VirusTotal & co.
//
// Exact matches return the stored verdict. For URLs the host is also
// checked, and for domains/URL hosts every parent domain is checked
// (a listed evil.com flags login.evil.com as suspicious).
type LocalSource struct {
	Store Store
}

func (s *LocalSource) ID() string               { return "localdb" }
func (s *LocalSource) Name() string             { return LocalSourceName }
func (s *LocalSource) RequiresKey() bool        { return false }
func (s *LocalSource) Configured() bool         { return s.Store != nil }
func (s *LocalSource) Supports(t ioc.Type) bool { return t.Valid() }

func (s *LocalSource) Query(ctx context.Context, i ioc.IOC) sources.Result {
	r := sources.Result{Source: s.Name()}
	if s.Store == nil {
		r.Status = sources.StatusSkipped
		return r
	}
	e, ok, err := s.Store.Get(i.Type, i.Value)
	if err != nil {
		r.Status, r.Error = sources.StatusError, err.Error()
		return r
	}
	if ok {
		describe(&r, e, "")
		return r
	}

	// related lookups: URL host, parent domains
	var host string
	switch i.Type {
	case ioc.URL:
		if u, err := url.Parse(i.Value); err == nil {
			host = strings.ToLower(u.Hostname())
		}
	case ioc.Domain:
		host = i.Value
	}
	if host != "" {
		if a, err := netip.ParseAddr(host); err == nil {
			t := ioc.IPv4
			if a.Unmap().Is6() {
				t = ioc.IPv6
			}
			if e, ok, _ := s.Store.Get(t, a.Unmap().String()); ok {
				describe(&r, e, "host "+e.Value+" is listed")
				return r
			}
		} else {
			cands := parents(host)
			if i.Type == ioc.URL {
				cands = append([]string{host}, cands...)
			}
			for k, d := range cands {
				if e, ok, _ := s.Store.Get(ioc.Domain, d); ok {
					exact := i.Type == ioc.URL && k == 0
					describe(&r, e, map[bool]string{true: "host", false: "parent domain"}[exact]+" "+d+" is listed")
					if !exact {
						r.Status = sources.StatusSuspicious
					}
					return r
				}
			}
		}
	}
	r.Status = sources.StatusNotFound
	r.Summary = "not in local list"
	return r
}

func describe(r *sources.Result, e Entry, prefix string) {
	r.Status = e.Verdict
	if r.Status.Severity() < sources.StatusSuspicious.Severity() {
		r.Status = sources.StatusMalicious
	}
	r.Score = "listed"
	parts := []string{}
	if prefix != "" {
		parts = append(parts, prefix)
	}
	parts = append(parts, fmt.Sprintf("%s %s", e.Origin, e.FirstSeen.Format("2006-01-02")))
	if len(e.Tags) > 0 {
		parts = append(parts, strings.Join(e.Tags, ","))
	}
	if e.Note != "" {
		parts = append(parts, e.Note)
	}
	r.Summary = strings.Join(parts, " · ")
	add := func(k, v string) {
		if v != "" {
			r.Fields = append(r.Fields, sources.Field{Key: k, Value: v})
		}
	}
	add("Listed value", e.Value)
	add("Origin", string(e.Origin))
	add("Tags", strings.Join(e.Tags, ", "))
	add("Flagged by", strings.Join(e.Sources, ", "))
	add("Note", e.Note)
	add("First seen", e.FirstSeen.Format("2006-01-02 15:04 MST"))
	add("Last seen", e.LastSeen.Format("2006-01-02 15:04 MST"))
	add("Hits", fmt.Sprint(e.Hits))
}

// parents("a.b.evil.com") = ["b.evil.com", "evil.com"]
func parents(d string) []string {
	labels := strings.Split(d, ".")
	var out []string
	for k := 1; k <= len(labels)-2; k++ {
		out = append(out, strings.Join(labels[k:], "."))
	}
	return out
}
