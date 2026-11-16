package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/attack"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/engine"
)

// Note is a highlighted fact about one IOC (NEW, UNKNOWN, KNOWN BENIGN…).
type Note struct {
	Kind string `json:"kind"` // new | unknown | benign | downgraded | context | first_seen
	Tag  string `json:"tag"`  // short upper-case label
	Text string `json:"text"`
}

// Notes lists the highlights for rep, most important first.
func Notes(rep engine.Report, now time.Time) []Note {
	var out []Note
	if rep.New {
		d := rep.AgeDays(now)
		when := "today"
		if d == 1 {
			when = "yesterday"
		} else if d > 1 {
			when = fmt.Sprintf("%d days ago", d)
		}
		out = append(out, Note{"new", "NEW", "first reported " + when + " (" + rep.FirstSeen.Format("2006-01-02") + ") — fresh threat"})
	}
	if rep.Unknown {
		out = append(out, Note{"unknown", "UNKNOWN", "no intel source has seen it — could be brand new or targeted"})
	}
	if rep.Downgraded {
		out = append(out, Note{"downgraded", "DOWNGRADED", "lowered to clean: it is on an allow-list and at most one source flagged it"})
	}
	if len(rep.Benign) > 0 {
		out = append(out, Note{"benign", "KNOWN BENIGN", strings.Join(rep.Benign, "; ")})
	}
	for _, c := range rep.Context {
		out = append(out, Note{"context", "CONTEXT", c})
	}
	if rep.FirstSeen != nil && !rep.New {
		out = append(out, Note{"first_seen", "FIRST SEEN", rep.FirstSeen.Format("2006-01-02")})
	}
	return out
}

// Techniques merges the ATT&CK techniques of all reports, with the IOCs
// each was seen with.
func Techniques(reps []engine.Report) []attack.Hit {
	var col attack.Collector
	for _, r := range reps {
		col.AddHits(r.Attack, r.IOC.Value)
	}
	return col.Hits()
}

func techIDs(hits []attack.Hit) string {
	var ids []string
	for _, h := range hits {
		ids = append(ids, h.ID)
	}
	return strings.Join(ids, " ")
}
