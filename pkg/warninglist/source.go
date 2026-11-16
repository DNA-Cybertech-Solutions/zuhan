package warninglist

import (
	"context"
	"fmt"
	"strings"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
)

// Source exposes the warninglists as a regular scan source. It never says
// malicious; it marks known-benign infrastructure (Result.Benign) and adds
// context labels (Result.Context).
type Source struct {
	Path string // user copy from `zuhan warninglists update`; "" or missing = embedded
}

func (s *Source) ID() string               { return "warninglists" }
func (s *Source) Name() string             { return "MISP warninglists" }
func (s *Source) RequiresKey() bool        { return false }
func (s *Source) Configured() bool         { return true }
func (s *Source) Supports(t ioc.Type) bool { return t.Valid() }
func (s *Source) LocalOnly() bool          { return true }

func (s *Source) Query(ctx context.Context, i ioc.IOC) sources.Result {
	r := sources.Result{Source: s.Name()}
	set, err := Load(s.Path)
	if err != nil {
		r.Status, r.Error = sources.StatusError, err.Error()
		return r
	}
	matches := set.Match(i)
	if len(matches) == 0 {
		r.Status = sources.StatusNotFound
		r.Summary = fmt.Sprintf("on none of %d lists", set.Len())
		return r
	}
	r.Status = sources.StatusInfo
	var benign, context, all []string
	// many "top N sites" lists overlap: fold them into one label
	popular, popularExact := 0, false
	var kept []Match
	for _, m := range matches {
		if IsPopularity(m.ListID) {
			popular++
			popularExact = popularExact || m.Kind == KindBenign
			all = append(all, m.Label+" ("+m.How+") ["+m.ListID+"]")
			continue
		}
		kept = append(kept, m)
	}
	if popular > 0 {
		label := fmt.Sprintf("Popular website (%d top-site lists)", popular)
		if popularExact {
			benign = append(benign, label)
		} else {
			context = append(context, "Hosted on a popular website ("+fmt.Sprint(popular)+" top-site lists)")
		}
	}
	for _, m := range kept {
		label := m.Label
		if m.How != "exact" {
			label += " (" + m.How + ")"
		}
		all = append([]string{label + " [" + m.ListID + "]"}, all...)
		if m.Kind == KindBenign {
			benign = append(benign, label)
		} else {
			context = append(context, label)
		}
	}
	r.Fields = append(r.Fields, sources.Field{Key: "Lists", Value: strings.Join(all, "\n")})
	r.Fields = append(r.Fields, sources.Field{Key: "Data", Value: set.Source})
	r.Score = fmt.Sprintf("%d list(s)", len(matches))
	r.Benign = strings.Join(benign, "; ")
	r.Context = strings.Join(context, "; ")
	var sum []string
	if len(benign) > 0 {
		sum = append(sum, "known benign: "+strings.Join(benign, ", "))
	}
	if len(context) > 0 {
		sum = append(sum, strings.Join(context, ", "))
	}
	r.Summary = strings.Join(sum, " · ")
	r.Link = "https://github.com/MISP/misp-warninglists/tree/main/lists/" + matches[0].ListID
	return r
}
