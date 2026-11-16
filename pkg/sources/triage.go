package sources

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

// Triage looks up sandbox analyses on Hatching Triage (tria.ge) by hash.
// BaseURL can point at a private instance (https://private.tria.ge/api/v0).
type Triage struct {
	Key     string
	BaseURL string
}

func (s *Triage) ID() string        { return "triage" }
func (s *Triage) Name() string      { return "Triage" }
func (s *Triage) RequiresKey() bool { return true }
func (s *Triage) Configured() bool  { return s.Key != "" }
func (s *Triage) Supports(t ioc.Type) bool {
	return typeIn(t, ioc.MD5, ioc.SHA1, ioc.SHA256)
}

type triageOverview struct {
	Sample struct {
		Score   int    `json:"score"`
		Created string `json:"created"`
		Target  string `json:"target"`
	} `json:"sample"`
	Analysis struct {
		Score  int      `json:"score"`
		Family []string `json:"family"`
		Tags   []string `json:"tags"`
	} `json:"analysis"`
	Signatures []struct {
		Name  string   `json:"name"`
		Score int      `json:"score"`
		TTP   []string `json:"ttp"`
	} `json:"signatures"`
	Extracted []struct {
		Config *struct {
			Family string   `json:"family"`
			Botnet string   `json:"botnet"`
			C2     []string `json:"c2"`
		} `json:"config"`
	} `json:"extracted"`
}

func (s *Triage) Query(ctx context.Context, i ioc.IOC) Result {
	r := Result{Source: s.Name()}
	base := orDefault(s.BaseURL, "https://tria.ge/api/v0")
	headers := map[string]string{"Authorization": "Bearer " + s.Key}

	var search struct {
		Data []struct {
			ID        string `json:"id"`
			Status    string `json:"status"`
			Filename  string `json:"filename"`
			Submitted string `json:"submitted"`
		} `json:"data"`
	}
	q := url.Values{"query": {string(i.Type) + ":" + i.Value}, "limit": {"10"}}
	code, err := getJSON(ctx, base+"/search?"+q.Encode(), headers, &search)
	if err != nil {
		return fail(r, err)
	}
	if code == 404 || len(search.Data) == 0 {
		r.Status = StatusNotFound
		r.Summary = "no Triage analyses"
		return r
	}

	pick := search.Data[0]
	for _, d := range search.Data {
		if d.Status == "reported" {
			pick = d
			break
		}
	}
	r.Link = "https://tria.ge/" + pick.ID
	var names, submitted []string
	for _, d := range search.Data {
		names = append(names, d.Filename)
		submitted = append(submitted, d.Submitted)
	}
	sort.Strings(submitted)

	var ov triageOverview
	if _, err := getJSON(ctx, base+"/samples/"+url.PathEscape(pick.ID)+"/overview.json", headers, &ov); err != nil {
		// we know analyses exist but could not read the verdict
		r.Status = StatusInfo
		r.Score = fmt.Sprintf("%d analyses", len(search.Data))
		r.Summary = "analyses exist (overview unavailable: " + err.Error() + ")"
		return r
	}

	score := ov.Analysis.Score
	if score == 0 {
		score = ov.Sample.Score
	}
	switch {
	case score >= 8:
		r.Status = StatusMalicious
	case score >= 6:
		r.Status = StatusSuspicious
	case score > 0:
		r.Status = StatusClean
	default:
		r.Status = StatusInfo
	}
	r.Score = fmt.Sprintf("%d/10", score)

	var sigs, c2 []string
	for _, sg := range ov.Signatures {
		for _, t := range sg.TTP {
			r.technique(t, "")
		}
		if sg.Score >= 5 {
			sigs = append(sigs, sg.Name)
		}
	}
	for _, ex := range ov.Extracted {
		if ex.Config != nil {
			c2 = append(c2, ex.Config.C2...)
			if ex.Config.Family != "" {
				ov.Analysis.Family = append(ov.Analysis.Family, ex.Config.Family)
			}
		}
	}
	if r.Status == StatusMalicious || r.Status == StatusSuspicious {
		for _, t := range submitted {
			r.seenString(t)
		}
	}

	r.add("Analyses", fmt.Sprint(len(search.Data)))
	r.addList("Family", ov.Analysis.Family, 5)
	r.addList("Tags", ov.Analysis.Tags, 12)
	r.addList("Signatures", sigs, 8)
	r.addList("Extracted C2", c2, 10)
	r.addList("Submitted as", names, 5)
	if len(submitted) > 0 {
		r.add("First submitted", submitted[0])
	}
	sum := []string{fmt.Sprintf("score %d/10", score)}
	if f := strings.Join(uniq(ov.Analysis.Family), ", "); f != "" {
		sum = append(sum, f)
	}
	if len(c2) > 0 {
		sum = append(sum, fmt.Sprintf("%d C2 extracted", len(uniq(c2))))
	}
	r.Summary = strings.Join(sum, " · ")
	return r
}
