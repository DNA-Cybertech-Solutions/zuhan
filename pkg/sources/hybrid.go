package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

// HybridAnalysis searches Falcon Sandbox (hybrid-analysis.com) reports by hash.
type HybridAnalysis struct {
	Key     string
	BaseURL string
}

func (s *HybridAnalysis) ID() string        { return "hybrid" }
func (s *HybridAnalysis) Name() string      { return "Hybrid Analysis" }
func (s *HybridAnalysis) RequiresKey() bool { return true }
func (s *HybridAnalysis) Configured() bool  { return s.Key != "" }
func (s *HybridAnalysis) Supports(t ioc.Type) bool {
	return typeIn(t, ioc.MD5, ioc.SHA1, ioc.SHA256)
}

type haReport struct {
	Verdict     flexStr `json:"verdict"`
	ThreatScore flexStr `json:"threat_score"`
	VxFamily    flexStr `json:"vx_family"`
	Type        flexStr `json:"type"`
	SubmitName  flexStr `json:"submit_name"`
	Environment flexStr `json:"environment_description"`
	StartTime   flexStr `json:"analysis_start_time"`
	SHA256      flexStr `json:"sha256"`
}

func (s *HybridAnalysis) Query(ctx context.Context, i ioc.IOC) Result {
	r := Result{Source: s.Name()}
	base := orDefault(s.BaseURL, "https://www.hybrid-analysis.com/api/v2")
	headers := map[string]string{"api-key": s.Key, "User-Agent": "Falcon Sandbox"}

	var raw json.RawMessage
	code, err := getJSON(ctx, base+"/search/hash?"+url.Values{"hash": {i.Value}}.Encode(), headers, &raw)
	var he *HTTPError
	if errors.As(err, &he) && (he.Code == 405 || he.Code == 400) {
		// older API flavour: POST form
		raw = nil
		code, err = postForm(ctx, base+"/search/hash", url.Values{"hash": {i.Value}}, headers, &raw)
	}
	if err != nil {
		return fail(r, err)
	}
	var reports []haReport
	raw = bytes.TrimSpace(raw)
	if code != 404 && len(raw) > 0 {
		if raw[0] == '[' {
			err = json.Unmarshal(raw, &reports)
		} else {
			var obj struct {
				Reports []haReport `json:"reports"`
			}
			err = json.Unmarshal(raw, &obj)
			reports = obj.Reports
		}
		if err != nil {
			return fail(r, err)
		}
	}
	if len(reports) == 0 {
		r.Status = StatusNotFound
		r.Summary = "no sandbox reports"
		return r
	}

	best := -1
	r.Status = StatusInfo
	var fams, names, envs []string
	sha := i.Value
	for _, rep := range reports {
		switch strings.ToLower(rep.Verdict.String()) {
		case "malicious":
			r.Status = StatusMalicious
		case "suspicious":
			if r.Status.Severity() < StatusSuspicious.Severity() {
				r.Status = StatusSuspicious
			}
		case "no specific threat", "whitelisted", "no verdict":
			if r.Status == StatusInfo {
				r.Status = StatusClean
			}
		}
		if n, err := strconv.Atoi(rep.ThreatScore.String()); err == nil && n > best {
			best = n
		}
		fams = append(fams, rep.VxFamily.String())
		names = append(names, rep.SubmitName.String())
		envs = append(envs, rep.Environment.String())
		if rep.SHA256 != "" {
			sha = rep.SHA256.String()
		}
	}
	if best >= 0 {
		r.Score = fmt.Sprintf("%d/100", best)
	}
	r.Link = "https://www.hybrid-analysis.com/sample/" + sha
	r.add("Reports", fmt.Sprint(len(reports)))
	r.add("Verdict", reports[0].Verdict.String())
	r.addList("Family", fams, 5)
	r.addList("Submitted as", names, 5)
	r.add("File type", reports[0].Type.String())
	r.addList("Environments", envs, 4)
	r.Summary = strings.Trim(reports[0].Verdict.String()+" · "+strings.Join(uniq(fams), ", "), " ·")
	return r
}
