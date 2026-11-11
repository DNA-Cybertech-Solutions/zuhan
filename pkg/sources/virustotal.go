package sources

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

// VirusTotal queries the VirusTotal v3 API.
type VirusTotal struct {
	Key     string
	BaseURL string
}

func (s *VirusTotal) ID() string        { return "virustotal" }
func (s *VirusTotal) Name() string      { return "VirusTotal" }
func (s *VirusTotal) RequiresKey() bool { return true }
func (s *VirusTotal) Configured() bool  { return s.Key != "" }
func (s *VirusTotal) Supports(t ioc.Type) bool {
	return typeIn(t, ioc.MD5, ioc.SHA1, ioc.SHA256, ioc.IPv4, ioc.IPv6, ioc.Domain, ioc.URL)
}

type vtResponse struct {
	Data struct {
		Attributes struct {
			Stats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			Reputation      int    `json:"reputation"`
			MeaningfulName  string `json:"meaningful_name"`
			TypeDescription string `json:"type_description"`
			Size            int64  `json:"size"`
			Threat          struct {
				Label string `json:"suggested_threat_label"`
			} `json:"popular_threat_classification"`
			Country          string   `json:"country"`
			ASOwner          string   `json:"as_owner"`
			ASN              int      `json:"asn"`
			Registrar        string   `json:"registrar"`
			Tags             []string `json:"tags"`
			LastFinalURL     string   `json:"last_final_url"`
			MD5              string   `json:"md5"`
			SHA1             string   `json:"sha1"`
			SHA256           string   `json:"sha256"`
			LastAnalysisDate int64    `json:"last_analysis_date"`
		} `json:"attributes"`
	} `json:"data"`
}

func (s *VirusTotal) Query(ctx context.Context, i ioc.IOC) Result {
	r := Result{Source: s.Name()}
	var path, gui string
	switch {
	case i.Type.IsHash():
		path, gui = "/files/"+i.Value, "file/"+i.Value
	case i.Type.IsIP():
		path, gui = "/ip_addresses/"+i.Value, "ip-address/"+i.Value
	case i.Type == ioc.Domain:
		path, gui = "/domains/"+i.Value, "domain/"+i.Value
	case i.Type == ioc.URL:
		sum := sha256.Sum256([]byte(i.Value))
		path = "/urls/" + base64.RawURLEncoding.EncodeToString([]byte(i.Value))
		gui = "url/" + hex.EncodeToString(sum[:])
	}
	r.Link = "https://www.virustotal.com/gui/" + gui

	var resp vtResponse
	code, err := getJSON(ctx, orDefault(s.BaseURL, "https://www.virustotal.com/api/v3")+path,
		map[string]string{"x-apikey": s.Key}, &resp)
	if err != nil {
		return fail(r, err)
	}
	if code == 404 {
		r.Status = StatusNotFound
		r.Summary = "no record on VirusTotal"
		return r
	}

	a := resp.Data.Attributes
	st := a.Stats
	total := st.Malicious + st.Suspicious + st.Harmless + st.Undetected
	r.Score = fmt.Sprintf("%d/%d", st.Malicious, total)
	// A single engine flagging something with a non-negative community
	// reputation is almost always a false positive (8.8.8.8 is the classic
	// case), so it is reported as clean with a note instead of suspicious.
	lone := st.Malicious == 1 && a.Reputation >= 0
	switch {
	case st.Malicious >= 3:
		r.Status = StatusMalicious
	case lone && st.Suspicious < 2:
		r.Status = StatusClean
	case st.Malicious > 0 || st.Suspicious >= 2:
		r.Status = StatusSuspicious
	default:
		r.Status = StatusClean
	}

	r.add("Threat label", a.Threat.Label)
	r.add("Name", a.MeaningfulName)
	r.add("File type", a.TypeDescription)
	if a.Size > 0 {
		r.add("Size", fmt.Sprintf("%d bytes", a.Size))
	}
	r.add("SHA256", a.SHA256)
	r.add("Country", a.Country)
	if a.ASOwner != "" {
		r.add("AS", fmt.Sprintf("AS%d %s", a.ASN, a.ASOwner))
	}
	r.add("Registrar", a.Registrar)
	r.add("Final URL", a.LastFinalURL)
	r.add("Detections", fmt.Sprintf("malicious=%d suspicious=%d harmless=%d undetected=%d",
		st.Malicious, st.Suspicious, st.Harmless, st.Undetected))
	r.add("Reputation", fmt.Sprint(a.Reputation))
	r.addList("Tags", a.Tags, 8)
	if a.LastAnalysisDate > 0 {
		r.add("Last analysis", time.Unix(a.LastAnalysisDate, 0).UTC().Format("2006-01-02 15:04 UTC"))
	}

	var parts []string
	if a.Threat.Label != "" {
		parts = append(parts, a.Threat.Label)
	}
	if a.MeaningfulName != "" {
		parts = append(parts, a.MeaningfulName)
	}
	if a.ASOwner != "" {
		parts = append(parts, a.ASOwner)
	}
	if len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d engines flagged", st.Malicious))
	}
	if r.Status == StatusClean && st.Malicious == 1 {
		parts = append([]string{"1 engine flagged (likely false positive)"}, parts...)
	}
	r.Summary = strings.Join(parts, " · ")
	return r
}
