package sources

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

// ---------------- AbuseIPDB ----------------

// AbuseIPDB returns community abuse reports for an IP.
type AbuseIPDB struct {
	Key     string
	BaseURL string
	MaxAge  int // days, default 90
}

func (s *AbuseIPDB) ID() string               { return "abuseipdb" }
func (s *AbuseIPDB) Name() string             { return "AbuseIPDB" }
func (s *AbuseIPDB) RequiresKey() bool        { return true }
func (s *AbuseIPDB) Configured() bool         { return s.Key != "" }
func (s *AbuseIPDB) Supports(t ioc.Type) bool { return t.IsIP() }

func (s *AbuseIPDB) Query(ctx context.Context, i ioc.IOC) Result {
	r := Result{Source: s.Name(), Link: "https://www.abuseipdb.com/check/" + i.Value}
	age := s.MaxAge
	if age <= 0 {
		age = 90
	}
	q := url.Values{"ipAddress": {i.Value}, "maxAgeInDays": {fmt.Sprint(age)}}
	var resp struct {
		Data struct {
			IsPublic      bool    `json:"isPublic"`
			Score         int     `json:"abuseConfidenceScore"`
			CountryCode   flexStr `json:"countryCode"`
			UsageType     flexStr `json:"usageType"`
			ISP           flexStr `json:"isp"`
			Domain        flexStr `json:"domain"`
			IsTor         bool    `json:"isTor"`
			IsWhitelisted flexStr `json:"isWhitelisted"`
			TotalReports  int     `json:"totalReports"`
			Users         int     `json:"numDistinctUsers"`
			LastReported  flexStr `json:"lastReportedAt"`
		} `json:"data"`
	}
	_, err := getJSON(ctx, orDefault(s.BaseURL, "https://api.abuseipdb.com/api/v2")+"/check?"+q.Encode(),
		map[string]string{"Key": s.Key}, &resp)
	if err != nil {
		return fail(r, err)
	}
	d := resp.Data
	r.Score = fmt.Sprintf("%d%%", d.Score)
	switch {
	case d.Score >= 75:
		r.Status = StatusMalicious
	case d.Score >= 25:
		r.Status = StatusSuspicious
	case d.TotalReports == 0:
		r.Status = StatusClean
	default:
		r.Status = StatusClean
	}
	r.Summary = fmt.Sprintf("%d report(s) from %d user(s)", d.TotalReports, d.Users)
	if d.ISP != "" {
		r.Summary += " · " + d.ISP.String()
	}
	r.add("Confidence", r.Score)
	r.add("Reports", fmt.Sprintf("%d (last %d days)", d.TotalReports, age))
	r.add("Last reported", d.LastReported.String())
	r.add("Country", d.CountryCode.String())
	r.add("ISP", d.ISP.String())
	r.add("Domain", d.Domain.String())
	r.add("Usage type", d.UsageType.String())
	if d.IsTor {
		r.add("Tor exit", "yes")
	}
	if d.IsWhitelisted == "true" {
		r.add("Whitelisted", "yes")
	}
	if !d.IsPublic {
		r.add("Public", "no (private/reserved range)")
	}
	return r
}

// ---------------- GreyNoise (community) ----------------

// GreyNoise tells whether an IP is internet background noise or a known benign service.
type GreyNoise struct {
	Key     string
	BaseURL string
}

func (s *GreyNoise) ID() string               { return "greynoise" }
func (s *GreyNoise) Name() string             { return "GreyNoise" }
func (s *GreyNoise) RequiresKey() bool        { return false }
func (s *GreyNoise) Configured() bool         { return true }
func (s *GreyNoise) Supports(t ioc.Type) bool { return t == ioc.IPv4 }

func (s *GreyNoise) Query(ctx context.Context, i ioc.IOC) Result {
	r := Result{Source: s.Name(), Link: "https://viz.greynoise.io/ip/" + i.Value}
	var resp struct {
		Noise          bool    `json:"noise"`
		RIOT           bool    `json:"riot"`
		Classification flexStr `json:"classification"`
		Name           flexStr `json:"name"`
		LastSeen       flexStr `json:"last_seen"`
		Message        flexStr `json:"message"`
	}
	code, err := getJSON(ctx, orDefault(s.BaseURL, "https://api.greynoise.io/v3/community")+"/"+i.Value,
		map[string]string{"key": s.Key}, &resp)
	if err != nil {
		return fail(r, err)
	}
	if code == 404 {
		r.Status = StatusNotFound
		r.Summary = "not observed scanning the internet"
		return r
	}
	cls := strings.ToLower(resp.Classification.String())
	switch {
	case cls == "malicious":
		r.Status = StatusMalicious
	case cls == "benign" || resp.RIOT:
		r.Status = StatusClean
	case resp.Noise:
		r.Status = StatusSuspicious
	default:
		r.Status = StatusInfo
	}
	r.Score = cls
	r.add("Classification", cls)
	r.add("Name", resp.Name.String())
	r.add("Noise (scanner)", fmt.Sprint(resp.Noise))
	r.add("RIOT (known benign service)", fmt.Sprint(resp.RIOT))
	r.add("Last seen", resp.LastSeen.String())
	var sum []string
	if n := resp.Name.String(); n != "" && !strings.EqualFold(n, "unknown") {
		sum = append(sum, n)
	}
	if resp.RIOT {
		sum = append(sum, "known benign service (RIOT)")
	} else if resp.Noise {
		sum = append(sum, "seen scanning the internet")
	}
	if m := resp.Message.String(); m != "" && !strings.EqualFold(m, "success") {
		sum = append(sum, m)
	}
	if len(sum) == 0 {
		sum = append(sum, "classification: "+cls)
	}
	r.Summary = strings.Join(sum, " · ")
	return r
}

// ---------------- Shodan InternetDB (free, no key) ----------------

// ShodanInternetDB returns open ports, CVEs and tags for an IP.
type ShodanInternetDB struct {
	BaseURL string
}

func (s *ShodanInternetDB) ID() string               { return "shodan" }
func (s *ShodanInternetDB) Name() string             { return "Shodan InternetDB" }
func (s *ShodanInternetDB) RequiresKey() bool        { return false }
func (s *ShodanInternetDB) Configured() bool         { return true }
func (s *ShodanInternetDB) Supports(t ioc.Type) bool { return t == ioc.IPv4 }

func (s *ShodanInternetDB) Query(ctx context.Context, i ioc.IOC) Result {
	r := Result{Source: s.Name(), Link: "https://www.shodan.io/host/" + i.Value}
	var resp struct {
		Hostnames []string `json:"hostnames"`
		Ports     []int    `json:"ports"`
		Vulns     []string `json:"vulns"`
		Tags      []string `json:"tags"`
		CPEs      []string `json:"cpes"`
	}
	code, err := getJSON(ctx, orDefault(s.BaseURL, "https://internetdb.shodan.io")+"/"+i.Value, nil, &resp)
	if err != nil {
		return fail(r, err)
	}
	if code == 404 {
		r.Status = StatusNotFound
		r.Summary = "no exposure data"
		return r
	}
	r.Status = StatusInfo
	for _, t := range resp.Tags {
		switch strings.ToLower(t) {
		case "c2", "malware", "compromised":
			r.Status = StatusSuspicious
		}
	}
	ports := make([]string, len(resp.Ports))
	for k, p := range resp.Ports {
		ports[k] = fmt.Sprint(p)
	}
	r.Score = fmt.Sprintf("%d ports, %d CVEs", len(resp.Ports), len(resp.Vulns))
	r.addList("Open ports", ports, 20)
	r.addList("Vulns", resp.Vulns, 10)
	r.addList("Hostnames", resp.Hostnames, 5)
	r.addList("Tags", resp.Tags, 0)
	r.addList("CPEs", resp.CPEs, 6)
	sum := "ports " + strings.Join(ports, ",")
	if len(ports) > 8 {
		sum = fmt.Sprintf("%d open ports", len(ports))
	}
	if len(resp.Tags) > 0 {
		sum += " · tags: " + strings.Join(resp.Tags, ",")
	}
	r.Summary = sum
	return r
}
