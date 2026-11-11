package sources

import (
	"context"
	"fmt"
	"strings"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

var otxBenign = map[string]bool{
	"whitelist": true, "alexa": true, "majestic": true, "akamai": true,
	"false_positive": true, "umbrella": true, "tranco": true,
}

// OTX queries AlienVault Open Threat Exchange. The key is optional
// (anonymous requests work, with lower rate limits).
type OTX struct {
	Key     string
	BaseURL string
}

func (s *OTX) ID() string        { return "otx" }
func (s *OTX) Name() string      { return "AlienVault OTX" }
func (s *OTX) RequiresKey() bool { return false }
func (s *OTX) Configured() bool  { return true }
func (s *OTX) Supports(t ioc.Type) bool {
	return typeIn(t, ioc.MD5, ioc.SHA1, ioc.SHA256, ioc.IPv4, ioc.IPv6, ioc.Domain, ioc.URL)
}

func (s *OTX) Query(ctx context.Context, i ioc.IOC) Result {
	r := Result{Source: s.Name()}
	var section, gui string
	switch i.Type {
	case ioc.IPv4:
		section, gui = "IPv4", "ip"
	case ioc.IPv6:
		section, gui = "IPv6", "ip"
	case ioc.Domain:
		section, gui = "domain", "domain"
	case ioc.URL:
		section, gui = "url", "url"
	default:
		section, gui = "file", "file"
	}
	r.Link = fmt.Sprintf("https://otx.alienvault.com/indicator/%s/%s", gui, i.Value)

	var resp struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				Name            string   `json:"name"`
				Tags            []string `json:"tags"`
				Adversary       string   `json:"adversary"`
				MalwareFamilies []struct {
					DisplayName string `json:"display_name"`
				} `json:"malware_families"`
			} `json:"pulses"`
		} `json:"pulse_info"`
		Country    flexStr `json:"country_name"`
		ASN        flexStr `json:"asn"`
		Validation []struct {
			Source string `json:"source"`
			Name   string `json:"name"`
		} `json:"validation"`
	}
	u := fmt.Sprintf("%s/indicators/%s/%s/general",
		orDefault(s.BaseURL, "https://otx.alienvault.com/api/v1"), section, i.Value)
	code, err := getJSON(ctx, u, map[string]string{"X-OTX-API-KEY": s.Key}, &resp)
	if err != nil {
		return fail(r, err)
	}
	if code == 404 {
		r.Status = StatusNotFound
		r.Summary = "unknown to OTX"
		return r
	}

	pi := resp.PulseInfo
	var families, pulses, tags, adversaries, valid []string
	for _, p := range pi.Pulses {
		pulses = append(pulses, p.Name)
		tags = append(tags, p.Tags...)
		adversaries = append(adversaries, p.Adversary)
		for _, f := range p.MalwareFamilies {
			families = append(families, f.DisplayName)
		}
	}
	// OTX "validation" mixes real allow-lists (whitelist, alexa, majestic…)
	// with plain annotations such as "IP Associated with Tor Exit Nodes";
	// only the former mean "known benign".
	var benign []string
	for _, v := range resp.Validation {
		valid = append(valid, v.Name)
		if otxBenign[strings.ToLower(v.Source)] {
			benign = append(benign, v.Name)
		}
	}
	families = uniq(families)

	r.Score = fmt.Sprintf("%d pulse(s)", pi.Count)
	switch {
	case len(benign) > 0 && len(families) == 0:
		r.Status = StatusClean
		r.Summary = "whitelisted: " + strings.Join(uniq(benign), ", ")
	case pi.Count == 0:
		r.Status = StatusNotFound
		r.Summary = "no pulses"
	case len(families) > 0 || pi.Count >= 5:
		r.Status = StatusMalicious
	default:
		r.Status = StatusSuspicious
	}
	if r.Summary == "" {
		if len(families) > 0 {
			r.Summary = strings.Join(families, ", ")
		} else {
			r.Summary = fmt.Sprintf("referenced in %d pulse(s)", pi.Count)
		}
	}

	r.addList("Malware families", families, 6)
	r.addList("Adversary", adversaries, 4)
	r.addList("Pulses", pulses, 4)
	r.addList("Tags", tags, 10)
	r.addList("Validation", valid, 0)
	r.add("Country", resp.Country.String())
	r.add("ASN", resp.ASN.String())
	return r
}
