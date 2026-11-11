package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

// All abuse.ch services share one Auth-Key (https://auth.abuse.ch/).

// ---------------- MalwareBazaar ----------------

// MalwareBazaar looks up malware samples by hash.
type MalwareBazaar struct {
	Key     string
	BaseURL string
}

func (s *MalwareBazaar) ID() string        { return "malwarebazaar" }
func (s *MalwareBazaar) Name() string      { return "MalwareBazaar" }
func (s *MalwareBazaar) RequiresKey() bool { return true }
func (s *MalwareBazaar) Configured() bool  { return s.Key != "" }
func (s *MalwareBazaar) Supports(t ioc.Type) bool {
	return typeIn(t, ioc.MD5, ioc.SHA1, ioc.SHA256)
}

func (s *MalwareBazaar) Query(ctx context.Context, i ioc.IOC) Result {
	r := Result{Source: s.Name()}
	var resp struct {
		QueryStatus string          `json:"query_status"`
		Data        json.RawMessage `json:"data"`
	}
	_, err := postForm(ctx, orDefault(s.BaseURL, "https://mb-api.abuse.ch/api/v1/"),
		url.Values{"query": {"get_info"}, "hash": {i.Value}},
		map[string]string{"Auth-Key": s.Key}, &resp)
	if err != nil {
		return fail(r, err)
	}
	switch resp.QueryStatus {
	case "ok":
	case "hash_not_found", "no_results":
		r.Status = StatusNotFound
		r.Summary = "sample not in MalwareBazaar"
		return r
	default:
		return fail(r, fmt.Errorf("query_status: %s", resp.QueryStatus))
	}

	var data []struct {
		SHA256         string   `json:"sha256_hash"`
		FileName       flexStr  `json:"file_name"`
		FileType       flexStr  `json:"file_type"`
		FileTypeMIME   flexStr  `json:"file_type_mime"`
		FileSize       flexStr  `json:"file_size"`
		Signature      flexStr  `json:"signature"`
		FirstSeen      flexStr  `json:"first_seen"`
		LastSeen       flexStr  `json:"last_seen"`
		Tags           []string `json:"tags"`
		DeliveryMethod flexStr  `json:"delivery_method"`
		Imphash        flexStr  `json:"imphash"`
		Reporter       flexStr  `json:"reporter"`
	}
	if err := decodeArray(resp.Data, &data); err != nil {
		return fail(r, err)
	}
	if len(data) == 0 {
		r.Status = StatusNotFound
		return r
	}
	d := data[0]
	r.Status = StatusMalicious
	r.Score = "known sample"
	r.Link = "https://bazaar.abuse.ch/sample/" + d.SHA256 + "/"
	r.add("Signature", d.Signature.String())
	r.add("File name", d.FileName.String())
	r.add("File type", d.FileType.String())
	r.add("Size", d.FileSize.String())
	r.add("SHA256", d.SHA256)
	r.add("Imphash", d.Imphash.String())
	r.add("First seen", d.FirstSeen.String())
	r.add("Last seen", d.LastSeen.String())
	r.add("Delivery", d.DeliveryMethod.String())
	r.addList("Tags", d.Tags, 10)

	sum := []string{}
	if d.Signature != "" {
		sum = append(sum, d.Signature.String())
	}
	if d.FileType != "" {
		sum = append(sum, d.FileType.String())
	}
	if d.FirstSeen != "" {
		sum = append(sum, "first seen "+d.FirstSeen.String())
	}
	r.Summary = strings.Join(sum, " · ")
	return r
}

// ---------------- ThreatFox ----------------

// ThreatFox looks up IOCs shared by the abuse.ch community.
type ThreatFox struct {
	Key     string
	BaseURL string
}

func (s *ThreatFox) ID() string        { return "threatfox" }
func (s *ThreatFox) Name() string      { return "ThreatFox" }
func (s *ThreatFox) RequiresKey() bool { return true }
func (s *ThreatFox) Configured() bool  { return s.Key != "" }
func (s *ThreatFox) Supports(t ioc.Type) bool {
	return typeIn(t, ioc.MD5, ioc.SHA256, ioc.IPv4, ioc.Domain, ioc.URL)
}

func (s *ThreatFox) Query(ctx context.Context, i ioc.IOC) Result {
	r := Result{Source: s.Name()}
	payload := map[string]any{"query": "search_ioc", "search_term": i.Value}
	if i.Type.IsHash() {
		payload = map[string]any{"query": "search_hash", "hash": i.Value}
	}
	var resp struct {
		QueryStatus string          `json:"query_status"`
		Data        json.RawMessage `json:"data"`
	}
	_, err := postJSON(ctx, orDefault(s.BaseURL, "https://threatfox-api.abuse.ch/api/v1")+"/",
		payload, map[string]string{"Auth-Key": s.Key}, &resp)
	if err != nil {
		return fail(r, err)
	}
	switch resp.QueryStatus {
	case "ok":
	case "no_result", "no_results":
		r.Status = StatusNotFound
		r.Summary = "no ThreatFox entries"
		return r
	default:
		return fail(r, fmt.Errorf("query_status: %s", resp.QueryStatus))
	}

	var data []struct {
		ID         flexStr  `json:"id"`
		IOC        string   `json:"ioc"`
		ThreatType flexStr  `json:"threat_type"`
		IOCType    flexStr  `json:"ioc_type"`
		Malware    flexStr  `json:"malware_printable"`
		Confidence flexStr  `json:"confidence_level"`
		FirstSeen  flexStr  `json:"first_seen"`
		LastSeen   flexStr  `json:"last_seen"`
		Tags       []string `json:"tags"`
		Reporter   flexStr  `json:"reporter"`
	}
	if err := decodeArray(resp.Data, &data); err != nil {
		return fail(r, err)
	}
	if len(data) == 0 {
		r.Status = StatusNotFound
		return r
	}

	var malware, threats, iocs, tags []string
	for _, d := range data {
		malware = append(malware, d.Malware.String())
		threats = append(threats, d.ThreatType.String())
		iocs = append(iocs, d.IOC)
		tags = append(tags, d.Tags...)
	}
	r.Status = StatusMalicious
	r.Score = fmt.Sprintf("%d hit(s)", len(data))
	r.Link = "https://threatfox.abuse.ch/ioc/" + data[0].ID.String() + "/"
	r.addList("Malware", malware, 6)
	r.addList("Threat type", threats, 6)
	r.add("Confidence", data[0].Confidence.String()+"%")
	r.add("First seen", data[0].FirstSeen.String())
	if i.Type.IsHash() || len(iocs) > 1 {
		r.addList("Related IOCs", iocs, 8)
	}
	r.addList("Tags", tags, 10)
	r.Summary = strings.Join(uniq(malware), ", ")
	if t := strings.Join(uniq(threats), ", "); t != "" {
		r.Summary += " · " + t
	}
	return r
}

// ---------------- URLhaus ----------------

// URLhaus looks up malware distribution URLs, hosts and payloads.
type URLhaus struct {
	Key     string
	BaseURL string
}

func (s *URLhaus) ID() string        { return "urlhaus" }
func (s *URLhaus) Name() string      { return "URLhaus" }
func (s *URLhaus) RequiresKey() bool { return true }
func (s *URLhaus) Configured() bool  { return s.Key != "" }
func (s *URLhaus) Supports(t ioc.Type) bool {
	return typeIn(t, ioc.URL, ioc.Domain, ioc.IPv4, ioc.MD5, ioc.SHA256)
}

type urlhausResp struct {
	QueryStatus string             `json:"query_status"`
	URLStatus   flexStr            `json:"url_status"`
	Threat      flexStr            `json:"threat"`
	DateAdded   flexStr            `json:"date_added"`
	Reference   flexStr            `json:"urlhaus_reference"`
	Tags        []string           `json:"tags"`
	URLCount    flexStr            `json:"url_count"`
	FirstSeen   flexStr            `json:"firstseen"`
	Blacklists  map[string]flexStr `json:"blacklists"`
	URLs        []struct {
		URL       string   `json:"url"`
		URLStatus flexStr  `json:"url_status"`
		Threat    flexStr  `json:"threat"`
		Tags      []string `json:"tags"`
	} `json:"urls"`
	FileType  flexStr `json:"file_type"`
	Signature flexStr `json:"signature"`
	SHA256    flexStr `json:"sha256_hash"`
}

func (s *URLhaus) Query(ctx context.Context, i ioc.IOC) Result {
	r := Result{Source: s.Name()}
	base := orDefault(s.BaseURL, "https://urlhaus-api.abuse.ch/v1")
	var endpoint string
	form := url.Values{}
	switch {
	case i.Type == ioc.URL:
		endpoint = "/url/"
		form.Set("url", i.Value)
	case i.Type == ioc.MD5:
		endpoint = "/payload/"
		form.Set("md5_hash", i.Value)
	case i.Type == ioc.SHA256:
		endpoint = "/payload/"
		form.Set("sha256_hash", i.Value)
	default:
		endpoint = "/host/"
		form.Set("host", i.Value)
	}

	var resp urlhausResp
	if _, err := postForm(ctx, base+endpoint, form, map[string]string{"Auth-Key": s.Key}, &resp); err != nil {
		return fail(r, err)
	}
	switch resp.QueryStatus {
	case "ok":
	case "no_results":
		r.Status = StatusNotFound
		r.Summary = "not listed on URLhaus"
		return r
	default:
		return fail(r, fmt.Errorf("query_status: %s", resp.QueryStatus))
	}
	r.Status = StatusMalicious
	r.Link = resp.Reference.String()

	switch endpoint {
	case "/url/":
		r.Score = resp.URLStatus.String()
		r.add("URL status", resp.URLStatus.String())
		r.add("Threat", resp.Threat.String())
		r.add("Date added", resp.DateAdded.String())
		r.addList("Tags", resp.Tags, 10)
		r.Summary = strings.Trim(resp.Threat.String()+" · "+resp.URLStatus.String(), " ·")
	case "/payload/":
		r.Score = "known payload"
		r.add("Signature", resp.Signature.String())
		r.add("File type", resp.FileType.String())
		r.add("First seen", resp.FirstSeen.String())
		r.add("Distributing URLs", resp.URLCount.String())
		var us []string
		for _, u := range resp.URLs {
			us = append(us, u.URL)
		}
		r.addList("URLs", us, 5)
		if r.Link == "" && resp.SHA256 != "" {
			r.Link = "https://urlhaus.abuse.ch/browse.php?search=" + resp.SHA256.String()
		}
		r.Summary = strings.Trim(resp.Signature.String()+" · "+resp.FileType.String(), " ·")
	default:
		online := 0
		var threats, tags []string
		for _, u := range resp.URLs {
			if u.URLStatus == "online" {
				online++
			}
			threats = append(threats, u.Threat.String())
			tags = append(tags, u.Tags...)
		}
		r.Score = fmt.Sprintf("%s URLs (%d online)", resp.URLCount, online)
		r.add("Malicious URLs", resp.URLCount.String())
		r.add("Online now", fmt.Sprint(online))
		r.add("First seen", resp.FirstSeen.String())
		var bl []string
		for k, v := range resp.Blacklists {
			if v != "" && v != "not listed" {
				bl = append(bl, k+": "+v.String())
			}
		}
		r.addList("Blacklists", bl, 0)
		r.addList("Threats", threats, 5)
		r.addList("Tags", tags, 10)
		r.Summary = fmt.Sprintf("hosts %s malicious URL(s), %d online", resp.URLCount, online)
	}
	return r
}
