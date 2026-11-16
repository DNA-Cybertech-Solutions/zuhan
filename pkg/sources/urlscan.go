package sources

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

// URLScan searches urlscan.io for scans of a domain, IP, URL or resource
// hash. The key is optional (anonymous searches have lower limits).
type URLScan struct {
	Key     string
	BaseURL string
}

func (s *URLScan) ID() string        { return "urlscan" }
func (s *URLScan) Name() string      { return "urlscan.io" }
func (s *URLScan) RequiresKey() bool { return false }
func (s *URLScan) Configured() bool  { return true }
func (s *URLScan) Supports(t ioc.Type) bool {
	return typeIn(t, ioc.Domain, ioc.IPv4, ioc.IPv6, ioc.URL, ioc.SHA256)
}

type urlscanHit struct {
	Task struct {
		Time string `json:"time"`
		URL  string `json:"url"`
	} `json:"task"`
	Page struct {
		URL     string `json:"url"`
		Domain  string `json:"domain"`
		IP      string `json:"ip"`
		Country string `json:"country"`
		Server  string `json:"server"`
		ASNName string `json:"asnname"`
	} `json:"page"`
	Verdicts *struct {
		Malicious bool `json:"malicious"`
	} `json:"verdicts"`
}

type urlscanResp struct {
	Total   int          `json:"total"`
	Results []urlscanHit `json:"results"`
}

// urlscanQueries returns the search queries to try, best first. URL
// searches are fragile on urlscan's side (some return HTTP 5xx), so a URL
// gets several spellings and finally a search on its host.
func urlscanQueries(i ioc.IOC) (qs []string, hostFallback string) {
	quote := func(v string) string {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
	}
	switch i.Type {
	case ioc.Domain:
		return []string{"domain:" + i.Value}, ""
	case ioc.IPv4, ioc.IPv6:
		return []string{"ip:" + quote(i.Value)}, ""
	case ioc.SHA256:
		return []string{"hash:" + i.Value}, ""
	case ioc.URL:
		v := i.Value
		qs = []string{"page.url:" + quote(v), "task.url:" + quote(v), "page.url:" + luceneEscape(v)}
		if h, _, ok := hostOf(i); ok {
			hostFallback = "page.domain:" + h
		}
		return qs, hostFallback
	}
	return nil, ""
}

// luceneEscape escapes Lucene query-string special characters.
func luceneEscape(v string) string {
	var b strings.Builder
	for _, c := range v {
		if strings.ContainsRune(`+-=&|><!(){}[]^"~*?:\/ `, c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

func (s *URLScan) search(ctx context.Context, q string, size int) (urlscanResp, error) {
	var resp urlscanResp
	u := orDefault(s.BaseURL, "https://urlscan.io/api/v1") + "/search/?" +
		url.Values{"q": {q}, "size": {fmt.Sprint(size)}}.Encode()
	_, err := getJSON(ctx, u, map[string]string{"API-Key": s.Key}, &resp)
	return resp, err
}

func (s *URLScan) Query(ctx context.Context, i ioc.IOC) Result {
	r := Result{Source: s.Name()}
	qs, hostQ := urlscanQueries(i)
	if len(qs) == 0 {
		r.Status = StatusSkipped
		return r
	}
	var (
		q       string
		all     urlscanResp
		err     error
		lastErr error
		found   bool
		anyOK   bool // some query got a real (possibly empty) answer
	)
	for _, cand := range qs {
		all, err = s.search(ctx, cand, 100)
		if err != nil {
			if isAuthOrRate(err) {
				return fail(r, err)
			}
			lastErr = err
			continue
		}
		q, anyOK = cand, true
		if all.Total > 0 || len(all.Results) > 0 {
			found = true
			break
		}
	}
	byHost := false
	if !found && hostQ != "" {
		if h, err := s.search(ctx, hostQ, 100); err == nil && (h.Total > 0 || len(h.Results) > 0) {
			q, all, found, byHost = hostQ, h, true, true
		} else if err == nil {
			anyOK = true
		}
	}
	if q == "" {
		q = qs[0]
	}
	r.Link = "https://urlscan.io/search/#" + url.QueryEscape(q)
	if !found {
		if !anyOK && lastErr != nil {
			return fail(r, lastErr)
		}
		r.Status = StatusNotFound
		r.Summary = "never scanned on urlscan.io"
		return r
	}
	total := all.Total
	if total < len(all.Results) {
		total = len(all.Results)
	}

	// how many scans urlscan itself classified as malicious
	malicious := 0
	var malHits []urlscanHit
	if mal, err := s.search(ctx, "("+q+") AND verdicts.malicious:true", 20); err == nil {
		malicious, malHits = mal.Total, mal.Results
		if malicious < len(mal.Results) {
			malicious = len(mal.Results)
		}
	}
	for _, h := range all.Results {
		if h.Verdicts != nil && h.Verdicts.Malicious && malicious == 0 {
			malicious = 1
			malHits = append(malHits, h)
		}
	}

	var countries, servers, asns, ips, domains, times []string
	for _, h := range all.Results {
		countries = append(countries, h.Page.Country)
		servers = append(servers, h.Page.Server)
		asns = append(asns, h.Page.ASNName)
		ips = append(ips, h.Page.IP)
		domains = append(domains, h.Page.Domain)
		times = append(times, h.Task.Time)
	}
	sort.Strings(times)

	r.Score = fmt.Sprintf("%d scans", total)
	if malicious > 0 {
		r.Status = StatusMalicious
		if byHost {
			// scans of the host, not of this exact URL: shared hosts are common
			r.Status = StatusSuspicious
		}
		r.Score = fmt.Sprintf("%d/%d malicious", malicious, total)
		for _, h := range malHits {
			r.seenString(h.Task.Time)
		}
	} else {
		r.Status = StatusInfo
	}

	if byHost {
		r.add("Matched on", "host only — urlscan has no scan of this exact URL")
	}
	r.add("Scans", fmt.Sprint(total))
	r.add("Malicious scans", fmt.Sprint(malicious))
	if n := len(all.Results); n > 0 {
		latest := all.Results[0]
		r.add("Latest scan", strings.TrimSpace(latest.Task.Time+" "+latest.Page.URL))
		if total <= n {
			r.add("First scan", times[0])
		}
	}
	if i.Type != ioc.IPv4 && i.Type != ioc.IPv6 {
		r.addList("Hosting IPs", ips, 8)
	}
	if i.Type != ioc.Domain {
		r.addList("Domains", domains, 8)
	}
	r.addList("Countries", countries, 8)
	r.addList("ASN", asns, 5)
	r.addList("Servers", servers, 5)

	if malicious > 0 {
		r.Summary = fmt.Sprintf("%d of %d scans classified malicious", malicious, total)
	} else {
		r.Summary = fmt.Sprintf("%d scan(s), none classified malicious", total)
	}
	if byHost {
		r.Summary = "host: " + r.Summary
	}
	if c := strings.Join(uniq(countries), ", "); c != "" && len(uniq(countries)) <= 3 {
		r.Summary += " · " + c
	}
	return r
}
