// Package sources contains the threat-intelligence providers ZUHAN queries.
package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

// Status is the normalized verdict of one source for one IOC.
type Status int

const (
	StatusNotFound Status = iota
	StatusInfo
	StatusClean
	StatusSuspicious
	StatusMalicious
	StatusSkipped
	StatusError
)

var statusNames = map[Status]string{
	StatusNotFound:   "not_found",
	StatusInfo:       "info",
	StatusClean:      "clean",
	StatusSuspicious: "suspicious",
	StatusMalicious:  "malicious",
	StatusSkipped:    "skipped",
	StatusError:      "error",
}

func (s Status) String() string { return statusNames[s] }

// Label is the upper-case display label.
func (s Status) Label() string {
	return strings.ToUpper(strings.ReplaceAll(s.String(), "_", " "))
}

func (s Status) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Status) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	for k, v := range statusNames {
		if v == str {
			*s = k
			return nil
		}
	}
	return fmt.Errorf("unknown status %q", str)
}

// Severity orders statuses for picking an overall verdict. Skipped/error = -1.
func (s Status) Severity() int {
	switch s {
	case StatusMalicious:
		return 4
	case StatusSuspicious:
		return 3
	case StatusClean:
		return 2
	case StatusInfo:
		return 1
	case StatusNotFound:
		return 0
	}
	return -1
}

// Field is an ordered key/value detail.
type Field struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Result is what a single source returned for a single IOC.
type Result struct {
	Source     string  `json:"source"`
	Status     Status  `json:"status"`
	Score      string  `json:"score,omitempty"`
	Summary    string  `json:"summary,omitempty"`
	Fields     []Field `json:"fields,omitempty"`
	Link       string  `json:"link,omitempty"`
	Error      string  `json:"error,omitempty"`
	DurationMS int64   `json:"duration_ms"`
}

func (r *Result) add(k, v string) {
	if v = strings.TrimSpace(v); v != "" {
		r.Fields = append(r.Fields, Field{k, v})
	}
}

func (r *Result) addList(k string, vs []string, max int) {
	vs = uniq(vs)
	if len(vs) == 0 {
		return
	}
	extra := ""
	if max > 0 && len(vs) > max {
		extra = fmt.Sprintf(" (+%d)", len(vs)-max)
		vs = vs[:max]
	}
	r.add(k, strings.Join(vs, ", ")+extra)
}

func fail(r Result, err error) Result {
	r.Status = StatusError
	r.Error = err.Error()
	return r
}

// Source is a threat-intelligence provider.
type Source interface {
	ID() string
	Name() string
	Supports(t ioc.Type) bool
	RequiresKey() bool
	Configured() bool
	Query(ctx context.Context, i ioc.IOC) Result
}

// Keys holds API keys for all providers.
type Keys struct {
	VirusTotal     string
	AbuseIPDB      string
	OTX            string
	AbuseCH        string
	GreyNoise      string
	HybridAnalysis string
}

// All returns every provider, configured with keys.
func All(k Keys) []Source {
	return []Source{
		&VirusTotal{Key: k.VirusTotal},
		&MalwareBazaar{Key: k.AbuseCH},
		&ThreatFox{Key: k.AbuseCH},
		&URLhaus{Key: k.AbuseCH},
		&OTX{Key: k.OTX},
		&HybridAnalysis{Key: k.HybridAnalysis},
		&AbuseIPDB{Key: k.AbuseIPDB},
		&GreyNoise{Key: k.GreyNoise},
		&ShodanInternetDB{},
	}
}

// ---------- HTTP helpers ----------

const userAgent = "zuhan/3 (+https://github.com/DNA-Cybertech-Solutions/zuhan)"

var httpClient = &http.Client{}

// HTTPError is a non-2xx, non-404 response.
type HTTPError struct {
	Code int
	Body string
}

func (e *HTTPError) Error() string {
	switch e.Code {
	case 401, 403:
		return fmt.Sprintf("HTTP %d: API key invalid or unauthorized", e.Code)
	case 429:
		return "HTTP 429: rate limit exceeded"
	}
	return fmt.Sprintf("HTTP %d: %s", e.Code, e.Body)
}

func do(ctx context.Context, req *http.Request, headers map[string]string, out any) (int, error) {
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return 0, fmt.Errorf("timeout")
		}
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, &HTTPError{resp.StatusCode, truncate(strings.Join(strings.Fields(string(body)), " "), 200)}
	}
	if out != nil && len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return resp.StatusCode, fmt.Errorf("unexpected response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

func getJSON(ctx context.Context, u string, headers map[string]string, out any) (int, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	return do(ctx, req, headers, out)
}

func postForm(ctx context.Context, u string, form url.Values, headers map[string]string, out any) (int, error) {
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return do(ctx, req, headers, out)
}

func postJSON(ctx context.Context, u string, payload any, headers map[string]string, out any) (int, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	return do(ctx, req, headers, out)
}

// ---------- small utils ----------

// flexStr decodes a JSON string, number, bool or null into a string.
type flexStr string

func (f *flexStr) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexStr(s)
		return nil
	}
	*f = flexStr(b)
	return nil
}

func (f flexStr) String() string { return string(f) }

// decodeArray decodes raw into out only when raw is a JSON array
// (abuse.ch returns a string in "data" when there are no results).
func decodeArray(raw json.RawMessage, out any) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[strings.ToLower(s)] {
			continue
		}
		seen[strings.ToLower(s)] = true
		out = append(out, s)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return strings.TrimRight(v, "/")
}

func typeIn(t ioc.Type, ts ...ioc.Type) bool {
	for _, x := range ts {
		if t == x {
			return true
		}
	}
	return false
}
