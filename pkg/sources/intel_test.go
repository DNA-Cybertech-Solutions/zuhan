package sources

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

func field(r Result, key string) string {
	for _, f := range r.Fields {
		if f.Key == key {
			return f.Value
		}
	}
	return ""
}

func TestThreatFoxFields(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"query_status":"ok","data":[{"id":"77","ioc":"evil.com","threat_type":"botnet_cc",
		"threat_type_desc":"Botnet C2","ioc_type":"domain","malware":"win.cobalt_strike","malware_printable":"Cobalt Strike",
		"malware_alias":"Agentemis,BEACON","malware_malpedia":"https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike",
		"confidence_level":75,"first_seen":"2026-11-01 10:00:00 UTC","last_seen":null,"reporter":"abuse_ch",
		"reference":"https://example.org/r","tags":["c2","cs"]}]}`)
	})
	r := (&ThreatFox{Key: "K", BaseURL: url}).Query(context.Background(), ioc.Parse("evil.com"))
	if r.Status != StatusMalicious || field(r, "Malware") == "" || !strings.Contains(field(r, "Malware aliases"), "BEACON") ||
		field(r, "Reporter") != "abuse_ch" || !strings.Contains(field(r, "Tags"), "c2") {
		t.Fatalf("fields: %+v", r.Fields)
	}
	if r.FirstSeen == nil || r.FirstSeen.Format("2006-01-02") != "2026-11-01" {
		t.Fatalf("first seen %v", r.FirstSeen)
	}
	if !strings.Contains(r.Summary, "75%") || !strings.Contains(r.Summary, "first seen 2026-11-01") {
		t.Fatalf("summary %q", r.Summary)
	}
}

func TestTriage(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer K" {
			t.Errorf("auth %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.URL.Path == "/search":
			if r.URL.Query().Get("query") != "sha256:"+strings.Repeat("a", 64) {
				io.WriteString(w, `{"data":[]}`)
				return
			}
			io.WriteString(w, `{"data":[{"id":"261116-abc","status":"reported","filename":"inv.exe","submitted":"2026-11-15T08:00:00Z"}]}`)
		case r.URL.Path == "/samples/261116-abc/overview.json":
			io.WriteString(w, `{"sample":{"score":10,"created":"2026-11-15T08:00:00Z","target":"inv.exe"},
			"analysis":{"score":10,"family":["asyncrat"],"tags":["family:asyncrat","rat"]},
			"signatures":[{"name":"AsyncRat","score":10,"ttp":["T1219"]},{"name":"Checks computer location","score":3,"ttp":["T1614"]}],
			"extracted":[{"config":{"family":"asyncrat","c2":["10.9.8.7:6606"]}}]}`)
		default:
			w.WriteHeader(404)
		}
	})
	src := &Triage{Key: "K", BaseURL: url}
	r := src.Query(context.Background(), ioc.Parse(strings.Repeat("a", 64)))
	if r.Status != StatusMalicious || !strings.Contains(r.Summary+field(r, "Family"), "asyncrat") ||
		!strings.Contains(field(r, "Extracted C2"), "10.9.8.7:6606") || r.Link != "https://tria.ge/261116-abc" {
		t.Fatalf("got %+v", r)
	}
	ids := map[string]bool{}
	for _, x := range r.Techniques {
		ids[x.ID] = true
	}
	if !ids["T1219"] {
		t.Fatalf("techniques %+v", r.Techniques)
	}
	if r.FirstSeen == nil {
		t.Fatal("first seen not set")
	}
	if r := src.Query(context.Background(), ioc.Parse(strings.Repeat("b", 64))); r.Status != StatusNotFound {
		t.Fatalf("want not found, got %+v", r)
	}
	if (&Triage{}).Configured() || src.Supports(ioc.Domain) {
		t.Fatal("triage should need a key and only take hashes")
	}
}

func TestURLScan(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "bad.com") && r.Header.Get("API-Key") != "K" {
			t.Errorf("key header")
		}
		if !strings.HasPrefix(q, "domain:bad.com") && !strings.Contains(q, "domain:bad.com") {
			io.WriteString(w, `{"total":0,"results":[]}`)
			return
		}
		if strings.Contains(q, "verdicts.malicious:true") {
			io.WriteString(w, `{"total":2,"results":[{"_id":"m1","task":{"time":"2026-11-10T00:00:00Z"},"page":{"domain":"bad.com","ip":"5.6.7.8"},"verdicts":{"malicious":true}},{"_id":"m2","task":{"time":"2026-11-11T00:00:00Z"},"page":{"domain":"bad.com"},"verdicts":{"malicious":true}}]}`)
			return
		}
		io.WriteString(w, `{"total":5,"results":[{"_id":"s1","task":{"time":"2026-11-12T00:00:00Z","url":"https://bad.com/"},"page":{"domain":"bad.com","ip":"5.6.7.8","country":"NL","server":"nginx","asnname":"BADNET"}}]}`)
	})
	r := (&URLScan{Key: "K", BaseURL: url}).Query(context.Background(), ioc.Parse("bad.com"))
	if r.Status != StatusMalicious || field(r, "Malicious scans") != "2" || !strings.Contains(field(r, "Hosting IPs"), "5.6.7.8") {
		t.Fatalf("got %+v", r)
	}
	r = (&URLScan{BaseURL: url}).Query(context.Background(), ioc.Parse("fine.com"))
	if r.Status != StatusNotFound {
		t.Fatalf("want not found, got %+v", r)
	}
}

func TestPassiveDNS(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Argus-API-Key") != "K" || !strings.HasPrefix(r.URL.Path, "/pdns/v3/") {
			t.Errorf("bad request %s", r.URL)
		}
		if !strings.HasSuffix(r.URL.Path, "/bad.com") {
			io.WriteString(w, `{"count":0,"data":[]}`)
			return
		}
		io.WriteString(w, `{"count":2,"data":[
		{"query":"bad.com","answer":"5.6.7.8","rrtype":"a","firstSeenTimestamp":1730000000000,"lastSeenTimestamp":1762000000000},
		{"query":"bad.com","answer":"9.9.9.1","rrtype":"a","firstSeenTimestamp":1700000000000,"lastSeenTimestamp":1710000000000}]}`)
	})
	src := &PassiveDNS{Key: "K", BaseURL: url}
	r := src.Query(context.Background(), ioc.Parse("bad.com"))
	if r.Status != StatusInfo || !strings.Contains(fmtFields(r), "5.6.7.8") || !strings.Contains(fmtFields(r), "9.9.9.1") {
		t.Fatalf("got %+v", r)
	}
	if r := src.Query(context.Background(), ioc.Parse("none.com")); r.Status != StatusNotFound {
		t.Fatalf("want not found, got %+v", r)
	}
}

func fmtFields(r Result) string {
	var b strings.Builder
	for _, f := range r.Fields {
		b.WriteString(f.Key + "=" + f.Value + "\n")
	}
	return b.String() + r.Summary
}

func TestRDAPDomainWalkUpAndNewlyRegistered(t *testing.T) {
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	var paths []string
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/domain/new.com":
			http.Redirect(w, r, "/registry/domain/new.com", http.StatusFound)
		case "/registry/domain/new.com":
			io.WriteString(w, `{"ldhName":"NEW.COM","status":["active"],
			"events":[{"eventAction":"registration","eventDate":"2026-11-10T00:00:00Z"},{"eventAction":"expiration","eventDate":"2027-11-10T00:00:00Z"}],
			"nameservers":[{"ldhName":"NS1.EVILDNS.NET"}],
			"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Cheap Registrar LLC"]]]}]}`)
		case "/domain/old.com":
			io.WriteString(w, `{"ldhName":"old.com","events":[{"eventAction":"registration","eventDate":"2001-01-01T00:00:00Z"}]}`)
		default:
			w.WriteHeader(404)
		}
	})
	src := &RDAP{BaseURL: url, Now: func() time.Time { return now }}
	r := src.Query(context.Background(), ioc.Parse("a.b.new.com"))
	if r.Status != StatusSuspicious || !strings.Contains(r.Context, "Newly registered") ||
		field(r, "Registrar") != "Cheap Registrar LLC" || !strings.Contains(field(r, "Name servers"), "ns1.evildns.net") {
		t.Fatalf("got %+v (paths %v)", r, paths)
	}
	if paths[0] != "/domain/a.b.new.com" || paths[1] != "/domain/b.new.com" {
		t.Fatalf("walk-up order %v", paths)
	}
	if r := src.Query(context.Background(), ioc.Parse("old.com")); r.Status != StatusInfo || r.Context != "" {
		t.Fatalf("old domain: %+v", r)
	}
	if r := src.Query(context.Background(), ioc.Parse("x.unknown-tld")); r.Status != StatusNotFound {
		t.Fatalf("want not found, got %+v", r)
	}
}

func TestRDAPIP(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"handle":"NET-1","name":"EXAMPLE-NET","country":"US","startAddress":"1.2.3.0","endAddress":"1.2.3.255",
		"entities":[{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse Desk"],["email",{},"text","abuse@example.net"]]]}]}`)
	})
	r := (&RDAP{BaseURL: url}).Query(context.Background(), ioc.Parse("1.2.3.4"))
	if r.Status != StatusInfo || field(r, "Country") != "US" || !strings.Contains(field(r, "Range"), "1.2.3.0") {
		t.Fatalf("got %+v", r)
	}
}

type fakeResolver struct{}

func (fakeResolver) LookupIPAddr(_ context.Context, h string) ([]net.IPAddr, error) {
	switch h {
	case "good.com":
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	case "intranet.com":
		return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
}
func (fakeResolver) LookupCNAME(_ context.Context, h string) (string, error) { return h + ".", nil }
func (fakeResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return []*net.MX{{Host: "mx.good.com.", Pref: 10}}, nil
}
func (fakeResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	return []*net.NS{{Host: "ns1.good.com."}}, nil
}
func (fakeResolver) LookupAddr(_ context.Context, a string) ([]string, error) {
	if a == "8.8.8.8" {
		return []string{"dns.google."}, nil
	}
	return nil, errors.New("no PTR")
}

func TestDNSSource(t *testing.T) {
	src := &DNS{Resolver: fakeResolver{}}
	if !src.OptIn() || !IsOptIn(src) {
		t.Fatal("DNS must be opt-in")
	}
	r := src.Query(context.Background(), ioc.Parse("good.com"))
	if r.Status != StatusInfo || !strings.Contains(fmtFields(r), "93.184.216.34") || !strings.Contains(fmtFields(r), "mx.good.com") {
		t.Fatalf("good: %+v", r)
	}
	if r := src.Query(context.Background(), ioc.Parse("gone.com")); r.Context != "Does not resolve" {
		t.Fatalf("nxdomain: %+v", r)
	}
	if r := src.Query(context.Background(), ioc.Parse("intranet.com")); !strings.Contains(r.Context, "private") {
		t.Fatalf("private: %+v", r)
	}
	if r := src.Query(context.Background(), ioc.Parse("8.8.8.8")); !strings.Contains(fmtFields(r), "dns.google") {
		t.Fatalf("ptr: %+v", r)
	}
	if r := src.Query(context.Background(), ioc.Parse(strings.Repeat("a", 32))); r.Status != StatusSkipped && src.Supports(ioc.MD5) {
		t.Fatalf("hash: %+v", r)
	}
	if got := Default([]Source{src, &RDAP{}}); len(got) != 1 || got[0].ID() != "rdap" {
		t.Fatalf("Default should drop opt-in sources: %v", got)
	}
}

func TestTechniqueValidation(t *testing.T) {
	var r Result
	r.technique("T1059.001", "PowerShell")
	r.technique("t1105", "")
	r.technique("TA0001", "tactic, not technique")
	r.technique("T1059.001", "dup")
	if len(r.Techniques) != 2 || r.Techniques[1].ID != "T1105" {
		t.Fatalf("got %+v", r.Techniques)
	}
}

func TestURLScanURLFallbacks(t *testing.T) {
	var seen []string
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		seen = append(seen, q)
		switch {
		case strings.HasPrefix(q, "page.url:"):
			w.WriteHeader(502)
			io.WriteString(w, `<!DOCTYPE html><html><head><title>urlscan.io - Error</title></head></html>`)
		case strings.HasPrefix(q, "page.domain:shop.example"):
			io.WriteString(w, `{"total":3,"results":[{"_id":"h1","task":{"time":"2026-11-01T00:00:00Z"},"page":{"domain":"shop.example","ip":"5.6.7.8"},"verdicts":{"malicious":true}}]}`)
		case strings.HasPrefix(q, "(page.domain:shop.example"):
			io.WriteString(w, `{"total":1,"results":[]}`)
		default:
			io.WriteString(w, `{"total":0,"results":[]}`)
		}
	})
	r := (&URLScan{BaseURL: url}).Query(context.Background(), ioc.Parse("https://shop.example/login"))
	if r.Status != StatusSuspicious || !strings.HasPrefix(field(r, "Matched on"), "host only") || !strings.HasPrefix(r.Summary, "host:") {
		t.Fatalf("host fallback: %+v (queries %q)", r, seen)
	}
	if len(seen) < 4 || !strings.HasPrefix(seen[1], "task.url:") {
		t.Fatalf("queries tried: %q", seen)
	}

	// every variant fails → readable error, not an HTML dump
	r = (&URLScan{BaseURL: url}).Query(context.Background(), ioc.Parse("https://other.example/x"))
	if r.Status != StatusNotFound {
		t.Fatalf("partial failures but a clean miss: %+v", r)
	}
	bad := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502)
		io.WriteString(w, `<!DOCTYPE html><html></html>`)
	})
	r = (&URLScan{BaseURL: bad}).Query(context.Background(), ioc.Parse("https://other.example/x"))
	if r.Status != StatusError || strings.Contains(r.Error, "<") || !strings.Contains(r.Error, "502") {
		t.Fatalf("error text: %+v", r)
	}
}

func TestHTTPErrorText(t *testing.T) {
	if e := (&HTTPError{400, `{"message":"DNS Error","description":"bad query"}`}).Error(); e != "HTTP 400: DNS Error — bad query" {
		t.Fatal(e)
	}
	if e := (&HTTPError{503, `<html>oops</html>`}).Error(); strings.Contains(e, "<") {
		t.Fatal(e)
	}
}

func TestThreatFoxRelatedOnly(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"query_status":"ok","data":[
		{"id":"1","ioc":"https://google.com/url?q=evil","threat_type":"payload_delivery","malware_printable":"Triada","confidence_level":100,"first_seen":"2026-11-15 10:00:00 UTC"},
		{"id":"2","ioc":"http://google.com/x.php","threat_type":"botnet_cc","malware_printable":"WARDENStealer","confidence_level":75,"first_seen":"2024-09-25 10:00:00 UTC"}]}`)
	})
	r := (&ThreatFox{Key: "K", BaseURL: url}).Query(context.Background(), ioc.Parse("google.com"))
	if r.Status != StatusSuspicious || r.FirstSeen != nil || !strings.HasPrefix(r.Summary, "not listed itself; 2 related") {
		t.Fatalf("related only: %+v", r)
	}
	for in, want := range map[string]bool{"1.2.3.4:443": true, "1.2.3.4": true, "1.2.3.45": false, "evil.com:8080": true, "https://evil.com/": false} {
		v := "1.2.3.4"
		if strings.Contains(in, "evil") {
			v = "evil.com"
		}
		if got := threatFoxExact(ioc.Parse(v), in); got != want {
			t.Errorf("%s vs %s: %v", v, in, got)
		}
	}
}
