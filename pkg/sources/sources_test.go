package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

func server(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(h))
	t.Cleanup(s.Close)
	return s.URL
}

func TestVirusTotalFound(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "K" {
			t.Errorf("missing api key header")
		}
		if !strings.HasSuffix(r.URL.Path, "/files/44d88612fea8a8f36de82e1278abb02f") {
			t.Errorf("path %s", r.URL.Path)
		}
		io.WriteString(w, `{"data":{"attributes":{"last_analysis_stats":{"malicious":60,"suspicious":0,"harmless":0,"undetected":10},
		"meaningful_name":"eicar.com","popular_threat_classification":{"suggested_threat_label":"virus.eicar/test"}}}}`)
	})
	r := (&VirusTotal{Key: "K", BaseURL: url}).Query(context.Background(), ioc.Parse("44d88612fea8a8f36de82e1278abb02f"))
	if r.Status != StatusMalicious || r.Score != "60/70" || !strings.Contains(r.Summary, "virus.eicar/test") {
		t.Fatalf("got %+v", r)
	}
}

func TestVirusTotalNotFoundAndAuth(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") == "bad" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(404)
	})
	r := (&VirusTotal{Key: "K", BaseURL: url}).Query(context.Background(), ioc.Parse("example.com"))
	if r.Status != StatusNotFound {
		t.Fatalf("want not_found, got %+v", r)
	}
	r = (&VirusTotal{Key: "bad", BaseURL: url}).Query(context.Background(), ioc.Parse("example.com"))
	if r.Status != StatusError || !strings.Contains(r.Error, "401") {
		t.Fatalf("want auth error, got %+v", r)
	}
}

func TestAbuseIPDB(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ipAddress") != "1.2.3.4" || r.Header.Get("Key") != "K" {
			t.Errorf("bad request %s", r.URL)
		}
		io.WriteString(w, `{"data":{"isPublic":true,"abuseConfidenceScore":100,"countryCode":"CN","isp":"Bad ISP",
		"totalReports":512,"numDistinctUsers":80,"lastReportedAt":"2026-11-09T10:00:00+00:00","isWhitelisted":null}}`)
	})
	r := (&AbuseIPDB{Key: "K", BaseURL: url}).Query(context.Background(), ioc.Parse("1.2.3.4"))
	if r.Status != StatusMalicious || r.Score != "100%" {
		t.Fatalf("got %+v", r)
	}
}

func TestMalwareBazaar(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Header.Get("Auth-Key") != "K" || r.Form.Get("query") != "get_info" {
			t.Errorf("bad request")
		}
		if r.Form.Get("hash") == "aa"+strings.Repeat("0", 62) {
			io.WriteString(w, `{"query_status":"hash_not_found"}`)
			return
		}
		io.WriteString(w, `{"query_status":"ok","data":[{"sha256_hash":"abc","file_name":"x.exe","file_type":"exe",
		"signature":"AgentTesla","first_seen":"2026-01-01 00:00:00","tags":["exe","AgentTesla"],"file_size":1234}]}`)
	})
	s := &MalwareBazaar{Key: "K", BaseURL: url}
	r := s.Query(context.Background(), ioc.Parse(strings.Repeat("b", 64)))
	if r.Status != StatusMalicious || !strings.Contains(r.Summary, "AgentTesla") {
		t.Fatalf("got %+v", r)
	}
	r = s.Query(context.Background(), ioc.Parse("aa"+strings.Repeat("0", 62)))
	if r.Status != StatusNotFound {
		t.Fatalf("got %+v", r)
	}
}

func TestThreatFoxNoResultStringData(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"query_status":"no_result","data":"Your search did not yield any results"}`)
	})
	r := (&ThreatFox{Key: "K", BaseURL: url}).Query(context.Background(), ioc.Parse("evil.example"))
	if r.Status != StatusNotFound {
		t.Fatalf("got %+v", r)
	}
}

func TestThreatFoxHit(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), `"search_ioc"`) {
			t.Errorf("body %s", b)
		}
		io.WriteString(w, `{"query_status":"ok","data":[{"id":"1234","ioc":"1.2.3.4:443","threat_type":"botnet_cc",
		"malware_printable":"Cobalt Strike","confidence_level":100,"first_seen":"2026-10-01","tags":null}]}`)
	})
	r := (&ThreatFox{Key: "K", BaseURL: url}).Query(context.Background(), ioc.Parse("1.2.3.4"))
	if r.Status != StatusMalicious || r.Link != "https://threatfox.abuse.ch/ioc/1234/" || !strings.Contains(r.Summary, "Cobalt Strike") {
		t.Fatalf("got %+v", r)
	}
}

func TestURLhausHost(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/host/" {
			t.Errorf("path %s", r.URL.Path)
		}
		io.WriteString(w, `{"query_status":"ok","urlhaus_reference":"https://urlhaus.abuse.ch/host/evil.example/","url_count":"3",
		"firstseen":"2026-01-01","blacklists":{"spamhaus_dbl":"abused_legit_malware","surbl":"not listed"},
		"urls":[{"url":"http://evil.example/a","url_status":"online","threat":"malware_download","tags":["elf"]},
		        {"url":"http://evil.example/b","url_status":"offline","threat":"malware_download","tags":null}]}`)
	})
	r := (&URLhaus{Key: "K", BaseURL: url}).Query(context.Background(), ioc.Parse("evil.example"))
	if r.Status != StatusMalicious || !strings.Contains(r.Score, "1 online") {
		t.Fatalf("got %+v", r)
	}
}

func TestOTXWhitelisted(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"pulse_info":{"count":40,"pulses":[{"name":"x"}]},"validation":[{"source":"alexa","name":"Alexa top"}]}`)
	})
	r := (&OTX{BaseURL: url}).Query(context.Background(), ioc.Parse("google.com"))
	if r.Status != StatusClean {
		t.Fatalf("got %+v", r)
	}
}

func TestGreyNoiseAndShodan(t *testing.T) {
	gn := server(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"ip":"8.8.8.8","noise":false,"riot":true,"classification":"benign","name":"Google Public DNS"}`)
	})
	if r := (&GreyNoise{BaseURL: gn}).Query(context.Background(), ioc.Parse("8.8.8.8")); r.Status != StatusClean {
		t.Fatalf("greynoise %+v", r)
	}
	sh := server(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"ip":"1.2.3.4","ports":[22,443],"vulns":["CVE-2023-1"],"tags":["c2"],"hostnames":[]}`)
	})
	if r := (&ShodanInternetDB{BaseURL: sh}).Query(context.Background(), ioc.Parse("1.2.3.4")); r.Status != StatusSuspicious {
		t.Fatalf("shodan %+v", r)
	}
}

func TestHybridBothShapes(t *testing.T) {
	arr := server(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[{"verdict":"malicious","threat_score":95,"vx_family":"Emotet","sha256":"abc"}]`)
	})
	r := (&HybridAnalysis{Key: "K", BaseURL: arr}).Query(context.Background(), ioc.Parse(strings.Repeat("c", 64)))
	if r.Status != StatusMalicious || r.Score != "95/100" {
		t.Fatalf("array: %+v", r)
	}
	obj := server(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"sha256s":[],"reports":[]}`)
	})
	r = (&HybridAnalysis{Key: "K", BaseURL: obj}).Query(context.Background(), ioc.Parse(strings.Repeat("c", 64)))
	if r.Status != StatusNotFound {
		t.Fatalf("object: %+v", r)
	}
}

func TestOTXTorAnnotationIsNotWhitelist(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"pulse_info":{"count":50,"pulses":[{"name":"tor exits"}]},
		"validation":[{"source":"tor","name":"IP Associated with Tor Exit Nodes"}]}`)
	})
	r := (&OTX{BaseURL: url}).Query(context.Background(), ioc.Parse("185.220.101.1"))
	if r.Status != StatusMalicious {
		t.Fatalf("got %s (%s)", r.Status, r.Summary)
	}
}

func TestGreyNoiseSummary(t *testing.T) {
	url := server(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"noise":true,"riot":false,"classification":"malicious","name":"unknown","message":"Success"}`)
	})
	r := (&GreyNoise{BaseURL: url}).Query(context.Background(), ioc.Parse("185.220.101.1"))
	if r.Status != StatusMalicious || strings.Contains(r.Summary, "unknown") || strings.Contains(r.Summary, "Success") {
		t.Fatalf("got %s %q", r.Status, r.Summary)
	}
}

func TestVirusTotalLoneEngine(t *testing.T) {
	resp := func(mal, rep int) string {
		return fmt.Sprintf(`{"data":{"attributes":{"last_analysis_stats":{"malicious":%d,"harmless":60,"undetected":31},"reputation":%d,"as_owner":"Google LLC"}}}`, mal, rep)
	}
	cases := []struct {
		mal, rep int
		want     Status
	}{
		{1, 500, StatusClean},      // 8.8.8.8 style
		{1, -20, StatusSuspicious}, // bad community reputation
		{2, 500, StatusSuspicious},
		{3, 500, StatusMalicious},
		{0, 0, StatusClean},
	}
	for _, c := range cases {
		body := resp(c.mal, c.rep)
		url := server(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) })
		r := (&VirusTotal{Key: "K", BaseURL: url}).Query(context.Background(), ioc.Parse("8.8.8.8"))
		if r.Status != c.want {
			t.Errorf("mal=%d rep=%d: got %s", c.mal, c.rep, r.Status)
		}
		if c.mal == 1 && c.want == StatusClean && !strings.Contains(r.Summary, "false positive") {
			t.Errorf("missing FP note: %q", r.Summary)
		}
	}
}
