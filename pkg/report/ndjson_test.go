package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/attack"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/engine"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
)

func ndjsonFixture() []engine.Report {
	t0 := time.Date(2026, 11, 18, 10, 22, 1, 0, time.UTC)
	first := t0.Add(-48 * time.Hour)
	return []engine.Report{
		{
			IOC:       ioc.IOC{Raw: "45[.]137[.]21[.]9", Value: "45.137.21.9", Type: ioc.IPv4},
			Verdict:   sources.StatusMalicious,
			Flagged:   3,
			Queried:   4,
			QueriedAt: t0,
			FirstSeen: &first,
			New:       true,
			Results: []sources.Result{
				{Source: "ThreatFox", Status: sources.StatusMalicious, Link: "https://threatfox.abuse.ch/ioc/1/"},
				{Source: "AlienVault OTX", Status: sources.StatusMalicious, Link: "https://otx.alienvault.com/indicator/ip/45.137.21.9"},
				{Source: "GreyNoise", Status: sources.StatusClean},
				{Source: "VirusTotal", Status: sources.StatusMalicious},
			},
			Attack: []attack.Hit{{ID: "T1071"}, {ID: "T1105"}},
		},
		{
			IOC:       ioc.IOC{Raw: "8.8.8.8", Value: "8.8.8.8", Type: ioc.IPv4},
			Verdict:   sources.StatusClean,
			Queried:   2,
			QueriedAt: t0,
			Benign:    []string{"Public DNS resolvers"},
		},
	}
}

func TestWriteNDJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "ndjson", ndjsonFixture(), Options{Version: "test"}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("output must end with a newline: %q", out)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines (one per IOC), got %d:\n%s", len(lines), out)
	}

	var a map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &a); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v\n%s", err, lines[0])
	}
	if a["ioc_type"] != "ip" {
		t.Errorf("ioc_type = %v, want ip", a["ioc_type"])
	}
	if a["ioc"] != "45.137.21.9" || a["type"] != "ipv4" || a["verdict"] != "malicious" {
		t.Errorf("unexpected core fields: %v", a)
	}
	if a["confidence"] != float64(75) || a["flagged"] != float64(3) || a["queried"] != float64(4) {
		t.Errorf("confidence math wrong: %v", a)
	}
	if a["ts"] != "2026-11-18T10:22:01Z" {
		t.Errorf("ts = %v", a["ts"])
	}
	if a["reference"] != "https://threatfox.abuse.ch/ioc/1/" {
		t.Errorf("reference should be the first malicious source's link, got %v", a["reference"])
	}
	srcs, _ := a["sources"].([]any)
	if len(srcs) != 3 || srcs[0] != "ThreatFox" || srcs[2] != "VirusTotal" {
		t.Errorf("sources = %v", a["sources"])
	}
	if tech, _ := a["techniques"].([]any); len(tech) != 2 || tech[0] != "T1071" {
		t.Errorf("techniques = %v", a["techniques"])
	}
	if a["new"] != true {
		t.Errorf("new flag missing: %v", a)
	}

	var b map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &b); err != nil {
		t.Fatalf("line 2 is not valid JSON: %v", err)
	}
	if b["verdict"] != "clean" || b["confidence"] != float64(0) {
		t.Errorf("clean record wrong: %v", b)
	}
	if s, ok := b["sources"].([]any); !ok || len(s) != 0 {
		t.Errorf("sources must be an empty array, not null: %v", b["sources"])
	}
	if _, has := b["reference"]; has {
		t.Errorf("reference should be omitted when empty: %v", b)
	}
}

func TestNDJSONEmptyInput(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "ndjson", nil, Options{}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("no reports must produce no output, got %q", buf.String())
	}
}

func TestNDJSONFormatFromPath(t *testing.T) {
	for _, p := range []string{"/data/results.ndjson", "x.JSONL"} {
		f, err := FormatFromPath(p)
		if err != nil || f != "ndjson" {
			t.Errorf("FormatFromPath(%q) = %q, %v", p, f, err)
		}
	}
}

func TestIOCCategory(t *testing.T) {
	want := map[ioc.Type]string{
		ioc.MD5: "hash", ioc.SHA1: "hash", ioc.SHA256: "hash", ioc.SHA512: "hash",
		ioc.IPv4: "ip", ioc.IPv6: "ip", ioc.Domain: "domain", ioc.URL: "url", ioc.Unknown: "",
	}
	for typ, w := range want {
		if got := IOCCategory(typ); got != w {
			t.Errorf("IOCCategory(%s) = %q, want %q", typ, got, w)
		}
	}
}
