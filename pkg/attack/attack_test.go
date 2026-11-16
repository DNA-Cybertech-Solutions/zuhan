package attack

import (
	"encoding/json"
	"testing"
)

func TestLookupAndCollector(t *testing.T) {
	if Version() == "" || len(Tactics()) < 10 {
		t.Fatalf("table not loaded: %q %d", Version(), len(Tactics()))
	}
	tech, ok := Lookup("T1059.001")
	if !ok || tech.Name == "" {
		t.Fatalf("T1059.001: %+v", tech)
	}
	if URL("T1059.001") != "https://attack.mitre.org/techniques/T1059/001/" {
		t.Fatal(URL("T1059.001"))
	}
	var c Collector
	c.Add("T1059.001", "", "Triage", "a.exe")
	c.Add("T1059.001", "", "OTX", "b.exe")
	c.Add("T1105", "", "OTX", "a.exe")
	c.Add("T9999", "Made up", "X", "")
	hits := c.Hits()
	if len(hits) != 3 {
		t.Fatalf("hits %+v", hits)
	}
	var ps Hit
	for _, h := range hits {
		if h.ID == "T1059.001" {
			ps = h
		}
		if h.ID == "T9999" && (h.Known || h.Name != "Made up") {
			t.Fatalf("unknown technique: %+v", h)
		}
	}
	if len(ps.Sources) != 2 || len(ps.IOCs) != 2 || !ps.Known || len(ps.Tactics) == 0 {
		t.Fatalf("merged hit %+v", ps)
	}
	if g := ByTactic(hits); len(g) < 2 || g[len(g)-1].Tactic != "Other" {
		t.Fatalf("by tactic %+v", g)
	}
	b, err := Layer("test", "desc", hits)
	if err != nil {
		t.Fatal(err)
	}
	var layer struct {
		Domain     string `json:"domain"`
		Techniques []struct {
			TechniqueID string `json:"techniqueID"`
			Score       int    `json:"score"`
		} `json:"techniques"`
	}
	if err := json.Unmarshal(b, &layer); err != nil || layer.Domain != "enterprise-attack" || len(layer.Techniques) < 2 {
		t.Fatalf("layer %s %v", b, err)
	}
	for _, lt := range layer.Techniques {
		if lt.TechniqueID == "T1059.001" && lt.Score != 2 {
			t.Fatalf("score %+v", lt)
		}
	}
}
