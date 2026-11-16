// Package attack maps MITRE ATT&CK technique IDs to names and tactics,
// summarises techniques seen across scan results, and exports them as an
// ATT&CK Navigator layer.
//
// The technique table (enterprise.json) is generated from MITRE's STIX data
// with tools/genattack. ATT&CK® is a registered trademark of The MITRE
// Corporation; the data is © The MITRE Corporation and is reproduced and
// distributed with the permission of The MITRE Corporation.
package attack

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
	"sync"
)

//go:embed enterprise.json
var raw []byte

// Tactic is one ATT&CK tactic (matrix column).
type Tactic struct {
	ID    string `json:"id"`    // TA0002
	Short string `json:"short"` // execution
	Name  string `json:"name"`  // Execution
}

// Technique is one (sub-)technique.
type Technique struct {
	ID      string
	Name    string
	Tactics []string // tactic short names
}

type table struct {
	Version    string   `json:"version"`
	Tactics    []Tactic `json:"tactics"`
	Techniques map[string]struct {
		Name    string   `json:"n"`
		Tactics []string `json:"t"`
	} `json:"techniques"`
	order map[string]int // tactic short name -> column
	names map[string]string
}

var (
	once sync.Once
	tab  table
)

func load() *table {
	once.Do(func() {
		if err := json.Unmarshal(raw, &tab); err != nil {
			panic("attack: corrupt embedded table: " + err.Error())
		}
		tab.order = map[string]int{}
		tab.names = map[string]string{}
		for k, t := range tab.Tactics {
			tab.order[t.Short] = k
			tab.names[t.Short] = t.Name
		}
	})
	return &tab
}

// Version is the embedded ATT&CK release (e.g. "20.1").
func Version() string { return load().Version }

// Tactics returns the tactics in matrix order.
func Tactics() []Tactic { return load().Tactics }

// TacticName turns a short name ("command-and-control") into its display name.
func TacticName(short string) string {
	if n, ok := load().names[short]; ok {
		return n
	}
	return short
}

// Lookup finds a technique by ID (case-insensitive).
func Lookup(id string) (Technique, bool) {
	id = strings.ToUpper(strings.TrimSpace(id))
	t, ok := load().Techniques[id]
	if !ok {
		return Technique{ID: id}, false
	}
	return Technique{ID: id, Name: t.Name, Tactics: t.Tactics}, true
}

// URL is the technique's page on attack.mitre.org.
func URL(id string) string {
	return "https://attack.mitre.org/techniques/" + strings.ReplaceAll(strings.ToUpper(id), ".", "/") + "/"
}

// Hit is a technique seen in scan results.
type Hit struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics,omitempty"` // display names, matrix order
	Sources []string `json:"sources"`
	IOCs    []string `json:"iocs,omitempty"`
	Known   bool     `json:"known"` // found in the embedded ATT&CK table
}

// Collector merges technique references from many sources and IOCs.
type Collector struct {
	m map[string]*Hit
}

// Add records that source reported technique id for ioc (ioc may be empty).
func (c *Collector) Add(id, fallbackName, source, ioc string) {
	t, known := Lookup(id)
	if t.ID == "" {
		return
	}
	if c.m == nil {
		c.m = map[string]*Hit{}
	}
	h, ok := c.m[t.ID]
	if !ok {
		name := t.Name
		if name == "" {
			name = fallbackName
		}
		h = &Hit{ID: t.ID, Name: name, Known: known}
		shorts := append([]string(nil), t.Tactics...)
		sort.Slice(shorts, func(a, b int) bool { return load().order[shorts[a]] < load().order[shorts[b]] })
		for _, s := range shorts {
			h.Tactics = append(h.Tactics, TacticName(s))
		}
		c.m[t.ID] = h
	}
	h.Sources = addOnce(h.Sources, source)
	h.IOCs = addOnce(h.IOCs, ioc)
}

// AddHits merges already-built hits (e.g. per-IOC summaries into a scan summary).
func (c *Collector) AddHits(hits []Hit, ioc string) {
	for _, h := range hits {
		for _, s := range h.Sources {
			c.Add(h.ID, h.Name, s, ioc)
		}
	}
}

// Hits returns the merged techniques sorted by first tactic, then ID.
func (c *Collector) Hits() []Hit {
	out := make([]Hit, 0, len(c.m))
	for _, h := range c.m {
		out = append(out, *h)
	}
	col := func(h Hit) int {
		t, ok := Lookup(h.ID)
		if !ok || len(t.Tactics) == 0 {
			return 1 << 20
		}
		best := 1 << 20
		for _, s := range t.Tactics {
			if o, ok := load().order[s]; ok && o < best {
				best = o
			}
		}
		return best
	}
	sort.Slice(out, func(a, b int) bool {
		ca, cb := col(out[a]), col(out[b])
		if ca != cb {
			return ca < cb
		}
		return out[a].ID < out[b].ID
	})
	return out
}

// ByTactic groups hits under each tactic (a technique can sit under several).
func ByTactic(hits []Hit) []struct {
	Tactic string `json:"tactic"`
	Hits   []Hit  `json:"techniques"`
} {
	var out []struct {
		Tactic string `json:"tactic"`
		Hits   []Hit  `json:"techniques"`
	}
	idx := map[string]int{}
	for _, t := range Tactics() {
		idx[t.Name] = len(out)
		out = append(out, struct {
			Tactic string `json:"tactic"`
			Hits   []Hit  `json:"techniques"`
		}{Tactic: t.Name})
	}
	other := -1
	for _, h := range hits {
		if len(h.Tactics) == 0 {
			if other < 0 {
				other = len(out)
				out = append(out, struct {
					Tactic string `json:"tactic"`
					Hits   []Hit  `json:"techniques"`
				}{Tactic: "Other"})
			}
			out[other].Hits = append(out[other].Hits, h)
			continue
		}
		for _, t := range h.Tactics {
			if k, ok := idx[t]; ok {
				out[k].Hits = append(out[k].Hits, h)
			}
		}
	}
	// drop empty tactics
	keep := out[:0]
	for _, g := range out {
		if len(g.Hits) > 0 {
			keep = append(keep, g)
		}
	}
	return keep
}

// Layer builds an ATT&CK Navigator layer (format 4.5). A technique's score
// is the number of IOCs it was seen with (at least 1).
func Layer(name, description string, hits []Hit) ([]byte, error) {
	type ltech struct {
		TechniqueID string `json:"techniqueID"`
		Score       int    `json:"score"`
		Color       string `json:"color"`
		Comment     string `json:"comment"`
		Enabled     bool   `json:"enabled"`
		ShowSub     bool   `json:"showSubtechniques"`
	}
	max := 1
	var techs []ltech
	for _, h := range hits {
		score := len(h.IOCs)
		if score < 1 {
			score = 1
		}
		if score > max {
			max = score
		}
		comment := "Reported by: " + strings.Join(h.Sources, ", ")
		if len(h.IOCs) > 0 {
			comment += "\nIOCs: " + strings.Join(h.IOCs, ", ")
		}
		techs = append(techs, ltech{TechniqueID: h.ID, Score: score, Comment: comment, Enabled: true, ShowSub: strings.Contains(h.ID, ".")})
	}
	major := strings.SplitN(Version(), ".", 2)[0]
	layer := map[string]any{
		"name":         name,
		"description":  description,
		"domain":       "enterprise-attack",
		"versions":     map[string]string{"attack": major, "navigator": "5.1.0", "layer": "4.5"},
		"sorting":      3,
		"layout":       map[string]any{"layout": "side", "showName": true, "showID": true},
		"hideDisabled": false,
		"techniques":   techs,
		"gradient": map[string]any{
			"colors":   []string{"#fde0dd", "#c62828"},
			"minValue": 0,
			"maxValue": max,
		},
		"legendItems": []any{},
		"metadata": []map[string]string{
			{"name": "generator", "value": "ZUHAN"},
			{"name": "ATT&CK data", "value": "ATT&CK v" + Version()},
		},
		"showTacticRowBackground": true,
		"tacticRowBackground":     "#205b8f",
	}
	return json.MarshalIndent(layer, "", "  ")
}

func addOnce(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// Describe renders a hit as "T1059.001 Command and Scripting Interpreter: PowerShell (Execution)".
func Describe(h Hit) string {
	s := h.ID
	if h.Name != "" {
		s += " " + h.Name
	}
	if len(h.Tactics) > 0 {
		s += " (" + strings.Join(h.Tactics, ", ") + ")"
	}
	return s
}
