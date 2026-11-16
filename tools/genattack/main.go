// Command genattack turns MITRE's enterprise-attack.json STIX bundle into the
// compact technique table embedded in pkg/attack.
//
//	git clone --depth 1 --filter=blob:none --sparse https://github.com/mitre-attack/attack-stix-data.git
//	(cd attack-stix-data && git sparse-checkout set --no-cone /enterprise-attack/enterprise-attack.json)
//	go run ./tools/genattack attack-stix-data/enterprise-attack/enterprise-attack.json > pkg/attack/enterprise.json
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type ref struct {
	Source string `json:"source_name"`
	ID     string `json:"external_id"`
}

type obj struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	ShortName  string   `json:"x_mitre_shortname"`
	Revoked    bool     `json:"revoked"`
	Deprecated bool     `json:"x_mitre_deprecated"`
	Sub        bool     `json:"x_mitre_is_subtechnique"`
	TacticRefs []string `json:"tactic_refs"`
	Version    string   `json:"x_mitre_version"`
	Phases     []struct {
		Chain string `json:"kill_chain_name"`
		Phase string `json:"phase_name"`
	} `json:"kill_chain_phases"`
	Refs []ref `json:"external_references"`
}

type tactic struct {
	ID    string `json:"id"`
	Short string `json:"short"`
	Name  string `json:"name"`
}

type tech struct {
	Name    string   `json:"n"`
	Tactics []string `json:"t"`
}

func mitreID(o obj) string {
	for _, r := range o.Refs {
		if r.Source == "mitre-attack" {
			return r.ID
		}
	}
	return ""
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: genattack enterprise-attack.json > enterprise.json")
		os.Exit(2)
	}
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var bundle struct {
		Objects []obj `json:"objects"`
	}
	if err := json.Unmarshal(b, &bundle); err != nil {
		panic(err)
	}

	byID := map[string]obj{}
	var matrix obj
	version := ""
	for _, o := range bundle.Objects {
		byID[o.ID] = o
		switch o.Type {
		case "x-mitre-matrix":
			if !o.Revoked && !o.Deprecated {
				matrix = o
			}
		case "x-mitre-collection":
			version = o.Version
		}
	}

	var tactics []tactic
	for _, ref := range matrix.TacticRefs {
		t := byID[ref]
		tactics = append(tactics, tactic{ID: mitreID(t), Short: t.ShortName, Name: t.Name})
	}

	parents := map[string]string{}
	for _, o := range bundle.Objects {
		if o.Type == "attack-pattern" && !o.Sub && !o.Revoked && !o.Deprecated {
			parents[mitreID(o)] = o.Name
		}
	}
	techs := map[string]tech{}
	for _, o := range bundle.Objects {
		if o.Type != "attack-pattern" || o.Revoked || o.Deprecated {
			continue
		}
		id := mitreID(o)
		if id == "" {
			continue
		}
		name := o.Name
		if o.Sub {
			if p, ok := parents[strings.SplitN(id, ".", 2)[0]]; ok {
				name = p + ": " + name
			}
		}
		var ts []string
		for _, ph := range o.Phases {
			if ph.Chain == "mitre-attack" {
				ts = append(ts, ph.Phase)
			}
		}
		sort.Strings(ts)
		techs[id] = tech{Name: name, Tactics: ts}
	}

	out := struct {
		Version    string          `json:"version"`
		Tactics    []tactic        `json:"tactics"`
		Techniques map[string]tech `json:"techniques"`
	}{version, tactics, techs}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "ATT&CK %s: %d tactics, %d techniques\n", version, len(tactics), len(techs))
}
