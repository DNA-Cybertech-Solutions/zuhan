// Package report renders scan results as terminal tables or report files.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/attack"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/engine"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
)

// Options controls rendering.
type Options struct {
	Color     bool
	Verbose   bool
	Generated time.Time
	Version   string
}

// Formats lists the supported output formats.
var Formats = []string{"table", "json", "ndjson", "md", "csv", "html"}

// FormatFromPath infers the report format from a file extension.
func FormatFromPath(path string) (string, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "json", nil
	case ".ndjson", ".jsonl":
		return "ndjson", nil
	case ".md", ".markdown":
		return "md", nil
	case ".csv":
		return "csv", nil
	case ".html", ".htm":
		return "html", nil
	case ".txt", ".log":
		return "table", nil
	}
	return "", fmt.Errorf("unknown report extension %q (use .html .json .ndjson .md .csv .txt)", filepath.Ext(path))
}

// Write renders reps in the given format.
func Write(w io.Writer, format string, reps []engine.Report, opt Options) error {
	if opt.Generated.IsZero() {
		opt.Generated = time.Now()
	}
	switch format {
	case "table", "":
		return writeTable(w, reps, opt)
	case "json":
		return writeJSON(w, reps, opt)
	case "ndjson", "jsonl":
		return writeNDJSON(w, reps, opt)
	case "md", "markdown":
		return writeMarkdown(w, reps, opt)
	case "csv":
		return writeCSV(w, reps)
	case "html":
		return writeHTML(w, reps, opt)
	}
	return fmt.Errorf("unknown format %q (supported: %s)", format, strings.Join(Formats, ", "))
}

// Stats counts verdicts across reports.
type Stats struct {
	Total, Malicious, Suspicious, Clean, NotFound, Other int
}

// Summarize computes Stats.
func Summarize(reps []engine.Report) Stats {
	s := Stats{Total: len(reps)}
	for _, r := range reps {
		switch r.Verdict {
		case sources.StatusMalicious:
			s.Malicious++
		case sources.StatusSuspicious:
			s.Suspicious++
		case sources.StatusClean, sources.StatusInfo:
			s.Clean++
		case sources.StatusNotFound:
			s.NotFound++
		default:
			s.Other++
		}
	}
	return s
}

// ---------------- table ----------------

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cMag    = "\033[35m"
	cCyan   = "\033[36m"
	cGray   = "\033[90m"
)

func statusColor(s sources.Status) string {
	switch s {
	case sources.StatusMalicious:
		return cBold + cRed
	case sources.StatusSuspicious:
		return cBold + cYellow
	case sources.StatusClean:
		return cGreen
	case sources.StatusInfo:
		return cCyan
	case sources.StatusError:
		return cMag
	}
	return cGray
}

func pad(s string, n int) string {
	if l := utf8.RuneCountInString(s); l < n {
		return s + strings.Repeat(" ", n-l)
	}
	return s
}

func writeTable(w io.Writer, reps []engine.Report, opt Options) error {
	c := func(code, s string) string {
		if !opt.Color {
			return s
		}
		return code + s + cReset
	}
	srcW := 10
	for _, rep := range reps {
		for _, r := range rep.Results {
			if l := utf8.RuneCountInString(r.Source); l > srcW {
				srcW = l
			}
		}
	}
	line := strings.Repeat("─", 78)
	for _, rep := range reps {
		fmt.Fprintln(w, c(cDim, strings.Repeat("═", 78)))
		fmt.Fprintf(w, " %s %s\n", c(cBold, "IOC     :"), c(cBold, rep.IOC.Value))
		if rep.IOC.Raw != rep.IOC.Value {
			fmt.Fprintf(w, " %s %s\n", "Input   :", rep.IOC.Raw)
		}
		fmt.Fprintf(w, " %s %s\n", "Type    :", rep.IOC.Type)
		for _, k := range []string{"md5", "sha1", "sha256", "size"} {
			if v, ok := rep.IOC.Meta[k]; ok {
				fmt.Fprintf(w, " %s %s\n", pad(strings.ToUpper(k), 8)+":", v)
			}
		}
		fmt.Fprintf(w, " %s %s  %s\n", "Verdict :", c(statusColor(rep.Verdict), rep.Verdict.Label()),
			c(cDim, fmt.Sprintf("(%d/%d sources flagged)", rep.Flagged, rep.Queried)))
		if rep.LocalDB != "" {
			fmt.Fprintf(w, " %s %s\n", "Local DB:", c(cCyan, localDBText(rep.LocalDB)))
		}
		for _, n := range Notes(rep, opt.Generated) {
			fmt.Fprintf(w, " %s %s\n", c(noteColor(n.Kind), pad(n.Tag, 13)), n.Text)
		}
		for _, h := range rep.Attack {
			fmt.Fprintf(w, " %s %s %s\n", c(cMag, pad("ATT&CK", 13)), attack.Describe(h), c(cGray, "← "+strings.Join(h.Sources, ", ")))
		}
		fmt.Fprintln(w, c(cDim, line))
		if len(rep.Results) == 0 {
			fmt.Fprintln(w, "  no source supports this IOC type")
		}
		for _, r := range rep.Results {
			label := pad("["+r.Status.Label()+"]", 13)
			detail := r.Summary
			if r.Error != "" {
				detail = r.Error
			}
			fmt.Fprintf(w, " %s %s %s %s\n",
				c(statusColor(r.Status), label),
				pad(r.Source, srcW),
				pad(r.Score, 16),
				truncRunes(detail, 70))
			if opt.Verbose {
				for _, f := range r.Fields {
					fmt.Fprintf(w, "      %s %s\n", c(cGray, pad(f.Key+":", 20)), f.Value)
				}
				if r.Link != "" {
					fmt.Fprintf(w, "      %s %s\n", c(cGray, pad("Link:", 20)), c(cBlue, r.Link))
				}
			}
		}
	}
	if len(reps) > 0 {
		s := Summarize(reps)
		fmt.Fprintln(w, c(cDim, strings.Repeat("═", 78)))
		fmt.Fprintf(w, " Summary: %d IOC(s) — %s, %s, %s, %s\n", s.Total,
			c(statusColor(sources.StatusMalicious), fmt.Sprintf("%d malicious", s.Malicious)),
			c(statusColor(sources.StatusSuspicious), fmt.Sprintf("%d suspicious", s.Suspicious)),
			c(statusColor(sources.StatusClean), fmt.Sprintf("%d clean", s.Clean)),
			c(cGray, fmt.Sprintf("%d not found", s.NotFound)))
		if hits := Techniques(reps); len(hits) > 0 && len(reps) > 1 {
			fmt.Fprintf(w, " ATT&CK : %d technique(s) — %s\n", len(hits), techIDs(hits))
		}
	}
	return nil
}

func noteColor(kind string) string {
	switch kind {
	case "new":
		return cBold + cRed
	case "unknown":
		return cBold + cYellow
	case "benign", "downgraded":
		return cGreen
	case "context":
		return cCyan
	}
	return cGray
}

func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// ---------------- json ----------------

func writeJSON(w io.Writer, reps []engine.Report, opt Options) error {
	out := struct {
		Tool      string          `json:"tool"`
		Version   string          `json:"version,omitempty"`
		Generated time.Time       `json:"generated"`
		Summary   Stats           `json:"summary"`
		Attack    []attack.Hit    `json:"attack,omitempty"`
		Reports   []engine.Report `json:"reports"`
	}{"zuhan", opt.Version, opt.Generated.UTC(), Summarize(reps), Techniques(reps), reps}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

// ---------------- csv ----------------

func writeCSV(w io.Writer, reps []engine.Report) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"ioc", "type", "verdict", "source", "status", "score", "summary", "details", "link", "error", "local_db",
		"first_seen", "flags", "benign", "context", "attack"})
	for _, rep := range reps {
		first := ""
		if rep.FirstSeen != nil {
			first = rep.FirstSeen.UTC().Format(time.RFC3339)
		}
		var flags []string
		for _, f := range []struct {
			on   bool
			name string
		}{{rep.New, "new"}, {rep.Unknown, "unknown"}, {rep.Downgraded, "downgraded"}} {
			if f.on {
				flags = append(flags, f.name)
			}
		}
		extra := []string{first, strings.Join(flags, " "), strings.Join(rep.Benign, "; "), strings.Join(rep.Context, "; "), techIDs(rep.Attack)}
		for _, r := range rep.Results {
			var det []string
			for _, f := range r.Fields {
				det = append(det, f.Key+"="+f.Value)
			}
			if err := cw.Write(append([]string{rep.IOC.Value, string(rep.IOC.Type), rep.Verdict.String(),
				r.Source, r.Status.String(), r.Score, r.Summary, strings.Join(det, "; "), r.Link, r.Error, rep.LocalDB}, extra...)); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

// ---------------- markdown ----------------

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

func writeMarkdown(w io.Writer, reps []engine.Report, opt Options) error {
	s := Summarize(reps)
	fmt.Fprintf(w, "# ZUHAN IOC Report\n\n")
	fmt.Fprintf(w, "_Generated %s by ZUHAN %s_\n\n", opt.Generated.Format("2006-01-02 15:04:05 MST"), opt.Version)
	fmt.Fprintf(w, "**%d IOC(s)** — %d malicious · %d suspicious · %d clean · %d not found\n\n",
		s.Total, s.Malicious, s.Suspicious, s.Clean, s.NotFound)
	fmt.Fprintln(w, "| IOC | Type | Verdict | Flagged | Notes |")
	fmt.Fprintln(w, "|---|---|---|---|---|")
	for _, rep := range reps {
		var tags []string
		for _, n := range Notes(rep, opt.Generated) {
			if n.Kind != "context" && n.Kind != "first_seen" {
				tags = append(tags, n.Tag)
			}
		}
		fmt.Fprintf(w, "| `%s` | %s | **%s** | %d/%d | %s |\n", mdEsc(rep.IOC.Value), rep.IOC.Type,
			rep.Verdict.Label(), rep.Flagged, rep.Queried, strings.Join(tags, ", "))
	}
	if hits := Techniques(reps); len(hits) > 0 {
		fmt.Fprintf(w, "\n## MITRE ATT&CK (%d techniques)\n\n", len(hits))
		for _, g := range attack.ByTactic(hits) {
			var ts []string
			for _, h := range g.Hits {
				ts = append(ts, fmt.Sprintf("[%s](%s) %s", h.ID, attack.URL(h.ID), mdEsc(h.Name)))
			}
			fmt.Fprintf(w, "- **%s:** %s\n", g.Tactic, strings.Join(ts, " · "))
		}
	}
	for _, rep := range reps {
		fmt.Fprintf(w, "\n## `%s`\n\n", mdEsc(rep.IOC.Value))
		fmt.Fprintf(w, "- **Type:** %s\n- **Verdict:** %s (%d/%d sources flagged)\n",
			rep.IOC.Type, rep.Verdict.Label(), rep.Flagged, rep.Queried)
		if rep.LocalDB != "" {
			fmt.Fprintf(w, "- **Local DB:** %s\n", localDBText(rep.LocalDB))
		}
		for _, n := range Notes(rep, opt.Generated) {
			fmt.Fprintf(w, "- **%s:** %s\n", n.Tag, mdEsc(n.Text))
		}
		if len(rep.Attack) > 0 {
			var ts []string
			for _, h := range rep.Attack {
				ts = append(ts, fmt.Sprintf("[%s](%s) %s", h.ID, attack.URL(h.ID), mdEsc(h.Name)))
			}
			fmt.Fprintf(w, "- **ATT&CK:** %s\n", strings.Join(ts, " · "))
		}
		for _, k := range []string{"file", "md5", "sha1", "sha256", "size"} {
			if v, ok := rep.IOC.Meta[k]; ok {
				fmt.Fprintf(w, "- **%s:** `%s`\n", strings.ToUpper(k), v)
			}
		}
		fmt.Fprintln(w, "\n| Source | Status | Score | Summary | Link |")
		fmt.Fprintln(w, "|---|---|---|---|---|")
		for _, r := range rep.Results {
			sum := r.Summary
			if r.Error != "" {
				sum = "⚠ " + r.Error
			}
			link := ""
			if r.Link != "" {
				link = "[open](" + r.Link + ")"
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n", r.Source, r.Status.Label(), mdEsc(r.Score), mdEsc(sum), link)
		}
		for _, r := range rep.Results {
			if len(r.Fields) == 0 {
				continue
			}
			fmt.Fprintf(w, "\n<details><summary>%s details</summary>\n\n", r.Source)
			for _, f := range r.Fields {
				fmt.Fprintf(w, "- **%s:** %s\n", f.Key, mdEsc(f.Value))
			}
			fmt.Fprintln(w, "\n</details>")
		}
	}
	return nil
}

func localDBText(s string) string {
	switch s {
	case "added":
		return "added to local IOC list"
	case "updated":
		return "updated in local IOC list"
	case "matched":
		return "already in local IOC list"
	case "skipped_benign":
		return "not added: on a benign allow-list"
	case "skipped_threshold":
		return "not added: flagged by too few sources"
	}
	return s
}
