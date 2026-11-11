package store

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/extract"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
)

// ToolName marks files written by ZUHAN. Files marked "iocscan" (the
// project's former name) are still accepted on import.
const ToolName = "zuhan"

// ExportFormats are the formats WriteEntries supports.
var ExportFormats = []string{"txt", "json", "csv"}

// WriteEntries writes entries as txt (one value per line), json (the
// FileFormat, re-importable) or csv.
func WriteEntries(w io.Writer, format string, es []Entry) error {
	switch format {
	case "txt":
		for _, e := range es {
			if _, err := fmt.Fprintln(w, e.Value); err != nil {
				return err
			}
		}
		return nil
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if es == nil {
			es = []Entry{}
		}
		return enc.Encode(FileFormat{Tool: ToolName, Version: 1, Updated: time.Now().UTC(), Count: len(es), Entries: es})
	case "csv":
		cw := csv.NewWriter(w)
		cw.Write([]string{"type", "value", "verdict", "origin", "hits", "first_seen", "last_seen", "tags", "sources", "note"})
		for _, e := range es {
			cw.Write([]string{string(e.Type), e.Value, e.Verdict.String(), string(e.Origin), fmt.Sprint(e.Hits),
				e.FirstSeen.Format(time.RFC3339), e.LastSeen.Format(time.RFC3339),
				strings.Join(e.Tags, ";"), strings.Join(e.Sources, ";"), e.Note})
		}
		cw.Flush()
		return cw.Error()
	}
	return fmt.Errorf("unknown export format %q (txt, json, csv)", format)
}

// ImportOptions tunes Import.
type ImportOptions struct {
	Tags        []string
	Note        string // default for extracted IOCs ("imported from <Name>")
	Name        string // file name, for the default note
	Verdict     sources.Status
	KeepPrivate bool
	Types       []ioc.Type
}

// ImportResult summarises an Import call.
type ImportResult struct {
	Found   int  `json:"found"`
	Added   int  `json:"added"`
	Updated int  `json:"updated"`
	Native  bool `json:"native"` // input was a ZUHAN (or legacy iocscan) export; metadata kept
}

// Import adds the IOCs in b to st. If b is a ZUHAN JSON export its
// entries are imported with their metadata; otherwise every IOC found in
// the text (plain list, log, sandbox dump, API response…) is added with
// origin "import".
func Import(st Store, b []byte, opt ImportOptions) (ImportResult, error) {
	var res ImportResult
	var entries []Entry
	var exported FileFormat
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) && json.Unmarshal(b, &exported) == nil && (exported.Tool == ToolName || exported.Tool == "iocscan") {
		res.Native = true
		f := Filter{Types: opt.Types}
		for _, e := range exported.Entries {
			if !f.Match(e) {
				continue
			}
			e.Tags = append(e.Tags, opt.Tags...)
			entries = append(entries, e)
		}
	} else {
		ex := extract.FromText(string(b), extract.Options{KeepPrivate: opt.KeepPrivate, Types: opt.Types})
		note := opt.Note
		if note == "" && opt.Name != "" {
			note = "imported from " + opt.Name
		}
		for _, i := range ex.IOCs {
			entries = append(entries, Entry{Value: i.Value, Verdict: opt.Verdict, Origin: OriginImport, Tags: opt.Tags, Note: note})
		}
	}
	res.Found = len(entries)
	a, u, err := st.Put(entries...)
	res.Added, res.Updated = a, u
	return res, err
}
