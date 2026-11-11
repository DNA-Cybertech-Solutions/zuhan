package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/extract"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

// extract: pull IOCs out of dumps without querying anything.
func (c *cli) extract(argv []string) int {
	fs := newFlags(c, "extract", "zuhan extract [flags] <file|-> ...")
	var (
		outFmt   = fs.String("o", "table", "output: table|txt|json|csv (txt = one IOC per line, for piping)")
		types    = fs.String("type", "", "only these types (comma separated): hash,md5,sha1,sha256,ip,ipv4,ipv6,domain,url")
		keepPriv = fs.Bool("keep-private", false, "keep private/local IPs")
		max      = fs.Int("max", 0, "at most this many IOCs (0 = unlimited)")
	)
	files, code, ok := parseArgs(fs, argv)
	if !ok {
		return code
	}
	if len(files) == 0 {
		if isTerminal(c.stdin) {
			fs.Usage()
			return exitErr
		}
		files = []string{"-"}
	}
	ts, err := ioc.ParseTypes(*types)
	if err != nil {
		return c.errf("%v", err)
	}
	opt := extract.Options{KeepPrivate: *keepPriv, Types: ts}

	var all []ioc.IOC
	seen := map[string]bool{}
	counts := map[ioc.Type]int{}
	truncated := 0
	for _, path := range files {
		f, err := openInput(c, path)
		if err != nil {
			return c.errf("%v", err)
		}
		ex, err := extract.FromReader(f, opt)
		f.Close()
		if err != nil {
			return c.errf("%s: %v", path, err)
		}
		for _, i := range ex.IOCs {
			if seen[i.Key()] {
				continue
			}
			seen[i.Key()] = true
			if *max > 0 && len(all) >= *max {
				truncated++
				continue
			}
			all = append(all, i)
			counts[i.Type]++
		}
	}

	switch *outFmt {
	case "txt":
		for _, i := range all {
			fmt.Fprintln(c.stdout, i.Value)
		}
	case "json":
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		type item struct {
			Type  ioc.Type `json:"type"`
			Value string   `json:"value"`
		}
		items := []item{}
		for _, i := range all {
			items = append(items, item{i.Type, i.Value})
		}
		enc.Encode(map[string]any{"count": len(all), "counts": counts, "iocs": items})
	case "csv":
		w := csv.NewWriter(c.stdout)
		w.Write([]string{"type", "value"})
		for _, i := range all {
			w.Write([]string{string(i.Type), i.Value})
		}
		w.Flush()
	case "table":
		tw := tabwriter.NewWriter(c.stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "TYPE\tVALUE")
		for _, i := range all {
			fmt.Fprintf(tw, "%s\t%s\n", i.Type, i.Value)
		}
		tw.Flush()
	default:
		return c.errf("unknown format %q (table, txt, json, csv)", *outFmt)
	}
	fmt.Fprintf(c.stderr, "%d IOCs %s\n", len(all), countsText(counts))
	if truncated > 0 {
		c.warnf("%d IOCs not shown because of -max", truncated)
	}
	return exitOK
}
