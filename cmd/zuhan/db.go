package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/config"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/extract"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/store"
)

func (c *cli) dbUsage() {
	fmt.Fprint(c.stderr, `Usage: zuhan db <command> [flags]

The local IOC list is a persistent list of malicious IPs / domains / hashes / URLs.
It is the first source checked on every scan; IOCs that external sources call
malicious are added to it automatically after a scan (disable with scan -no-save).

Commands:
  add <ioc> ...        add (no arguments: interactive mode)   -tag -note -verdict
  rm <ioc> ...         remove
  list                 list                                    -type -origin -search -o
  import <file> ...    bulk-add from a file (IOC list, dump, or a db export JSON)
  export [file]        export (extension or -o: txt, json, csv)
  stats                statistics
  path                 path of the list file

All commands accept -db <file> to use another list (or the ZUHAN_DB environment variable).
`)
}

func (c *cli) db(argv []string) int {
	if len(argv) == 0 || argv[0] == "-h" || argv[0] == "help" || argv[0] == "--help" {
		c.dbUsage()
		if len(argv) == 0 {
			return exitErr
		}
		return exitOK
	}
	switch argv[0] {
	case "add":
		return c.dbAdd(argv[1:])
	case "rm", "remove", "del", "delete":
		return c.dbRemove(argv[1:])
	case "list", "ls":
		return c.dbList(argv[1:])
	case "import":
		return c.dbImport(argv[1:])
	case "export":
		return c.dbExport(argv[1:])
	case "stats":
		return c.dbStats(argv[1:])
	case "path":
		return c.dbPath(argv[1:])
	}
	c.dbUsage()
	return c.errf("unknown db command %q", argv[0])
}

func dbFlag(fs interface {
	String(string, string, string) *string
}) *string {
	return fs.String("db", "", "local IOC list file (default: "+config.DefaultDBPath()+")")
}

func (c *cli) openDB(path string) (*store.FileStore, int) {
	st, err := store.Open(config.DBPath(path))
	if err != nil {
		return nil, c.errf("%v", err)
	}
	return st, 0
}

func parseVerdict(s string) (sources.Status, error) {
	switch strings.ToLower(s) {
	case "", "malicious", "m":
		return sources.StatusMalicious, nil
	case "suspicious", "s":
		return sources.StatusSuspicious, nil
	}
	return 0, fmt.Errorf("invalid verdict %q (malicious, suspicious)", s)
}

// ---------------- add ----------------

func (c *cli) dbAdd(argv []string) int {
	fs := newFlags(c, "db add", "zuhan db add [flags] <ioc> ...   (no arguments: interactive)")
	dbp := dbFlag(fs)
	tags := fs.String("tag", "", "tags (comma separated), e.g. c2,emotet,case-42")
	note := fs.String("note", "", "note")
	verd := fs.String("verdict", "malicious", "malicious | suspicious")
	args, code, ok := parseArgs(fs, argv)
	if !ok {
		return code
	}
	v, err := parseVerdict(*verd)
	if err != nil {
		return c.errf("%v", err)
	}
	st, code := c.openDB(*dbp)
	if st == nil {
		return code
	}
	base := store.Entry{Verdict: v, Origin: store.OriginManual, Tags: splitList(*tags), Note: *note}

	addOne := func(tokens []string) (added, updated, bad int) {
		for _, tok := range tokens {
			i := ioc.Parse(tok)
			if !i.Type.Valid() {
				fmt.Fprintf(c.stderr, "  ! not an IOC: %s\n", tok)
				bad++
				continue
			}
			_, exists, _ := st.Get(i.Type, i.Value)
			e := base
			e.Value = i.Value
			if _, _, err := st.Put(e); err != nil {
				fmt.Fprintf(c.stderr, "  ! %s: %v\n", i.Value, err)
				bad++
				continue
			}
			if exists {
				fmt.Fprintf(c.stdout, "  ~ updated  %-8s %s\n", i.Type, i.Value)
				updated++
			} else {
				fmt.Fprintf(c.stdout, "  + added    %-8s %s\n", i.Type, i.Value)
				added++
			}
		}
		return
	}

	var a, u, b int
	switch {
	case len(args) > 0:
		a, u, b = addOne(args)
	case isTerminal(c.stdin):
		fmt.Fprintln(c.stdout, "Enter IOCs (hash, IP, domain, URL). You can put several on one line.")
		fmt.Fprintln(c.stdout, "Finish with an empty line, Ctrl+D or 'q'.")
		in := bufio.NewScanner(c.stdin)
		for {
			fmt.Fprint(c.stdout, "ioc> ")
			if !in.Scan() {
				fmt.Fprintln(c.stdout)
				break
			}
			line := strings.TrimSpace(in.Text())
			if line == "" || line == "q" || line == "quit" || line == "exit" {
				break
			}
			x, y, z := addOne(splitLine(line))
			a, u, b = a+x, u+y, b+z
		}
	default:
		a, u, b = addOne(readTokens(c.stdin))
	}
	fmt.Fprintf(c.stderr, "%d added, %d updated, %d invalid → %s\n", a, u, b, st.Path())
	if a+u == 0 {
		return exitErr
	}
	return exitOK
}

// ---------------- rm ----------------

func (c *cli) dbRemove(argv []string) int {
	fs := newFlags(c, "db rm", "zuhan db rm [flags] <ioc> ...")
	dbp := dbFlag(fs)
	args, code, ok := parseArgs(fs, argv)
	if !ok {
		return code
	}
	if len(args) == 0 {
		if isTerminal(c.stdin) {
			fs.Usage()
			return exitErr
		}
		args = readTokens(c.stdin)
	}
	st, code := c.openDB(*dbp)
	if st == nil {
		return code
	}
	var iocs []ioc.IOC
	for _, a := range args {
		if i := ioc.Parse(a); i.Type.Valid() {
			iocs = append(iocs, i)
		} else {
			c.warnf("not an IOC: %s", a)
		}
	}
	n, err := st.Delete(iocs...)
	if err != nil {
		return c.errf("%v", err)
	}
	fmt.Fprintf(c.stdout, "%d removed (%d requested)\n", n, len(iocs))
	return exitOK
}

// ---------------- list ----------------

func (c *cli) dbFilter(fs interface {
	String(string, string, string) *string
}) func() (store.Filter, error) {
	types := fs.String("type", "", "only these types (comma separated): hash,md5,sha1,sha256,ip,ipv4,ipv6,domain,url")
	origin := fs.String("origin", "", "by origin: manual | auto | import")
	search := fs.String("search", "", "search value, tags, note or sources")
	return func() (store.Filter, error) {
		ts, err := ioc.ParseTypes(*types)
		if err != nil {
			return store.Filter{}, err
		}
		o := store.Origin(strings.ToLower(*origin))
		switch o {
		case "", store.OriginManual, store.OriginAuto, store.OriginImport:
		default:
			return store.Filter{}, fmt.Errorf("invalid origin %q (manual, auto, import)", *origin)
		}
		return store.Filter{Types: ts, Origin: o, Search: *search}, nil
	}
}

func (c *cli) dbList(argv []string) int {
	fs := newFlags(c, "db list", "zuhan db list [flags]")
	dbp := dbFlag(fs)
	filter := c.dbFilter(fs)
	outFmt := fs.String("o", "table", "output: table|txt|json|csv")
	if _, code, ok := parseArgs(fs, argv); !ok {
		return code
	}
	f, err := filter()
	if err != nil {
		return c.errf("%v", err)
	}
	st, code := c.openDB(*dbp)
	if st == nil {
		return code
	}
	es, err := st.List(f)
	if err != nil {
		return c.errf("%v", err)
	}
	if *outFmt == "table" && len(es) == 0 {
		fmt.Fprintln(c.stderr, "the list is empty (or nothing matches the filter) —", st.Path())
		return exitOK
	}
	if err := writeEntries(c.stdout, *outFmt, es); err != nil {
		return c.errf("%v", err)
	}
	if *outFmt == "table" {
		fmt.Fprintf(c.stderr, "\n%d entries — %s\n", len(es), st.Path())
	}
	return exitOK
}

func writeEntries(w io.Writer, format string, es []store.Entry) error {
	if format != "table" {
		return store.WriteEntries(w, format, es)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TYPE\tVALUE\tVERDICT\tORIGIN\tHITS\tFIRST SEEN\tLAST SEEN\tTAGS / NOTE")
	for _, e := range es {
		extra := strings.Join(e.Tags, ",")
		if len(e.Sources) > 0 {
			extra = strings.Trim(extra+" ["+strings.Join(e.Sources, ",")+"]", " ")
		}
		if e.Note != "" {
			extra = strings.Trim(extra+" "+e.Note, " ")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", e.Type, e.Value, e.Verdict, e.Origin, e.Hits,
			e.FirstSeen.Local().Format("2006-01-02 15:04"), e.LastSeen.Local().Format("2006-01-02 15:04"), extra)
	}
	return tw.Flush()
}

// ---------------- import ----------------

func (c *cli) dbImport(argv []string) int {
	fs := newFlags(c, "db import", "zuhan db import [flags] <file|-> ...")
	dbp := dbFlag(fs)
	tags := fs.String("tag", "", "tags for every imported IOC (comma separated)")
	note := fs.String("note", "", "note for every imported IOC (default: file name)")
	verd := fs.String("verdict", "malicious", "malicious | suspicious")
	keepPriv := fs.Bool("keep-private", false, "keep private/local IPs")
	types := fs.String("type", "", "only these types (comma separated)")
	files, code, ok := parseArgs(fs, argv)
	if !ok {
		return code
	}
	if len(files) == 0 {
		fs.Usage()
		return exitErr
	}
	v, err := parseVerdict(*verd)
	if err != nil {
		return c.errf("%v", err)
	}
	ts, err := ioc.ParseTypes(*types)
	if err != nil {
		return c.errf("%v", err)
	}
	st, code := c.openDB(*dbp)
	if st == nil {
		return code
	}
	total := 0
	for _, path := range files {
		f, err := openInput(c, path)
		if err != nil {
			return c.errf("%v", err)
		}
		b, err := io.ReadAll(io.LimitReader(f, extract.MaxInput))
		f.Close()
		if err != nil {
			return c.errf("%s: %v", path, err)
		}

		name := ""
		if path != "-" {
			name = filepath.Base(path)
		}
		res, err := store.Import(st, b, store.ImportOptions{
			Tags: splitList(*tags), Note: *note, Name: name, Verdict: v, KeepPrivate: *keepPriv, Types: ts,
		})
		if err != nil {
			return c.errf("%s: %v", path, err)
		}
		fmt.Fprintf(c.stdout, "%s: %d IOCs found → %d added, %d updated\n", path, res.Found, res.Added, res.Updated)
		total += res.Added + res.Updated
	}
	fmt.Fprintln(c.stderr, "list:", st.Path())
	if total == 0 {
		return exitErr
	}
	return exitOK
}

// ---------------- export ----------------

func (c *cli) dbExport(argv []string) int {
	fs := newFlags(c, "db export", "zuhan db export [flags] [file]   (no file: print to stdout)")
	dbp := dbFlag(fs)
	filter := c.dbFilter(fs)
	outFmt := fs.String("o", "", "format: txt|json|csv (default: from the file extension, else txt)")
	args, code, ok := parseArgs(fs, argv)
	if !ok {
		return code
	}
	f, err := filter()
	if err != nil {
		return c.errf("%v", err)
	}
	path := ""
	if len(args) > 0 && args[0] != "-" {
		path = args[0]
	}
	format := *outFmt
	if format == "" {
		switch strings.ToLower(filepath.Ext(path)) {
		case ".json":
			format = "json"
		case ".csv":
			format = "csv"
		default:
			format = "txt"
		}
	}
	if format == "table" {
		return c.errf("use txt, json or csv for export")
	}
	st, code := c.openDB(*dbp)
	if st == nil {
		return code
	}
	es, err := st.List(f)
	if err != nil {
		return c.errf("%v", err)
	}
	var w io.Writer = c.stdout
	var file *os.File
	if path != "" {
		if file, err = os.Create(path); err != nil {
			return c.errf("%v", err)
		}
		w = file
	}
	werr := writeEntries(w, format, es)
	if file != nil {
		if cerr := file.Close(); werr == nil {
			werr = cerr
		}
	}
	if werr != nil {
		return c.errf("%v", werr)
	}
	if path != "" {
		fmt.Fprintf(c.stderr, "%d entries → %s (%s)\n", len(es), path, format)
	}
	return exitOK
}

// ---------------- stats / path ----------------

func (c *cli) dbStats(argv []string) int {
	fs := newFlags(c, "db stats", "zuhan db stats [flags]")
	dbp := dbFlag(fs)
	if _, code, ok := parseArgs(fs, argv); !ok {
		return code
	}
	st, code := c.openDB(*dbp)
	if st == nil {
		return code
	}
	es, err := st.List(store.Filter{})
	if err != nil {
		return c.errf("%v", err)
	}
	byType, byOrigin, byVerdict := map[string]int{}, map[string]int{}, map[string]int{}
	var last time.Time
	for _, e := range es {
		byType[string(e.Type)]++
		byOrigin[string(e.Origin)]++
		byVerdict[e.Verdict.String()]++
		if e.LastSeen.After(last) {
			last = e.LastSeen
		}
	}
	fmt.Fprintf(c.stdout, "File          : %s\nTotal         : %d\n", st.Path(), len(es))
	if len(es) > 0 {
		fmt.Fprintf(c.stdout, "Last activity : %s\n", last.Local().Format("2006-01-02 15:04"))
	}
	show := func(title string, m map[string]int) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
		}
		fmt.Fprintf(c.stdout, "%-14s: %s\n", title, strings.Join(parts, ", "))
	}
	if len(es) > 0 {
		show("Type", byType)
		show("Origin", byOrigin)
		show("Verdict", byVerdict)
	}
	return exitOK
}

func (c *cli) dbPath(argv []string) int {
	fs := newFlags(c, "db path", "zuhan db path")
	dbp := dbFlag(fs)
	if _, code, ok := parseArgs(fs, argv); !ok {
		return code
	}
	fmt.Fprintln(c.stdout, config.DBPath(*dbp))
	return exitOK
}
