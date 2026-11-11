package main

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/config"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/engine"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/extract"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/report"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/store"
)

var aliases = map[string]string{
	"local": "localdb", "localdb": "localdb", "db": "localdb",
	"vt": "virustotal", "virustotal": "virustotal",
	"mb": "malwarebazaar", "bazaar": "malwarebazaar", "malwarebazaar": "malwarebazaar",
	"tf": "threatfox", "threatfox": "threatfox",
	"uh": "urlhaus", "urlhaus": "urlhaus",
	"otx": "otx", "alienvault": "otx",
	"ha": "hybrid", "hybrid": "hybrid", "hybridanalysis": "hybrid",
	"abuseipdb": "abuseipdb", "aipdb": "abuseipdb",
	"gn": "greynoise", "greynoise": "greynoise",
	"shodan": "shodan", "internetdb": "shodan",
}

func (c *cli) scan(argv []string) int {
	fs := newFlags(c, "scan", "zuhan [scan] [flags] <ioc|file> ...")
	var (
		inFile   = fs.String("f", "", "IOC list file (one IOC per line, # comments)")
		dump     = fs.String("dump", "", "API-call dump / log / JSON response: extract the IOCs in it and look them up ('-' = stdin)")
		maxDump  = fs.Int("max", 100, "look up at most this many IOCs from a dump (0 = unlimited)")
		keepPriv = fs.Bool("keep-private", false, "keep private/local IPs from dumps (192.168.x, 10.x, 127.x …)")
		outFmt   = fs.String("o", "table", "stdout format: table|json|md|csv|html")
		repPath  = fs.String("r", "", "write a report file (format from extension: .html .json .md .csv .txt)")
		srcList  = fs.String("s", "", "only these sources (comma separated): local,vt,mb,tf,uh,otx,ha,abuseipdb,gn,shodan")
		exclude  = fs.String("x", "", "exclude these sources (comma separated)")
		offline  = fs.Bool("offline", false, "check the local IOC list only (no internet)")
		noSave   = fs.Bool("no-save", false, "do NOT add malicious IOCs to the local list")
		saveSus  = fs.Bool("save-suspicious", false, "also add suspicious IOCs to the local list")
		dbPath   = fs.String("db", "", "local IOC list file (default: "+config.DefaultDBPath()+")")
		timeout  = fs.Duration("t", 25*time.Second, "timeout per source")
		cfgPath  = fs.String("c", "", "config file (default: "+config.DefaultPath()+")")
		verbose  = fs.Bool("v", false, "show every field and link")
		hashMode = fs.Bool("hash", false, "hash file arguments (MD5/SHA1/SHA256) and look up the hashes")
		listSrc  = fs.Bool("list", false, "list sources and API key status")
		initCfg  = fs.Bool("init", false, "create an empty config file")
		noColor  = fs.Bool("no-color", false, "disable colours")
		parallel = fs.Int("p", 4, "IOCs processed in parallel")
		quiet    = fs.Bool("q", false, "print nothing (for reports / exit codes)")
		showVer  = fs.Bool("version", false, "print the version")
	)
	positional, code, ok := parseArgs(fs, argv)
	if !ok {
		return code
	}

	if *showVer {
		fmt.Fprintln(c.stdout, "zuhan", version)
		return exitOK
	}
	if *initCfg {
		p := *cfgPath
		if p == "" {
			p = config.DefaultPath()
		}
		if err := config.WriteTemplate(p); err != nil {
			return c.errf("%v", err)
		}
		fmt.Fprintln(c.stdout, "config created:", p)
		fmt.Fprintln(c.stdout, "Put your API keys in this file, in environment variables, or in the web UI (zuhan web).")
		return exitOK
	}

	keys, usedCfg, err := config.Load(*cfgPath)
	if err != nil {
		return c.errf("%v", err)
	}
	st, err := store.Open(config.DBPath(*dbPath))
	if err != nil {
		return c.errf("%v", err)
	}
	sc := zuhan.New(keys, st)
	if *offline {
		*srcList = "localdb"
	}
	if sc.Sources, err = selectSources(sc.Sources, *srcList, *exclude); err != nil {
		return c.errf("%v", err)
	}
	if *listSrc {
		listSources(c.stdout, sc.Sources, usedCfg, st)
		return exitOK
	}

	if !validFormat(*outFmt) {
		return c.errf("unknown format %q (%s)", *outFmt, strings.Join(report.Formats, ", "))
	}
	repFmt := ""
	if *repPath != "" {
		if repFmt, err = report.FormatFromPath(*repPath); err != nil {
			return c.errf("%v", err)
		}
	}

	// ---- collect IOCs ----
	var iocs []ioc.IOC
	seen := map[string]bool{}
	push := func(i ioc.IOC) {
		if !seen[i.Key()] {
			seen[i.Key()] = true
			iocs = append(iocs, i)
		}
	}
	var raw []string
	stdinUsed := false
	for _, p := range positional {
		if *hashMode && p != "-" {
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				i, err := hashFile(p)
				if err != nil {
					return c.errf("%v", err)
				}
				push(i)
				continue
			}
		}
		if p == "-" {
			raw = append(raw, readTokens(c.stdin)...)
			stdinUsed = true
		} else {
			raw = append(raw, p)
		}
	}
	if *inFile != "" {
		f, err := os.Open(*inFile)
		if err != nil {
			return c.errf("%v", err)
		}
		raw = append(raw, readTokens(f)...)
		f.Close()
	}
	if *dump != "" {
		f, err := openInput(c, *dump)
		if err != nil {
			return c.errf("%v", err)
		}
		ex, err := extract.FromReader(f, extract.Options{KeepPrivate: *keepPriv, Max: *maxDump})
		f.Close()
		if err != nil {
			return c.errf("could not read the dump: %v", err)
		}
		stdinUsed = stdinUsed || *dump == "-"
		fmt.Fprintf(c.stderr, "%s: %d IOCs extracted %s\n", *dump, len(ex.IOCs), countsText(ex.Counts))
		if ex.Truncated > 0 {
			c.warnf("%d IOCs were not looked up because of -max %d (use -max 0 for all, or zuhan extract to just list them)", ex.Truncated, *maxDump)
		}
		for _, i := range ex.IOCs {
			push(i)
		}
	}
	if len(raw) == 0 && len(iocs) == 0 && !stdinUsed && !isTerminal(c.stdin) {
		raw = readTokens(c.stdin)
	}
	for _, r := range raw {
		i := ioc.Parse(r)
		switch {
		case i.Type == ioc.SHA512:
			c.warnf("SHA512 is not supported, use MD5/SHA1/SHA256: %s", r)
		case !i.Type.Valid():
			c.warnf("skipped, not an IOC: %q", r)
		default:
			push(i)
		}
	}
	if len(iocs) == 0 {
		if *dump != "" {
			fmt.Fprintln(c.stderr, "no IOCs to look up in the dump")
			return exitOK
		}
		fs.Usage()
		return exitErr
	}

	// ---- scan ----
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	showProgress := !*quiet && len(iocs) > 1 && isTerminal(c.stderr)
	sc.Engine = engine.Options{Timeout: *timeout, Parallel: *parallel}
	if showProgress {
		sc.Engine.Progress = func(done, total int) { fmt.Fprintf(c.stderr, "\r  scanning… %d/%d", done, total) }
	}
	sc.Save = zuhan.SavePolicy{Enabled: !*noSave && !*offline, IncludeSuspicious: *saveSus}
	reps, serr := sc.Scan(ctx, iocs)
	if showProgress {
		fmt.Fprint(c.stderr, "\r\033[K")
	}
	if serr != nil {
		c.warnf("could not update the local IOC list: %v", serr)
	}

	// ---- output ----
	ropt := report.Options{
		Verbose:   *verbose,
		Version:   version,
		Generated: time.Now(),
		Color:     *outFmt == "table" && !*noColor && os.Getenv("NO_COLOR") == "" && isTerminal(c.stdout),
	}
	if !*quiet {
		if err := report.Write(c.stdout, *outFmt, reps, ropt); err != nil {
			return c.errf("%v", err)
		}
		added := 0
		for _, r := range reps {
			if r.LocalDB == "added" {
				added++
			}
		}
		if added > 0 {
			fmt.Fprintf(c.stderr, "%d new malicious IOC(s) added to the local list (%s)\n", added, st.Path())
		}
	}
	if *repPath != "" {
		f, err := os.Create(*repPath)
		if err != nil {
			return c.errf("%v", err)
		}
		fo := ropt
		fo.Color, fo.Verbose = false, true
		werr := report.Write(f, repFmt, reps, fo)
		cerr := f.Close()
		if werr != nil || cerr != nil {
			return c.errf("could not write the report: %v", errors.Join(werr, cerr))
		}
		if !*quiet {
			fmt.Fprintln(c.stderr, "rapor kaydedildi:", *repPath)
		}
	}

	if ctx.Err() != nil {
		return exitErr
	}
	s := report.Summarize(reps)
	switch {
	case s.Malicious > 0:
		return exitMalicious
	case s.Suspicious > 0:
		return exitSuspicious
	case s.Other > 0:
		return exitErr
	}
	return exitOK
}

func countsText(m map[ioc.Type]int) string {
	var parts []string
	for _, t := range ioc.Types {
		if m[t] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", t, m[t]))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func validFormat(f string) bool {
	for _, x := range report.Formats {
		if f == x {
			return true
		}
	}
	return f == "markdown"
}

func parseIDs(list string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, n := range splitList(list) {
		id, ok := aliases[strings.ReplaceAll(strings.ToLower(n), "-", "")]
		if !ok {
			return nil, fmt.Errorf("unknown source %q (see: zuhan sources)", n)
		}
		out[id] = true
	}
	return out, nil
}

func selectSources(all []sources.Source, only, exclude string) ([]sources.Source, error) {
	inc, err := parseIDs(only)
	if err != nil {
		return nil, err
	}
	exc, err := parseIDs(exclude)
	if err != nil {
		return nil, err
	}
	var out []sources.Source
	for _, s := range all {
		if (len(inc) == 0 || inc[s.ID()]) && !exc[s.ID()] {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no sources left to query")
	}
	return out, nil
}

func listSources(w io.Writer, srcs []sources.Source, cfg string, st *store.FileStore) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSOURCE\tIOC TYPES\tAPI KEY\tENV VARIABLE")
	for _, s := range srcs {
		var ts []string
		for _, t := range ioc.Types {
			if s.Supports(t) {
				ts = append(ts, string(t))
			}
		}
		status := "not needed"
		switch {
		case s.ID() == "localdb":
			status = "local"
		case s.RequiresKey() && s.Configured():
			status = "✓ configured"
		case s.RequiresKey():
			status = "✗ missing"
		case s.ID() == "otx" || s.ID() == "greynoise":
			status = "optional"
		}
		env := config.EnvVars[s.ID()]
		if s.ID() == "localdb" {
			env = "ZUHAN_DB"
		}
		if env == "" {
			env = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.ID(), s.Name(), strings.Join(ts, ","), status, env)
	}
	tw.Flush()
	if cfg == "" {
		cfg = "(none yet — " + config.DefaultPath() + ")"
	}
	fmt.Fprintln(w, "\nconfig:  ", cfg)
	n := 0
	if es, err := st.List(store.Filter{}); err == nil {
		n = len(es)
	}
	fmt.Fprintf(w, "IOC list: %s (%d entries)\n", st.Path(), n)
}

func hashFile(path string) (ioc.IOC, error) {
	f, err := os.Open(path)
	if err != nil {
		return ioc.IOC{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ioc.IOC{}, err
	}
	m, s1, s2 := md5.New(), sha1.New(), sha256.New()
	if _, err := io.Copy(io.MultiWriter(m, s1, s2), f); err != nil {
		return ioc.IOC{}, err
	}
	sha := hex.EncodeToString(s2.Sum(nil))
	return ioc.IOC{
		Raw: path, Value: sha, Type: ioc.SHA256,
		Meta: map[string]string{
			"file":   path,
			"md5":    hex.EncodeToString(m.Sum(nil)),
			"sha1":   hex.EncodeToString(s1.Sum(nil)),
			"sha256": sha,
			"size":   fmt.Sprintf("%d bytes", fi.Size()),
		},
	}, nil
}
