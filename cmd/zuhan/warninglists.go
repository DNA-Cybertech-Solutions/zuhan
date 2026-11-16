package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/config"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/warninglist"
)

func (c *cli) warninglists(argv []string) int {
	usage := func() {
		fmt.Fprint(c.stderr, `Usage: zuhan warninglists <command>

MISP warninglists mark known-benign infrastructure (public DNS resolvers,
private ranges, popular domains, known false-positive hashes…) and add
context (cloud/hosting ranges, Tor exit nodes, scanners, URL shorteners…).
A snapshot ships with ZUHAN; "update" downloads the current lists.

Commands:
  list               show the loaded lists
  check <ioc> ...    show which lists an IOC is on
  update             download the current lists from GitHub   -max-size MB, -all, -only a,b
  path               where downloaded lists are stored
`)
	}
	if len(argv) == 0 {
		usage()
		return exitErr
	}
	path := config.WarninglistPath()
	switch argv[0] {
	case "path":
		fmt.Fprintln(c.stdout, path)
		return exitOK
	case "list", "ls":
		set, err := warninglist.Load(path)
		if err != nil {
			return c.errf("%v", err)
		}
		tw := tabwriter.NewWriter(c.stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tKIND\tTYPE\tENTRIES\tNAME")
		for _, l := range set.Lists() {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", l.ID, l.Kind, l.Type, l.Version, l.Label())
		}
		tw.Flush()
		upd := ""
		if !set.Updated.IsZero() {
			upd = ", newest list " + set.Updated.Format("2006-01-02")
		}
		fmt.Fprintf(c.stderr, "\n%d lists from %s%s\n", set.Len(), set.Source, upd)
		return exitOK
	case "check":
		set, err := warninglist.Load(path)
		if err != nil {
			return c.errf("%v", err)
		}
		vals := argv[1:]
		if len(vals) == 0 {
			vals = readTokens(c.stdin)
		}
		for _, v := range vals {
			i := ioc.Parse(v)
			if !i.Type.Valid() {
				c.warnf("not an IOC: %s", v)
				continue
			}
			ms := set.Match(i)
			if len(ms) == 0 {
				fmt.Fprintf(c.stdout, "%s: on no warninglist\n", i.Value)
				continue
			}
			fmt.Fprintf(c.stdout, "%s:\n", i.Value)
			for _, m := range ms {
				fmt.Fprintf(c.stdout, "  %-8s %-40s %s (%s)\n", m.Kind, m.ListID, m.Label, m.How)
			}
		}
		return exitOK
	case "update":
		fs := newFlags(c, "warninglists update", "zuhan warninglists update [flags]")
		maxMB := fs.Float64("max-size", 5, "skip lists larger than this many MB (the top-1M lists are 20–60 MB)")
		all := fs.Bool("all", false, "download every list, whatever its size")
		only := fs.String("only", "", "download only these list IDs (comma separated)")
		if _, code, ok := parseArgs(fs, argv[1:]); !ok {
			return code
		}
		opt := warninglist.UpdateOptions{MaxBytes: int64(*maxMB * (1 << 20)), Only: splitList(*only)}
		if *all {
			opt.MaxBytes = -1
		}
		if isTerminal(c.stderr) {
			opt.Progress = func(done, total int) { fmt.Fprintf(c.stderr, "\r  downloading… %d/%d", done, total) }
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		res, err := warninglist.Update(ctx, path, opt)
		if opt.Progress != nil {
			fmt.Fprint(c.stderr, "\r\033[K")
		}
		if err != nil {
			return c.errf("%v", err)
		}
		fmt.Fprintf(c.stdout, "%d lists, %d entries saved to %s\n", res.Lists, res.Entries, res.Path)
		if len(res.Skipped) > 0 {
			fmt.Fprintf(c.stderr, "skipped: %s\n", strings.Join(res.Skipped, ", "))
		}
		return exitOK
	}
	usage()
	return c.errf("unknown warninglists command %q", argv[0])
}
