// Command genwarninglists builds the warninglist snapshot embedded in
// pkg/warninglist from a local clone of MISP/misp-warninglists:
//
//	git clone --depth 1 https://github.com/MISP/misp-warninglists.git
//	go run ./tools/genwarninglists misp-warninglists/lists > pkg/warninglist/default.jsonl.gz
//
// Lists larger than -max bytes are left out of the snapshot (they can still
// be fetched with `zuhan warninglists update -max-size`).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/warninglist"
)

func main() {
	max := flag.Int64("max", 1_500_000, "skip list.json files larger than this many bytes")
	skip := flag.String("skip", "vpn-ipv4,vpn-ipv6,datacenter-ipv4,datacenter-ipv6", "list IDs to leave out (comma separated)")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: genwarninglists [-max bytes] <misp-warninglists/lists> > default.jsonl.gz")
		os.Exit(2)
	}
	skipped := map[string]bool{}
	for _, s := range strings.Split(*skip, ",") {
		skipped[strings.TrimSpace(s)] = true
	}
	dirs, err := os.ReadDir(flag.Arg(0))
	if err != nil {
		panic(err)
	}
	var lists []warninglist.List
	entries := 0
	for _, d := range dirs {
		if !d.IsDir() || skipped[d.Name()] {
			continue
		}
		p := filepath.Join(flag.Arg(0), d.Name(), "list.json")
		st, err := os.Stat(p)
		if err != nil || st.Size() > *max {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			panic(err)
		}
		l, ok, err := warninglist.FromMISP(d.Name(), b)
		if err != nil {
			panic(err)
		}
		if ok {
			lists = append(lists, l)
			entries += len(l.Entries)
		}
	}
	sort.Slice(lists, func(a, b int) bool { return lists[a].ID < lists[b].ID })
	if err := warninglist.Write(os.Stdout, lists); err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "%d lists, %d entries\n", len(lists), entries)
}
