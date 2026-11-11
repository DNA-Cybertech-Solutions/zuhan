// Example: using ZUHAN as a Go library (framework) with your own intel
// source. Run with:
//
//	go run ./examples/custom-source 1.2.3.4 evil.com
//
// A "source" is any type with these six methods. Here we flag IOCs found in
// a plain-text company blocklist; the same pattern works for an internal
// API, a MISP instance, a SIEM lookup, etc.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/DNA-Cybertech-Solutions/zuhan"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/config"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/report"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/store"
)

// CompanyBlocklist reads one IOC per line from a text file.
type CompanyBlocklist struct {
	Path string
}

func (b *CompanyBlocklist) ID() string               { return "company" }
func (b *CompanyBlocklist) Name() string             { return "Company Blocklist" }
func (b *CompanyBlocklist) Supports(t ioc.Type) bool { return t.Valid() }
func (b *CompanyBlocklist) RequiresKey() bool        { return false }
func (b *CompanyBlocklist) Configured() bool         { return b.Path != "" }

func (b *CompanyBlocklist) Query(ctx context.Context, i ioc.IOC) sources.Result {
	r := sources.Result{Source: b.Name()}
	f, err := os.Open(b.Path)
	if err != nil {
		r.Status, r.Error = sources.StatusError, err.Error()
		return r
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if ioc.Parse(strings.TrimSpace(sc.Text())).Value == i.Value {
			r.Status, r.Score, r.Summary = sources.StatusMalicious, "listed", "on the company blocklist"
			return r
		}
	}
	r.Status, r.Summary = sources.StatusNotFound, "not on the company blocklist"
	return r
}

func main() {
	keys, _, err := config.Load("") // same API keys as the CLI
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	st, err := store.Open(config.DBPath("")) // same local IOC list as the CLI
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	sc := zuhan.New(keys, st)
	sc.Use(&CompanyBlocklist{Path: "blocklist.txt"})
	sc.Save.IncludeSuspicious = true

	reps, skipped, err := sc.ScanValues(context.Background(), os.Args[1:]...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "local list:", err)
	}
	for _, s := range skipped {
		fmt.Fprintln(os.Stderr, "not an IOC:", s)
	}
	report.Write(os.Stdout, "table", reps, report.Options{Verbose: true})
}
