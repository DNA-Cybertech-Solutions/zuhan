// Command zuhan looks up IOCs (hashes, IPs, domains, URLs) in many
// threat-intelligence sources at once, keeps malicious ones in a local IOC
// list, and extracts IOCs from raw dumps.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/config"
)

// version is overridden at build time with
// -ldflags "-X main.version=v3.0.0" (see Makefile).
var version = "3.0.0"

// Exit codes: 0 = nothing malicious, 1 = usage/runtime error,
// 2 = at least one IOC malicious, 3 = at least one suspicious (none malicious).
const (
	exitOK         = 0
	exitErr        = 1
	exitMalicious  = 2
	exitSuspicious = 3
)

type cli struct {
	stdin          io.Reader
	stdout, stderr io.Writer
}

func main() {
	version = strings.TrimPrefix(version, "v")
	c := &cli{os.Stdin, os.Stdout, os.Stderr}
	os.Exit(c.run(os.Args[1:]))
}

func (c *cli) run(argv []string) int {
	// One-time move of settings from the project's former name (iocscan).
	if copied, err := config.MigrateLegacy(); err != nil {
		c.warnf("could not copy settings from the old iocscan folder: %v", err)
	} else {
		for _, f := range copied {
			fmt.Fprintf(c.stderr, "note: copied your previous iocscan settings to %s\n", f)
		}
	}

	if len(argv) > 0 {
		cmd, rest := argv[0], argv[1:]
		switch cmd {
		case "scan":
			return c.scan(rest)
		case "extract":
			return c.extract(rest)
		case "db":
			return c.db(rest)
		case "web", "ui", "gui":
			return c.web(rest)
		case "sources":
			return c.scan(append([]string{"-list"}, rest...))
		case "init":
			return c.scan(append([]string{"-init"}, rest...))
		case "version":
			fmt.Fprintln(c.stdout, "zuhan", version)
			return exitOK
		case "help", "-h", "-help", "--help":
			c.usage()
			return exitOK
		}
	}
	return c.scan(argv) // `zuhan <ioc>` = `zuhan scan <ioc>`
}

func (c *cli) usage() {
	fmt.Fprintf(c.stderr, `ZUHAN %s — IOC lookup tool

Commands:
  zuhan [scan] [flags] <ioc> ...     look up IOCs in every source (default)
  zuhan scan -dump dump.json         extract IOCs from a dump and look them up
  zuhan extract <file>               list the IOCs in a dump (no lookups)
  zuhan db add <ioc> ...             add to the local IOC list (no args: interactive)
  zuhan db rm <ioc> ...              remove from the list
  zuhan db list                      show the list
  zuhan db import <file>             bulk-add from a file or dump
  zuhan db export [file]             export the list (txt/json/csv)
  zuhan db stats                     list statistics
  zuhan web                          open the browser UI (this computer only)
  zuhan sources                      sources and API key status
  zuhan init                         create an empty config file
  zuhan version

Help for a command: zuhan <command> -h
Supported IOCs: MD5, SHA1, SHA256, IPv4, IPv6, domain, URL (defanged input works too)
Exit codes: 0 clean/not found, 1 error, 2 malicious, 3 suspicious
`, version)
}

func (c *cli) errf(format string, a ...any) int {
	fmt.Fprintf(c.stderr, "error: "+format+"\n", a...)
	return exitErr
}

func (c *cli) warnf(format string, a ...any) {
	fmt.Fprintf(c.stderr, "warning: "+format+"\n", a...)
}

// parseArgs parses flags that may appear before or after positional args.
// ok=false means the caller should return code.
func parseArgs(fs *flag.FlagSet, args []string) (positional []string, code int, ok bool) {
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, exitOK, false
			}
			return nil, exitErr, false
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, 0, true
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

func newFlags(c *cli, name, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() {
		fmt.Fprintf(c.stderr, "Usage: %s\n\nFlags:\n", synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// readTokens reads IOCs separated by newlines, spaces, commas or
// semicolons; '#' starts a comment (except inside URLs).
func readTokens(r io.Reader) []string {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		out = append(out, splitLine(sc.Text())...)
	}
	return out
}

func splitLine(line string) []string {
	if i := strings.Index(line, "#"); i >= 0 && !strings.Contains(line[:i], "://") {
		line = line[:i]
	}
	return strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ',' || r == ';'
	})
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isTerminal(v any) bool {
	f, ok := v.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func openInput(c *cli, path string) (io.ReadCloser, error) {
	if path == "-" {
		return io.NopCloser(c.stdin), nil
	}
	return os.Open(path)
}
