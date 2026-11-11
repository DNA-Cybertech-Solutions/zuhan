package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/DNA-Cybertech-Solutions/zuhan"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/config"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/store"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/web"
)

const defaultWebAddr = "127.0.0.1:8787"

// web: run the browser UI on this machine only.
func (c *cli) web(argv []string) int {
	fs := newFlags(c, "web", "zuhan web [flags]")
	addr := fs.String("addr", defaultWebAddr, "address to listen on (127.0.0.1 / localhost / ::1 only)")
	noOpen := fs.Bool("no-open", false, "don't open the browser automatically")
	dbPath := fs.String("db", "", "local IOC list file (default: "+config.DefaultDBPath()+")")
	cfgPath := fs.String("c", "", "config file (default: "+config.DefaultPath()+")")
	if _, code, ok := parseArgs(fs, argv); !ok {
		return code
	}

	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		return c.errf("invalid address %q: %v", *addr, err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return c.errf("the UI only runs on this computer: use -addr 127.0.0.1:<port> (got %s)", *addr)
	}
	if host == "localhost" {
		*addr = net.JoinHostPort("127.0.0.1", (*addr)[len(host)+1:])
	}

	keys, usedCfg, err := config.Load(*cfgPath)
	if err != nil {
		return c.errf("%v", err)
	}
	db := config.DBPath(*dbPath)
	st, err := store.Open(db)
	if err != nil {
		return c.errf("%v", err)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil && *addr == defaultWebAddr {
		ln, err = net.Listen("tcp", "127.0.0.1:0") // default port busy: pick a free one
	}
	if err != nil {
		return c.errf("cannot listen on %s: %v (try another port: -addr 127.0.0.1:9000)", *addr, err)
	}

	srv, err := web.New(zuhan.New(keys, st), ln.Addr())
	if err != nil {
		ln.Close()
		return c.errf("%v", err)
	}
	srv.DBPath, srv.Version = db, version
	srv.ConfigFile = config.Resolve(*cfgPath)
	srv.Rebuild = func(k sources.Keys) *zuhan.Scanner { return zuhan.New(k, st) }
	srv.ConfigPath = usedCfg
	if srv.ConfigPath == "" {
		srv.ConfigPath = srv.ConfigFile + " (not created yet — it is created when you save a key)"
	}

	url := "http://" + ln.Addr().String() + "/"
	fmt.Fprintf(c.stdout, "ZUHAN web UI is running at %s\n", url)
	fmt.Fprintln(c.stdout, "Reachable from this computer only. Press Ctrl+C in this window to stop it.")
	if !*noOpen {
		openBrowser(url)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Serve(ctx, ln); err != nil {
		return c.errf("%v", err)
	}
	fmt.Fprintln(c.stdout, "\nweb UI stopped")
	return exitOK
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err == nil {
		go cmd.Wait()
	}
}
