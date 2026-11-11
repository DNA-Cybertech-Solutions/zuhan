package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	c := &cli{strings.NewReader(stdin), &out, &errb}
	code := c.run(args)
	return code, out.String(), errb.String()
}

func TestCLIEndToEndOffline(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "iocdb.json")
	t.Setenv("ZUHAN_DB", db)
	t.Setenv("HOME", dir) // no real config
	t.Setenv("XDG_CONFIG_HOME", dir)

	if code, _, e := run(t, "", "db", "add", "evil.com", "6.6.6.6", "-tag", "c2"); code != 0 {
		t.Fatalf("add: %d %s", code, e)
	}
	if code, _, _ := run(t, "nope\n", "db", "add"); code != 1 {
		t.Fatalf("add invalid via stdin should fail, got %d", code)
	}

	// offline scan: listed -> exit 2, unknown -> 0
	if code, out, _ := run(t, "", "-offline", "-no-color", "login.evil.com", "6.6.6.6"); code != 2 || !strings.Contains(out, "parent domain evil.com") {
		t.Fatalf("offline scan: %d\n%s", code, out)
	}
	if code, _, _ := run(t, "", "scan", "-offline", "8.8.8.8"); code != 0 {
		t.Fatalf("clean offline: %d", code)
	}

	// dump: extract + import + scan
	dump := filepath.Join(dir, "trace.log")
	os.WriteFile(dump, []byte(`connect("hxxp://c2[.]top/gate") ip=45.9.148.114 local=10.0.0.5 kernel32.dll`), 0o600)
	if code, out, _ := run(t, "", "extract", dump, "-o", "txt"); code != 0 || out != "http://c2.top/gate\nc2.top\n45.9.148.114\n" {
		t.Fatalf("extract: %d %q", code, out)
	}
	if code, out, _ := run(t, "", "db", "import", dump, "-tag", "sandbox"); code != 0 || !strings.Contains(out, "3 added") {
		t.Fatalf("import: %d %s", code, out)
	}
	if code, _, e := run(t, "", "scan", "-offline", "-dump", dump); code != 2 || !strings.Contains(e, "3 IOCs extracted") {
		t.Fatalf("scan -dump: %d %s", code, e)
	}

	// list / export / rm
	_, out, _ := run(t, "", "db", "list", "-o", "json", "-type", "ip")
	var f struct{ Count int }
	if json.Unmarshal([]byte(out), &f); f.Count != 2 {
		t.Fatalf("list json: %s", out)
	}
	if _, out, _ = run(t, "", "db", "export", "-origin", "import"); out != "45.9.148.114\nc2.top\nhttp://c2.top/gate\n" {
		t.Fatalf("export: %q", out)
	}
	exp := filepath.Join(dir, "backup.json")
	run(t, "", "db", "export", exp)
	if code, out, _ := run(t, "", "db", "rm", "evil.com"); code != 0 || !strings.HasPrefix(out, "1 removed") {
		t.Fatalf("rm: %s", out)
	}
	// re-import a ZUHAN export restores the entry with its tags
	run(t, "", "db", "import", exp)
	if _, out, _ = run(t, "", "db", "list", "-search", "c2", "-o", "txt"); !strings.Contains(out, "evil.com") {
		t.Fatalf("restore: %q", out)
	}
	if code, _, _ := run(t, "", "db", "bogus"); code != 1 {
		t.Fatal("unknown db cmd should fail")
	}
}

func TestLegacyMigration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("ZUHAN_DB", "")
	t.Setenv("IOCSCAN_DB", "")
	old := filepath.Join(home, ".config", "iocscan")
	os.MkdirAll(old, 0o700)
	os.WriteFile(filepath.Join(old, "config.json"), []byte(`{"virustotal":"legacykey123456789"}`), 0o600)
	os.WriteFile(filepath.Join(old, "iocdb.json"), []byte(`{"tool":"iocscan","version":1,"entries":[{"value":"evil.com","type":"domain","verdict":"malicious","origin":"manual"}]}`), 0o600)

	code, out, e := run(t, "", "-offline", "-no-color", "evil.com")
	if code != 2 || !strings.Contains(e, "copied your previous iocscan settings") || !strings.Contains(out, "MALICIOUS") {
		t.Fatalf("first run: %d\n%s\n%s", code, out, e)
	}
	b, _ := os.ReadFile(filepath.Join(home, ".config", "zuhan", "config.json"))
	if !strings.Contains(string(b), "legacykey123456789") {
		t.Fatalf("config not migrated: %s", b)
	}
	if _, err := os.Stat(filepath.Join(old, "config.json")); err != nil {
		t.Fatal("old folder must be left untouched")
	}
	// second run: nothing copied again
	if _, _, e := run(t, "", "version"); strings.Contains(e, "copied") {
		t.Fatalf("migrated twice: %s", e)
	}
}
