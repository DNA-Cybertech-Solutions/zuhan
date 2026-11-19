package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// collector records what the forwarder posts.
func collector(t *testing.T, status int) (*httptest.Server, func() []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var batch []map[string]any
		if err := json.Unmarshal(b, &batch); err != nil {
			t.Errorf("forward body is not a JSON array: %v", err)
		}
		mu.Lock()
		got = append(got, batch...)
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []map[string]any { mu.Lock(); defer mu.Unlock(); return got }
}

func offlineEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ZUHAN_DB", filepath.Join(dir, "iocdb.json"))
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("ZUHAN_FORWARD_URL", "")
}

func TestScanForwardsEveryResult(t *testing.T) {
	offlineEnv(t)
	srv, got := collector(t, http.StatusOK)
	if code, _, e := run(t, "", "db", "add", "44d88612fea8a8f36de82e1278abb02f", "evil.com"); code != 0 {
		t.Fatalf("db add: %s", e)
	}

	code, _, e := run(t, "", "-offline", "-q", "-forward", srv.URL,
		"44d88612fea8a8f36de82e1278abb02f", "evil.com", "8.8.8.8", "http://x.example/a")
	if code != 2 {
		t.Fatalf("exit %d (want 2, something malicious): %s", code, e)
	}
	recs := got()
	if len(recs) != 4 {
		t.Fatalf("want 4 forwarded records (clean ones too), got %d", len(recs))
	}
	byIOC := map[string]map[string]any{}
	for _, r := range recs {
		z := r["zuhan"].(map[string]any)
		byIOC[z["ioc"].(string)] = z
		tags := r["tags"].([]any)
		if len(tags) != 2 || tags[1] != "zuhan-cli" {
			t.Errorf("tags = %v", tags)
		}
	}
	want := map[string][2]string{ // ioc -> {ioc_type, verdict}
		"44d88612fea8a8f36de82e1278abb02f": {"hash", "malicious"},
		"evil.com":                         {"domain", "malicious"},
		"8.8.8.8":                          {"ip", ""},
		"http://x.example/a":               {"url", ""},
	}
	for ioc, w := range want {
		z, ok := byIOC[ioc]
		if !ok {
			t.Errorf("%s was not forwarded", ioc)
			continue
		}
		if z["ioc_type"] != w[0] {
			t.Errorf("%s: ioc_type = %v, want %s", ioc, z["ioc_type"], w[0])
		}
		if w[1] != "" && z["verdict"] != w[1] {
			t.Errorf("%s: verdict = %v, want %s", ioc, z["verdict"], w[1])
		}
	}
}

func TestScanForwardFromEnv(t *testing.T) {
	offlineEnv(t)
	srv, got := collector(t, http.StatusOK)
	t.Setenv("ZUHAN_FORWARD_URL", srv.URL)
	if code, _, e := run(t, "", "-offline", "-q", "8.8.8.8"); code != 0 {
		t.Fatalf("exit %d: %s", code, e)
	}
	if len(got()) != 1 {
		t.Fatalf("ZUHAN_FORWARD_URL should enable forwarding, got %d records", len(got()))
	}
}

func TestScanForwardFailureIsOnlyAWarning(t *testing.T) {
	offlineEnv(t)
	srv, _ := collector(t, http.StatusServiceUnavailable)
	code, out, e := run(t, "", "-offline", "-no-color", "-forward", srv.URL, "8.8.8.8")
	if code != 0 {
		t.Fatalf("a collector error must not change the exit code, got %d", code)
	}
	if !strings.Contains(out, "8.8.8.8") {
		t.Errorf("results must still be printed:\n%s", out)
	}
	if !strings.Contains(e, "503") {
		t.Errorf("want a warning about the collector, got: %s", e)
	}
}

func TestScanForwardBadURL(t *testing.T) {
	offlineEnv(t)
	if code, _, e := run(t, "", "-offline", "-forward", "127.0.0.1:8080", "8.8.8.8"); code != 1 || !strings.Contains(e, "forward URL") {
		t.Fatalf("bad URL should be rejected before scanning: %d %s", code, e)
	}
}
