package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DNA-Cybertech-Solutions/zuhan"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/config"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/store"
)

type evilIntel struct{}

func (evilIntel) ID() string               { return "fake" }
func (evilIntel) Name() string             { return "FakeIntel" }
func (evilIntel) Supports(t ioc.Type) bool { return true }
func (evilIntel) RequiresKey() bool        { return false }
func (evilIntel) Configured() bool         { return true }
func (evilIntel) Query(_ context.Context, i ioc.IOC) sources.Result {
	if strings.Contains(i.Value, "evil") || i.Type == ioc.SHA256 {
		return sources.Result{Status: sources.StatusMalicious, Summary: "bad"}
	}
	return sources.Result{Status: sources.StatusClean}
}

type env struct {
	t    *testing.T
	srv  *Server
	h    http.Handler
	host string
	st   *store.FileStore
}

func setup(t *testing.T) *env {
	st, err := store.Open(filepath.Join(t.TempDir(), "db.json"))
	if err != nil {
		t.Fatal(err)
	}
	sc := &zuhan.Scanner{Store: st, Save: zuhan.SavePolicy{Enabled: true}}
	sc.Use(&store.LocalSource{Store: st}, evilIntel{})
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8787}
	srv, err := New(sc, addr)
	if err != nil {
		t.Fatal(err)
	}
	srv.Version = "test"
	return &env{t, srv, srv.Handler(), "127.0.0.1:8787", st}
}

func (e *env) do(method, path string, body any, mod ...func(*http.Request)) *httptest.ResponseRecorder {
	var rd io.Reader
	ct := ""
	switch b := body.(type) {
	case nil:
	case *bytes.Buffer:
		rd = b
	default:
		j, _ := json.Marshal(b)
		rd, ct = bytes.NewReader(j), "application/json"
	}
	r := httptest.NewRequest(method, path, rd)
	r.Host = e.host
	r.Header.Set(tokenHeader, e.srv.Token())
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	for _, m := range mod {
		m(r)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func TestNewRejectsNonLoopback(t *testing.T) {
	if _, err := New(&zuhan.Scanner{}, &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 1}); err == nil {
		t.Fatal("0.0.0.0 must be rejected")
	}
	if _, err := New(&zuhan.Scanner{}, &net.TCPAddr{IP: net.IPv4(192, 168, 1, 5), Port: 1}); err == nil {
		t.Fatal("LAN IP must be rejected")
	}
}

func TestSecurity(t *testing.T) {
	e := setup(t)
	// page: host check, token embedded, CSP set
	w := e.do("GET", "/", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), e.srv.Token()) || w.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("index: %d", w.Code)
	}
	if w := e.do("GET", "/", nil, func(r *http.Request) { r.Host = "evil.com:8787" }); w.Code != 403 {
		t.Fatalf("dns rebinding host accepted: %d", w.Code)
	}
	if w := e.do("GET", "/api/info", nil, func(r *http.Request) { r.Header.Del(tokenHeader) }); w.Code != 401 {
		t.Fatalf("missing token accepted: %d", w.Code)
	}
	if w := e.do("GET", "/api/info", nil, func(r *http.Request) { r.Header.Set(tokenHeader, "x") }); w.Code != 401 {
		t.Fatalf("wrong token accepted: %d", w.Code)
	}
	if w := e.do("GET", "/api/info", nil, func(r *http.Request) { r.Header.Set("Origin", "https://evil.com") }); w.Code != 403 {
		t.Fatalf("foreign origin accepted: %d", w.Code)
	}
	if w := e.do("GET", "/api/info", nil, func(r *http.Request) { r.Header.Set("Origin", "http://localhost:8787"); r.Host = "localhost:8787" }); w.Code != 200 {
		t.Fatalf("localhost origin rejected: %d", w.Code)
	}
	if w := e.do("GET", "/nope", nil); w.Code != 404 {
		t.Fatalf("unknown path: %d", w.Code)
	}
}

func readStream(t *testing.T, body string) (events []map[string]any) {
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad ndjson line %q", sc.Text())
		}
		events = append(events, m)
	}
	return
}

func TestScanFlow(t *testing.T) {
	e := setup(t)
	w := e.do("POST", "/api/scan", map[string]any{
		"values": "evil.com, 8.8.8.8\nnot-an-ioc", "dump": `connect("hxxp://evil[.]top/x") 10.0.0.1`,
		"save": true, "max": 50,
	})
	ev := readStream(t, w.Body.String())
	if w.Code != 200 || len(ev) < 3 || ev[0]["type"] != "start" || ev[len(ev)-1]["type"] != "result" {
		t.Fatalf("stream: %d %s", w.Code, w.Body.String())
	}
	if ev[0]["total"].(float64) != 4 || len(ev[0]["skipped"].([]any)) != 1 {
		t.Fatalf("start: %v", ev[0])
	}
	res := ev[len(ev)-1]
	reps := res["reports"].([]any)
	if len(reps) != 4 || res["summary"].(map[string]any)["Malicious"].(float64) != 3 {
		t.Fatalf("result: %v", res["summary"])
	}
	if _, ok, _ := e.st.Get(ioc.Domain, "evil.com"); !ok {
		t.Fatal("malicious not auto-saved")
	}

	// offline: only local source, no saving
	w = e.do("POST", "/api/scan", map[string]any{"values": "evil.com evil2.com", "offline": true, "save": true})
	ev = readStream(t, w.Body.String())
	last := ev[len(ev)-1]["reports"].([]any)
	for _, r := range last {
		for _, x := range r.(map[string]any)["results"].([]any) {
			if src := x.(map[string]any)["source"]; src != store.LocalSourceName {
				t.Fatalf("offline used %v", src)
			}
		}
	}
	if _, ok, _ := e.st.Get(ioc.Domain, "evil2.com"); ok {
		t.Fatal("offline scan saved")
	}

	// source filter + nothing valid
	if w := e.do("POST", "/api/scan", map[string]any{"values": "???"}); w.Code != 400 {
		t.Fatalf("empty scan: %d", w.Code)
	}
	if w := e.do("POST", "/api/scan", map[string]any{"values": "a.com", "sources": []string{"nope"}}); w.Code != 400 {
		t.Fatalf("no sources: %d", w.Code)
	}

	// report round trip
	body := map[string]any{"reports": last}
	w = e.do("POST", "/api/report?format=html", body)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "evil.com") || !strings.Contains(w.Header().Get("Content-Disposition"), ".html") {
		t.Fatalf("report: %d", w.Code)
	}
	if w := e.do("POST", "/api/report?format=exe", body); w.Code != 400 {
		t.Fatalf("bad format: %d", w.Code)
	}
}

func TestHashAndFileScan(t *testing.T) {
	e := setup(t)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "eicar.txt")
	io.WriteString(fw, `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
	mw.Close()
	w := e.do("POST", "/api/hash", &buf, func(r *http.Request) { r.Header.Set("Content-Type", mw.FormDataContentType()) })
	var hr struct{ Files []fileHash }
	json.Unmarshal(w.Body.Bytes(), &hr)
	if w.Code != 200 || len(hr.Files) != 1 || hr.Files[0].MD5 != "44d88612fea8a8f36de82e1278abb02f" {
		t.Fatalf("hash: %d %s", w.Code, w.Body.String())
	}
	w = e.do("POST", "/api/scan", map[string]any{"files": hr.Files, "save": true})
	if !strings.Contains(w.Body.String(), `"local_db":"added"`) {
		t.Fatalf("file scan: %s", w.Body.String())
	}
	// all three hashes of the file are now listed
	for _, h := range []string{hr.Files[0].MD5, hr.Files[0].SHA1, hr.Files[0].SHA256} {
		if _, ok, _ := e.st.Get(ioc.Parse(h).Type, h); !ok {
			t.Errorf("%s not listed", h)
		}
	}
}

func TestDBEndpoints(t *testing.T) {
	e := setup(t)
	w := e.do("POST", "/api/db/add", map[string]any{"values": "evil.com 6.6.6.6\nbad input", "tags": "c2, vaka", "verdict": "suspicious"})
	var ar struct{ Added, Updated, Invalid int }
	json.Unmarshal(w.Body.Bytes(), &ar)
	if w.Code != 200 || ar.Added != 2 || ar.Invalid != 2 {
		t.Fatalf("add: %s", w.Body.String())
	}
	w = e.do("POST", "/api/db/add", map[string]any{"values": "evil.com"})
	json.Unmarshal(w.Body.Bytes(), &ar)
	if ar.Updated != 1 {
		t.Fatalf("re-add: %s", w.Body.String())
	}

	w = e.do("POST", "/api/db/import", map[string]any{"text": "log: hxxp://x[.]top/a 45.9.148.114 192.168.0.1", "name": "trace.log", "tags": "sandbox"})
	var ir store.ImportResult
	json.Unmarshal(w.Body.Bytes(), &ir)
	if ir.Found != 3 || ir.Added != 3 {
		t.Fatalf("import: %s", w.Body.String())
	}

	var lr struct {
		Entries []store.Entry
		Count   int
		Total   int
	}
	json.Unmarshal(e.do("GET", "/api/db?type=ip", nil).Body.Bytes(), &lr)
	if lr.Count != 2 || lr.Total != 5 {
		t.Fatalf("list: %+v", lr)
	}
	json.Unmarshal(e.do("GET", "/api/db?search=sandbox&origin=import", nil).Body.Bytes(), &lr)
	if lr.Count != 3 {
		t.Fatalf("search: %+v", lr.Count)
	}
	if w := e.do("GET", "/api/db?type=bogus", nil); w.Code != 400 {
		t.Fatalf("bad type: %d", w.Code)
	}

	w = e.do("GET", "/api/db/export?format=txt&type=domain", nil)
	if w.Body.String() != "evil.com\nx.top\n" {
		t.Fatalf("export: %q", w.Body.String())
	}
	if w := e.do("GET", "/api/db/export?format=xml", nil); w.Code != 400 {
		t.Fatalf("bad export format: %d", w.Code)
	}

	w = e.do("POST", "/api/db/delete", map[string]any{"values": []string{"evil.com", "nope.com"}})
	if !strings.Contains(w.Body.String(), `"deleted":1`) {
		t.Fatalf("delete: %s", w.Body.String())
	}
	var info struct {
		DBCount int `json:"db_count"`
		Sources []sourceInfo
	}
	json.Unmarshal(e.do("GET", "/api/info", nil).Body.Bytes(), &info)
	if info.DBCount != 4 || len(info.Sources) != 2 || info.Sources[0].Status != "local" {
		t.Fatalf("info: %+v", info)
	}
}

func TestKeys(t *testing.T) {
	e := setup(t)
	cfg := filepath.Join(t.TempDir(), "conf", "config.json")
	t.Setenv("VT_API_KEY", "")
	t.Setenv("GREYNOISE_API_KEY", "from-env-1234567890")

	// read-only until ConfigFile + Rebuild are set
	if w := e.do("POST", "/api/keys", map[string]any{"set": map[string]string{"virustotal": "x"}}); w.Code != 403 {
		t.Fatalf("read-only: %d", w.Code)
	}
	e.srv.ConfigFile = cfg
	e.srv.Rebuild = func(k sources.Keys) *zuhan.Scanner { return zuhan.New(k, e.st) }

	secret := "abcdef0123456789abcdef0123456789SECRETEND"
	w := e.do("POST", "/api/keys", map[string]any{"set": map[string]string{"virustotal": "  " + secret + "  ", "abusech": "short"}})
	if w.Code != 200 {
		t.Fatalf("set: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), "short") {
		t.Fatal("key leaked back to the browser")
	}
	var kr struct {
		Editable bool
		Keys     []keyView
	}
	json.Unmarshal(w.Body.Bytes(), &kr)
	got := map[string]keyView{}
	for _, k := range kr.Keys {
		got[k.ID] = k
	}
	if !kr.Editable || !got["virustotal"].Set || got["virustotal"].Masked != "••••••••TEND" || got["abusech"].Masked != "••••" ||
		got["otx"].Set || !got["greynoise"].FromEnv {
		t.Fatalf("view: %+v", got)
	}
	// file written, 0600, trimmed
	f, err := config.ReadFile(cfg)
	if err != nil || f.VirusTotal != secret || f.AbuseCH != "short" {
		t.Fatalf("file: %+v %v", f, err)
	}
	if st, _ := os.Stat(cfg); st.Mode().Perm() != 0o600 {
		t.Fatalf("perm %v", st.Mode().Perm())
	}
	// sources hot-reloaded
	var info struct{ Sources []sourceInfo }
	json.Unmarshal(e.do("GET", "/api/info", nil).Body.Bytes(), &info)
	st := map[string]string{}
	for _, s := range info.Sources {
		st[s.ID] = s.Status
	}
	if st["virustotal"] != "configured" || st["malwarebazaar"] != "configured" || st["abuseipdb"] != "missing" || st["localdb"] != "local" {
		t.Fatalf("reload: %v", st)
	}

	// clear one, other untouched
	e.do("POST", "/api/keys", map[string]any{"clear": []string{"abusech"}})
	f, _ = config.ReadFile(cfg)
	if f.AbuseCH != "" || f.VirusTotal != secret {
		t.Fatalf("clear: %+v", f)
	}
	// validation
	for _, body := range []map[string]any{
		{"set": map[string]string{"nope": "x"}},
		{"set": map[string]string{"otx": "two words"}},
		{"set": map[string]string{"otx": "   "}},
		{"clear": []string{"nope"}},
	} {
		if w := e.do("POST", "/api/keys", body); w.Code != 400 {
			t.Errorf("%v: %d", body, w.Code)
		}
	}
}
