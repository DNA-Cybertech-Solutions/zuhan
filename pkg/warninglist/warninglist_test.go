package warninglist

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
)

const dnsList = `{"name":"List of known IPv4 public DNS resolvers","type":"cidr","version":20261001,
 "matching_attributes":["ip-src","ip-dst","domain|ip"],"list":["8.8.8.8/32","1.1.1.0/24"]}`
const cloudList = `{"name":"List of known Amazon AWS IP address ranges","type":"cidr","version":20261001,
 "matching_attributes":["ip-src","ip-dst"],"list":["3.0.0.0/9"]}`
const hostingList = `{"name":"List of known hosting domains","type":"hostname","version":20261001,
 "matching_attributes":["hostname","domain","url"],"list":["blogspot.com","github.io"]}`
const hashList = `{"name":"List of known hashes of empty files","type":"string","version":20261001,
 "matching_attributes":["md5","sha256"],"list":["d41d8cd98f00b204e9800998ecf8427e"]}`

func testSet(t *testing.T) *Set {
	t.Helper()
	var lists []List
	for id, js := range map[string]string{"public-dns-v4": dnsList, "amazon-aws": cloudList,
		"second-level-tlds": hostingList, "empty-hashes": hashList} {
		l, ok, err := FromMISP(id, []byte(js))
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v", id, ok, err)
		}
		lists = append(lists, l)
	}
	var buf bytes.Buffer
	if err := Write(&buf, lists); err != nil {
		t.Fatal(err)
	}
	s, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func kinds(ms []Match) string {
	var out []string
	for _, m := range ms {
		out = append(out, m.ListID+":"+m.Kind+":"+m.How)
	}
	return strings.Join(out, ",")
}

func TestMatchKinds(t *testing.T) {
	s := testSet(t)
	cases := map[string]string{
		"8.8.8.8":                          "public-dns-v4:benign:exact",
		"1.1.1.7":                          "public-dns-v4:benign:exact",
		"3.5.6.7":                          "amazon-aws:context:exact",
		"evil.blogspot.com":                "second-level-tlds:context:parent domain",
		"https://x.github.io/payload.exe":  "second-level-tlds:context:URL host",
		"d41d8cd98f00b204e9800998ecf8427e": "empty-hashes:benign:exact",
		"9.9.9.9":                          "",
		"example.org":                      "",
	}
	for in, want := range cases {
		if got := kinds(s.Match(ioc.Parse(in))); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}

func TestEmbeddedSnapshot(t *testing.T) {
	Reset()
	s, err := Load("")
	if err != nil || s.Len() < 50 || s.Source != "embedded" {
		t.Fatalf("embedded: %v %v", s, err)
	}
	if ms := s.Match(ioc.Parse("8.8.8.8")); len(ms) == 0 {
		t.Fatal("8.8.8.8 should be on a public DNS list")
	}
	if s.Updated.Year() > 2100 {
		t.Fatalf("bogus updated %v", s.Updated)
	}
}

func TestSourceResult(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wl.jsonl.gz")
	srv := fakeGitHub(t)
	if _, err := Update(context.Background(), path, UpdateOptions{APIBase: srv, RawBase: srv}); err != nil {
		t.Fatal(err)
	}
	src := &Source{Path: path}
	r := src.Query(context.Background(), ioc.Parse("8.8.8.8"))
	if r.Status != sources.StatusInfo || r.Benign == "" || r.Context != "" {
		t.Fatalf("8.8.8.8: %+v", r)
	}
	r = src.Query(context.Background(), ioc.Parse("a.blogspot.com"))
	if r.Benign != "" || r.Context == "" {
		t.Fatalf("subdomain must be context only: %+v", r)
	}
	if r = src.Query(context.Background(), ioc.Parse("9.9.9.9")); r.Status != sources.StatusNotFound {
		t.Fatalf("9.9.9.9: %+v", r)
	}
	if !src.LocalOnly() {
		t.Fatal("warninglists are local")
	}
}

func fakeGitHub(t *testing.T) string {
	files := map[string]string{"public-dns-v4": dnsList, "second-level-tlds": hostingList, "huge": cloudList}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/git/trees/main" {
			var items []string
			for id, js := range files {
				size := len(js)
				if id == "huge" {
					size = 50 << 20
				}
				items = append(items, fmt.Sprintf(`{"path":"lists/%s/list.json","size":%d}`, id, size))
			}
			items = append(items, `{"path":"README.md","size":10}`)
			io.WriteString(w, `{"tree":[`+strings.Join(items, ",")+`]}`)
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/lists/"), "/list.json")
		if js, ok := files[id]; ok {
			io.WriteString(w, js)
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "wl.jsonl.gz")
	srv := fakeGitHub(t)
	res, err := Update(context.Background(), path, UpdateOptions{APIBase: srv, RawBase: srv})
	if err != nil {
		t.Fatal(err)
	}
	if res.Lists != 2 || len(res.Skipped) != 1 || !strings.HasPrefix(res.Skipped[0], "huge") {
		t.Fatalf("result %+v", res)
	}
	s, err := Load(path)
	if err != nil || s.Source != path || s.Len() != 2 {
		t.Fatalf("load after update: %+v %v", s, err)
	}
	res, err = Update(context.Background(), path, UpdateOptions{APIBase: srv, RawBase: srv, MaxBytes: -1, Only: []string{"huge"}})
	if err != nil || res.Lists != 1 {
		t.Fatalf("only+all: %+v %v", res, err)
	}
}
