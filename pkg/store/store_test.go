package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
)

func open(t *testing.T) *FileStore {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "sub", "iocdb.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPutGetMergeDelete(t *testing.T) {
	s := open(t)
	a, u, err := s.Put(
		Entry{Value: "Evil[.]COM", Tags: []string{"c2"}},
		Entry{Value: "1.2.3.4", Verdict: sources.StatusSuspicious, Origin: OriginImport},
		Entry{Value: "not an ioc"},
	)
	if err != nil || a != 2 || u != 0 {
		t.Fatalf("put: %d %d %v", a, u, err)
	}
	e, ok, _ := s.Get(ioc.Domain, "evil.com")
	if !ok || e.Verdict != sources.StatusMalicious || e.Origin != OriginManual || e.Tags[0] != "c2" {
		t.Fatalf("get: %+v %v", e, ok)
	}

	// merge: tags union, verdict max, origin kept
	_, u, _ = s.Put(Entry{Value: "1.2.3.4", Verdict: sources.StatusMalicious, Origin: OriginAuto, Tags: []string{"scanner"}, Sources: []string{"VirusTotal"}, Hits: 1})
	e, _, _ = s.Get(ioc.IPv4, "1.2.3.4")
	if u != 1 || e.Verdict != sources.StatusMalicious || e.Origin != OriginImport || e.Hits != 1 || len(e.Sources) != 1 {
		t.Fatalf("merge: %+v", e)
	}

	// persistence: a fresh store sees the same data, file is 0600
	s2, err := Open(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := s2.List(Filter{}); len(l) != 2 || l[0].Type != ioc.IPv4 {
		t.Fatalf("list after reopen: %+v", l)
	}
	if st, _ := os.Stat(s.Path()); st.Mode().Perm() != 0o600 {
		t.Errorf("perm %v", st.Mode().Perm())
	}
	if l, _ := s2.List(Filter{Types: []ioc.Type{ioc.Domain}, Search: "C2"}); len(l) != 1 {
		t.Fatalf("filter: %+v", l)
	}

	// touch + delete
	now := time.Now().Add(time.Hour).UTC()
	s.Touch(now, ioc.Parse("evil.com"), ioc.Parse("unknown.com"))
	e, _, _ = s2.Get(ioc.Domain, "evil.com")
	if e.Hits != 1 || !e.LastSeen.Equal(now) {
		t.Fatalf("touch not visible to other instance: %+v", e)
	}
	if n, _ := s.Delete(ioc.Parse("evil.com"), ioc.Parse("nope.com")); n != 1 {
		t.Fatalf("delete %d", n)
	}
	if _, ok, _ := s2.Get(ioc.Domain, "evil.com"); ok {
		t.Fatal("still there")
	}
}

func TestCorruptFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "db.json")
	os.WriteFile(p, []byte("{nope"), 0o600)
	if _, err := Open(p); err == nil {
		t.Fatal("want error for corrupt file")
	}
}

func TestLocalSource(t *testing.T) {
	s := open(t)
	s.Put(Entry{Value: "evil.com", Tags: []string{"phishing"}},
		Entry{Value: "6.6.6.6"},
		Entry{Value: "http://bad.org/x", Verdict: sources.StatusSuspicious})
	src := &LocalSource{Store: s}
	q := func(v string) sources.Result { return src.Query(context.Background(), ioc.Parse(v)) }

	cases := map[string]sources.Status{
		"evil.com":                sources.StatusMalicious,  // exact
		"login.a.evil.com":        sources.StatusSuspicious, // parent domain
		"http://evil.com/login":   sources.StatusMalicious,  // URL host exact
		"http://x.evil.com/":      sources.StatusSuspicious, // URL host parent
		"https://6.6.6.6:8443/gw": sources.StatusMalicious,  // URL host IP
		"http://bad.org/x":        sources.StatusSuspicious, // stored verdict kept
		"notevil.com":             sources.StatusNotFound,
		"6.6.6.7":                 sources.StatusNotFound,
	}
	for v, want := range cases {
		if r := q(v); r.Status != want {
			t.Errorf("%s: got %s (%s), want %s", v, r.Status, r.Summary, want)
		}
	}
}
