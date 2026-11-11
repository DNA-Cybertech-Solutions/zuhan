package zuhan_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DNA-Cybertech-Solutions/zuhan"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/store"
)

// fakeIntel flags anything containing "evil" as malicious and "sus" as suspicious.
type fakeIntel struct{}

func (fakeIntel) ID() string               { return "fake" }
func (fakeIntel) Name() string             { return "FakeIntel" }
func (fakeIntel) Supports(t ioc.Type) bool { return true }
func (fakeIntel) RequiresKey() bool        { return false }
func (fakeIntel) Configured() bool         { return true }
func (fakeIntel) Query(_ context.Context, i ioc.IOC) sources.Result {
	switch {
	case strings.Contains(i.Value, "evil"):
		return sources.Result{Status: sources.StatusMalicious}
	case strings.Contains(i.Value, "sus"):
		return sources.Result{Status: sources.StatusSuspicious}
	}
	return sources.Result{Status: sources.StatusClean}
}

func newScanner(t *testing.T) (*zuhan.Scanner, *store.FileStore) {
	st, err := store.Open(filepath.Join(t.TempDir(), "db.json"))
	if err != nil {
		t.Fatal(err)
	}
	sc := &zuhan.Scanner{Store: st, Save: zuhan.SavePolicy{Enabled: true}}
	sc.Use(&store.LocalSource{Store: st}, fakeIntel{})
	return sc, st
}

func TestAutoSave(t *testing.T) {
	sc, st := newScanner(t)
	ctx := context.Background()

	reps, skipped, err := sc.ScanValues(ctx, "evil.com", "sus.com", "good.com", "???")
	if err != nil || len(skipped) != 1 || len(reps) != 3 {
		t.Fatalf("%v %v %d", err, skipped, len(reps))
	}
	if reps[0].LocalDB != "added" || reps[1].LocalDB != "" || reps[2].LocalDB != "" {
		t.Fatalf("local_db: %q %q %q", reps[0].LocalDB, reps[1].LocalDB, reps[2].LocalDB)
	}
	e, ok, _ := st.Get(ioc.Domain, "evil.com")
	if !ok || e.Origin != store.OriginAuto || e.Sources[0] != "FakeIntel" || e.Hits != 1 {
		t.Fatalf("entry %+v", e)
	}
	if _, ok, _ := st.Get(ioc.Domain, "sus.com"); ok {
		t.Fatal("suspicious saved without policy")
	}

	// second scan: local source now flags it too; entry updated, hits grow
	reps, _, _ = sc.ScanValues(ctx, "evil.com")
	if reps[0].LocalDB != "updated" || reps[0].Flagged != 2 {
		t.Fatalf("rescan: %q flagged=%d", reps[0].LocalDB, reps[0].Flagged)
	}
	e, _, _ = st.Get(ioc.Domain, "evil.com")
	if e.Hits != 2 {
		t.Fatalf("hits %d", e.Hits)
	}

	// manually listed IOC that external intel says is clean: only "matched"
	st.Put(store.Entry{Value: "mine.com", Tags: []string{"internal-case-42"}})
	reps, _, _ = sc.ScanValues(ctx, "mine.com")
	if reps[0].LocalDB != "matched" || reps[0].Verdict != sources.StatusMalicious {
		t.Fatalf("manual: %q %s", reps[0].LocalDB, reps[0].Verdict)
	}
	e, _, _ = st.Get(ioc.Domain, "mine.com")
	if e.Hits != 1 || e.Origin != store.OriginManual {
		t.Fatalf("manual entry %+v", e)
	}

	// policy: suspicious + disabled
	sc.Save.IncludeSuspicious = true
	sc.ScanValues(ctx, "sus.com")
	if _, ok, _ := st.Get(ioc.Domain, "sus.com"); !ok {
		t.Fatal("suspicious not saved with policy")
	}
	sc.Save.Enabled = false
	sc.ScanValues(ctx, "evil2.com")
	if _, ok, _ := st.Get(ioc.Domain, "evil2.com"); ok {
		t.Fatal("saved while disabled")
	}
}

func TestFileHashSiblings(t *testing.T) {
	sc, st := newScanner(t)
	sha256 := strings.Repeat("e", 63) + "1"
	i := ioc.IOC{Value: sha256, Type: ioc.SHA256, Meta: map[string]string{
		"md5": strings.Repeat("a", 31) + "b", "sha1": strings.Repeat("1", 39) + "2", "sha256": sha256,
	}}
	sc.Sources = []sources.Source{&store.LocalSource{Store: st}, alwaysBad{}}
	sc.Scan(context.Background(), []ioc.IOC{i})
	for _, v := range []string{sha256, i.Meta["md5"], i.Meta["sha1"]} {
		if _, ok, _ := st.Get(ioc.Parse(v).Type, v); !ok {
			t.Errorf("%s not saved", v)
		}
	}
}

type alwaysBad struct{ fakeIntel }

func (alwaysBad) Query(context.Context, ioc.IOC) sources.Result {
	return sources.Result{Status: sources.StatusMalicious}
}
