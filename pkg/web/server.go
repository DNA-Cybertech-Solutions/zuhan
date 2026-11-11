// Package web serves the ZUHAN browser UI and its JSON API.
//
// The server is meant to run on the analyst's own machine only:
//   - it must listen on a loopback address (127.0.0.1 / ::1 / localhost);
//   - every request's Host header must be that loopback address
//     (blocks DNS-rebinding attacks from malicious web pages);
//   - every API call needs a random per-run token in the X-Zuhan-Token
//     header. The token is only embedded in the page served to the same
//     origin, and the custom header forces a CORS preflight that the
//     server never approves, so other sites cannot call the API (CSRF).
package web

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/engine"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/extract"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/report"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/store"
)

//go:embed index.html
var indexHTML string

const tokenHeader = "X-Zuhan-Token"

// maxBody limits JSON request bodies (dumps can be large).
const maxBody = 64 << 20

// Server is the UI + API.
type Server struct {
	Base       *zuhan.Scanner // sources (incl. local list) and store; swapped when keys change
	DBPath     string
	ConfigPath string // shown in the UI
	Version    string

	// ConfigFile is the config file the key editor writes to. Rebuild turns
	// fresh keys into a new scanner. If either is unset, keys are read-only.
	ConfigFile string
	Rebuild    func(sources.Keys) *zuhan.Scanner

	mu    sync.RWMutex // guards Base
	token string
	hosts map[string]bool
}

func (s *Server) base() *zuhan.Scanner {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Base
}

// New prepares a server for an already-bound listener address.
func New(base *zuhan.Scanner, addr net.Addr) (*Server, error) {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || !tcp.IP.IsLoopback() {
		return nil, fmt.Errorf("web UI must listen on a loopback address, got %v", addr)
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	p := strconv.Itoa(tcp.Port)
	return &Server{
		Base:  base,
		token: hex.EncodeToString(b),
		hosts: map[string]bool{"127.0.0.1:" + p: true, "localhost:" + p: true, "[::1]:" + p: true},
	}, nil
}

// Token returns the per-run API token (for tests).
func (s *Server) Token() string { return s.token }

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /api/info", s.info)
	mux.HandleFunc("POST /api/scan", s.scan)
	mux.HandleFunc("POST /api/extract", s.extract)
	mux.HandleFunc("POST /api/hash", s.hash)
	mux.HandleFunc("POST /api/report", s.report)
	mux.HandleFunc("GET /api/db", s.dbList)
	mux.HandleFunc("POST /api/db/add", s.dbAdd)
	mux.HandleFunc("POST /api/db/delete", s.dbDelete)
	mux.HandleFunc("POST /api/db/import", s.dbImport)
	mux.HandleFunc("GET /api/db/export", s.dbExport)
	mux.HandleFunc("GET /api/keys", s.keysGet)
	mux.HandleFunc("POST /api/keys", s.keysSet)
	return s.guard(mux)
}

func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

		if !s.hosts[strings.ToLower(r.Host)] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if o := r.Header.Get("Origin"); o != "" && !s.hosts[strings.ToLower(strings.TrimPrefix(o, "http://"))] {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.Header.Get(tokenHeader)), []byte(s.token)) != 1 {
				writeErr(w, http.StatusUnauthorized, "invalid session token — reload the page")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, strings.Replace(indexHTML, "__ZUHAN_TOKEN__", s.token, 1))
}

// ---------------- helpers ----------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return false
	}
	return true
}

func parseVerdict(s string) sources.Status {
	if strings.EqualFold(s, "suspicious") {
		return sources.StatusSuspicious
	}
	return sources.StatusMalicious
}

func splitTags(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// tokens splits free text into candidate IOC values (one or more per line).
func tokens(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "#"); i >= 0 && !strings.Contains(line[:i], "://") {
			line = line[:i]
		}
		out = append(out, strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == '\t' || r == ',' || r == ';' || r == '\r'
		})...)
	}
	return out
}

// ---------------- info ----------------

type sourceInfo struct {
	ID     string     `json:"id"`
	Name   string     `json:"name"`
	Types  []ioc.Type `json:"types"`
	Status string     `json:"status"` // local | configured | missing | optional | free
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	base := s.base()
	var srcs []sourceInfo
	for _, src := range base.Sources {
		si := sourceInfo{ID: src.ID(), Name: src.Name(), Status: "free"}
		for _, t := range ioc.Types {
			if src.Supports(t) {
				si.Types = append(si.Types, t)
			}
		}
		switch {
		case src.ID() == "localdb":
			si.Status = "local"
		case src.RequiresKey() && src.Configured():
			si.Status = "configured"
		case src.RequiresKey():
			si.Status = "missing"
		case src.ID() == "otx" || src.ID() == "greynoise":
			si.Status = "optional"
		}
		srcs = append(srcs, si)
	}
	count := 0
	if base.Store != nil {
		if es, err := base.Store.List(store.Filter{}); err == nil {
			count = len(es)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.Version, "db_path": s.DBPath, "config_path": s.ConfigPath,
		"db_count": count, "sources": srcs, "keys_editable": s.ConfigFile != "" && s.Rebuild != nil,
	})
}

// ---------------- scan (streams NDJSON) ----------------

type fileHash struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

type scanReq struct {
	Values         string     `json:"values"` // free text, IOCs separated by space/newline/comma
	Dump           string     `json:"dump"`   // raw dump; IOCs are extracted
	Files          []fileHash `json:"files"`  // from /api/hash
	Sources        []string   `json:"sources"`
	Offline        bool       `json:"offline"`
	Save           bool       `json:"save"`
	SaveSuspicious bool       `json:"save_suspicious"`
	KeepPrivate    bool       `json:"keep_private"`
	Max            int        `json:"max"`
	TimeoutSec     int        `json:"timeout_sec"`
}

func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	var req scanReq
	if !readJSON(w, r, &req) {
		return
	}

	var iocs []ioc.IOC
	var skipped []string
	seen := map[string]bool{}
	push := func(i ioc.IOC) {
		if !seen[i.Key()] {
			seen[i.Key()] = true
			iocs = append(iocs, i)
		}
	}
	for _, f := range req.Files {
		if ioc.Parse(f.SHA256).Type != ioc.SHA256 {
			continue
		}
		push(ioc.IOC{Raw: f.Name, Value: f.SHA256, Type: ioc.SHA256, Meta: map[string]string{
			"file": f.Name, "md5": f.MD5, "sha1": f.SHA1, "sha256": f.SHA256, "size": fmt.Sprintf("%d bytes", f.Size),
		}})
	}
	for _, t := range tokens(req.Values) {
		if i := ioc.Parse(t); i.Type.Valid() {
			push(i)
		} else {
			skipped = append(skipped, t)
		}
	}
	var ex *extract.Result
	if strings.TrimSpace(req.Dump) != "" {
		max := req.Max
		if max < 0 {
			max = 0
		}
		res := extract.FromText(req.Dump, extract.Options{KeepPrivate: req.KeepPrivate, Max: max})
		ex = &res
		for _, i := range res.IOCs {
			push(i)
		}
	}
	if len(iocs) == 0 {
		writeErr(w, http.StatusBadRequest, "no valid IOC to scan")
		return
	}

	// per-request copy: never mutate the shared scanner
	base := s.base()
	sc := *base
	sc.Sources = nil
	want := map[string]bool{}
	for _, id := range req.Sources {
		want[id] = true
	}
	for _, src := range base.Sources {
		switch {
		case req.Offline && src.ID() != "localdb":
		case !req.Offline && len(want) > 0 && !want[src.ID()]:
		default:
			sc.Sources = append(sc.Sources, src)
		}
	}
	if len(sc.Sources) == 0 {
		writeErr(w, http.StatusBadRequest, "no source selected")
		return
	}
	sc.Save = zuhan.SavePolicy{Enabled: req.Save && !req.Offline, IncludeSuspicious: req.SaveSuspicious}
	timeout := 25 * time.Second
	if req.TimeoutSec > 0 {
		timeout = time.Duration(req.TimeoutSec) * time.Second
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Accel-Buffering", "no")
	fl, _ := w.(http.Flusher)
	var mu sync.Mutex
	send := func(v any) {
		mu.Lock()
		defer mu.Unlock()
		b, _ := json.Marshal(v)
		w.Write(append(b, '\n'))
		if fl != nil {
			fl.Flush()
		}
	}
	start := map[string]any{"type": "start", "total": len(iocs), "skipped": skipped}
	if ex != nil {
		start["extracted"] = ex
	}
	send(start)

	sc.Engine = engine.Options{Timeout: timeout, Parallel: 4, Progress: func(done, total int) {
		send(map[string]any{"type": "progress", "done": done, "total": total})
	}}
	reps, err := sc.Scan(r.Context(), iocs)
	if r.Context().Err() != nil {
		return
	}
	out := map[string]any{"type": "result", "reports": reps, "summary": report.Summarize(reps)}
	if err != nil {
		out["save_error"] = err.Error()
	}
	send(out)
}

// ---------------- extract / hash / report ----------------

func (s *Server) extract(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text        string `json:"text"`
		KeepPrivate bool   `json:"keep_private"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	res := extract.FromText(req.Text, extract.Options{KeepPrivate: req.KeepPrivate})
	type item struct {
		Type  ioc.Type `json:"type"`
		Value string   `json:"value"`
	}
	items := []item{}
	for _, i := range res.IOCs {
		items = append(items, item{i.Type, i.Value})
	}
	writeJSON(w, http.StatusOK, map[string]any{"iocs": items, "counts": res.Counts})
}

// hash streams uploaded files through MD5/SHA1/SHA256 without keeping them.
func (s *Server) hash(w http.ResponseWriter, r *http.Request) {
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "expected a file upload")
		return
	}
	out := []fileHash{}
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if part.FileName() == "" {
			continue
		}
		m, s1, s2 := md5.New(), sha1.New(), sha256.New()
		n, err := io.Copy(io.MultiWriter(m, s1, s2), part)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		out = append(out, fileHash{
			Name: part.FileName(), Size: n,
			MD5: hex.EncodeToString(m.Sum(nil)), SHA1: hex.EncodeToString(s1.Sum(nil)), SHA256: hex.EncodeToString(s2.Sum(nil)),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": out})
}

// report renders scan results (posted back by the UI) as a downloadable file.
func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	ext := map[string]string{"html": "html", "json": "json", "md": "md", "csv": "csv", "table": "txt"}[format]
	if ext == "" {
		writeErr(w, http.StatusBadRequest, "format: html, json, md, csv, table")
		return
	}
	var req struct {
		Reports []engine.Report `json:"reports"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="zuhan-report-%s.%s"`, time.Now().Format("20060102-150405"), ext))
	w.Header().Set("Content-Type", "application/octet-stream")
	report.Write(w, format, req.Reports, report.Options{Verbose: true, Version: s.Version, Generated: time.Now()})
}

// ---------------- local IOC list ----------------

func (s *Server) needStore(w http.ResponseWriter) bool {
	if s.base().Store == nil {
		writeErr(w, http.StatusServiceUnavailable, "local IOC list is not available")
		return false
	}
	return true
}

func (s *Server) filter(r *http.Request) (store.Filter, error) {
	q := r.URL.Query()
	ts, err := ioc.ParseTypes(q.Get("type"))
	if err != nil {
		return store.Filter{}, err
	}
	return store.Filter{Types: ts, Origin: store.Origin(q.Get("origin")), Search: q.Get("search")}, nil
}

func (s *Server) dbList(w http.ResponseWriter, r *http.Request) {
	if !s.needStore(w) {
		return
	}
	f, err := s.filter(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	all, err := s.base().Store.List(store.Filter{})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	stats := map[string]int{}
	var es []store.Entry
	for _, e := range all {
		stats[string(e.Type)]++
		stats["origin_"+string(e.Origin)]++
		if f.Match(e) {
			es = append(es, e)
		}
	}
	if es == nil {
		es = []store.Entry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": es, "count": len(es), "total": len(all), "stats": stats, "path": s.DBPath})
}

func (s *Server) dbAdd(w http.ResponseWriter, r *http.Request) {
	if !s.needStore(w) {
		return
	}
	var req struct {
		Values  string `json:"values"`
		Tags    string `json:"tags"`
		Note    string `json:"note"`
		Verdict string `json:"verdict"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	type item struct {
		Input  string   `json:"input"`
		Value  string   `json:"value,omitempty"`
		Type   ioc.Type `json:"type,omitempty"`
		Result string   `json:"result"` // added | updated | invalid
	}
	var items []item
	var entries []store.Entry
	counts := map[string]int{}
	seen := map[string]bool{}
	for _, t := range tokens(req.Values) {
		i := ioc.Parse(t)
		if !i.Type.Valid() {
			items = append(items, item{Input: t, Result: "invalid"})
			counts["invalid"]++
			continue
		}
		if seen[i.Key()] {
			continue
		}
		seen[i.Key()] = true
		res := "added"
		if _, ok, _ := s.base().Store.Get(i.Type, i.Value); ok {
			res = "updated"
		}
		counts[res]++
		items = append(items, item{t, i.Value, i.Type, res})
		entries = append(entries, store.Entry{Value: i.Value, Verdict: parseVerdict(req.Verdict), Origin: store.OriginManual, Tags: splitTags(req.Tags), Note: strings.TrimSpace(req.Note)})
	}
	if len(items) == 0 {
		writeErr(w, http.StatusBadRequest, "no IOC given")
		return
	}
	if _, _, err := s.base().Store.Put(entries...); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "added": counts["added"], "updated": counts["updated"], "invalid": counts["invalid"]})
}

func (s *Server) dbDelete(w http.ResponseWriter, r *http.Request) {
	if !s.needStore(w) {
		return
	}
	var req struct {
		Values []string `json:"values"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	var iocs []ioc.IOC
	for _, v := range req.Values {
		if i := ioc.Parse(v); i.Type.Valid() {
			iocs = append(iocs, i)
		}
	}
	n, err := s.base().Store.Delete(iocs...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": n})
}

func (s *Server) dbImport(w http.ResponseWriter, r *http.Request) {
	if !s.needStore(w) {
		return
	}
	var req struct {
		Text        string `json:"text"`
		Name        string `json:"name"`
		Tags        string `json:"tags"`
		Note        string `json:"note"`
		Verdict     string `json:"verdict"`
		KeepPrivate bool   `json:"keep_private"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	res, err := store.Import(s.base().Store, []byte(req.Text), store.ImportOptions{
		Tags: splitTags(req.Tags), Note: strings.TrimSpace(req.Note), Name: req.Name,
		Verdict: parseVerdict(req.Verdict), KeepPrivate: req.KeepPrivate,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) dbExport(w http.ResponseWriter, r *http.Request) {
	if !s.needStore(w) {
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "txt"
	}
	f, err := s.filter(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	es, err := s.base().Store.List(f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	valid := false
	for _, x := range store.ExportFormats {
		valid = valid || x == format
	}
	if !valid {
		writeErr(w, http.StatusBadRequest, "format: txt, json, csv")
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="zuhan-list-%s.%s"`, time.Now().Format("20060102"), format))
	w.Header().Set("Content-Type", "application/octet-stream")
	store.WriteEntries(w, format, es)
}

// Serve runs the server on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
