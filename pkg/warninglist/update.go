package warninglist

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// UpdateOptions controls Update.
type UpdateOptions struct {
	MaxBytes int64 // skip lists larger than this (0 = 5 MB); -1 = no limit
	Only     []string
	// APIBase / RawBase are overridable for tests and mirrors.
	APIBase  string // default https://api.github.com/repos/MISP/misp-warninglists
	RawBase  string // default https://raw.githubusercontent.com/MISP/misp-warninglists/main
	Client   *http.Client
	Parallel int
	Progress func(done, total int)
}

// UpdateResult summarises an Update.
type UpdateResult struct {
	Lists   int      `json:"lists"`
	Entries int      `json:"entries"`
	Skipped []string `json:"skipped,omitempty"` // too large or unusable
	Path    string   `json:"path"`
}

// Update downloads the current MISP warninglists from GitHub and writes
// them to path (gzip'ed JSON lines), replacing the embedded snapshot.
func Update(ctx context.Context, path string, opt UpdateOptions) (UpdateResult, error) {
	res := UpdateResult{Path: path}
	if opt.APIBase == "" {
		opt.APIBase = "https://api.github.com/repos/MISP/misp-warninglists"
	}
	if opt.RawBase == "" {
		opt.RawBase = "https://raw.githubusercontent.com/MISP/misp-warninglists/main"
	}
	if opt.Client == nil {
		opt.Client = &http.Client{}
	}
	if opt.MaxBytes == 0 {
		opt.MaxBytes = 5 << 20
	}
	if opt.Parallel <= 0 {
		opt.Parallel = 8
	}

	// one API call lists every file with its size
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Size int64  `json:"size"`
		} `json:"tree"`
	}
	if err := fetchJSON(ctx, opt.Client, opt.APIBase+"/git/trees/main?recursive=1", &tree); err != nil {
		return res, fmt.Errorf("listing warninglists: %w", err)
	}
	only := map[string]bool{}
	for _, o := range opt.Only {
		only[strings.TrimSpace(o)] = true
	}
	type item struct {
		id   string
		size int64
	}
	var items []item
	for _, t := range tree.Tree {
		parts := strings.Split(t.Path, "/")
		if len(parts) != 3 || parts[0] != "lists" || parts[2] != "list.json" {
			continue
		}
		id := parts[1]
		if len(only) > 0 && !only[id] {
			continue
		}
		if opt.MaxBytes > 0 && t.Size > opt.MaxBytes {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s (%.1f MB)", id, float64(t.Size)/(1<<20)))
			continue
		}
		items = append(items, item{id, t.Size})
	}
	if len(items) == 0 {
		return res, fmt.Errorf("no warninglists to download")
	}

	lists := make([]List, len(items))
	ok := make([]bool, len(items))
	errs := make([]error, len(items))
	sem := make(chan struct{}, opt.Parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for k, it := range items {
		wg.Add(1)
		go func(k int, it item) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			b, err := fetch(ctx, opt.Client, opt.RawBase+"/lists/"+it.id+"/list.json")
			if err == nil {
				lists[k], ok[k], err = FromMISP(it.id, b)
			}
			errs[k] = err
			if opt.Progress != nil {
				mu.Lock()
				done++
				opt.Progress(done, len(items))
				mu.Unlock()
			}
		}(k, it)
	}
	wg.Wait()

	var keep []List
	for k := range items {
		if errs[k] != nil {
			return res, errs[k]
		}
		if !ok[k] {
			res.Skipped = append(res.Skipped, items[k].id+" (no matching IOC types)")
			continue
		}
		keep = append(keep, lists[k])
		res.Entries += len(lists[k].Entries)
	}
	sort.Slice(keep, func(a, b int) bool { return keep[a].ID < keep[b].ID })
	res.Lists = len(keep)

	var buf bytes.Buffer
	if err := Write(&buf, keep); err != nil {
		return res, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return res, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".warninglists-*.tmp")
	if err != nil {
		return res, err
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return res, err
	}
	tmp.Close()
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return res, err
	}
	Reset()
	return res, nil
}

func fetch(ctx context.Context, c *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "zuhan-warninglists")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

func fetchJSON(ctx context.Context, c *http.Client, u string, v any) error {
	b, err := fetch(ctx, c, u)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
