package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

// FileStore keeps the IOC list in a single JSON file. Every write re-reads
// the file first and replaces it atomically (temp file + rename), so the
// file is never left half-written and concurrent runs lose as little as
// possible. Reads are cached until the file changes on disk.
type FileStore struct {
	path string

	mu      sync.Mutex
	cache   map[string]Entry
	modTime time.Time
	size    int64
}

// FileFormat is the on-disk layout (also used by `db export -o json`).
type FileFormat struct {
	Tool    string    `json:"tool"`
	Version int       `json:"version"`
	Updated time.Time `json:"updated"`
	Count   int       `json:"count"`
	Entries []Entry   `json:"entries"`
}

// Open returns a FileStore for path. The file is created on first write;
// an existing but unreadable/corrupt file is reported immediately.
func Open(path string) (*FileStore, error) {
	s := &FileStore{path: path}
	if _, err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path returns the backing file.
func (s *FileStore) Path() string { return s.path }

func (s *FileStore) load() (map[string]Entry, error) {
	st, err := os.Stat(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		s.cache, s.modTime, s.size = map[string]Entry{}, time.Time{}, 0
		return s.cache, nil
	}
	if err != nil {
		return nil, err
	}
	if s.cache != nil && st.ModTime().Equal(s.modTime) && st.Size() == s.size {
		return s.cache, nil
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	m := map[string]Entry{}
	if len(b) > 0 {
		var f FileFormat
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("IOC db %s is corrupt: %w", s.path, err)
		}
		for _, e := range f.Entries {
			m[e.Key()] = e
		}
	}
	s.cache, s.modTime, s.size = m, st.ModTime(), st.Size()
	return m, nil
}

func (s *FileStore) save(m map[string]Entry) error {
	es := make([]Entry, 0, len(m))
	for _, e := range m {
		es = append(es, e)
	}
	sortEntries(es)
	b, err := json.MarshalIndent(FileFormat{ToolName, 1, time.Now().UTC(), len(es), es}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".iocdb-*.tmp")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(append(b, '\n'))
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		return errors.Join(werr, cerr)
	}
	_ = os.Chmod(tmp.Name(), 0o600)
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	s.cache = m
	if st, err := os.Stat(s.path); err == nil {
		s.modTime, s.size = st.ModTime(), st.Size()
	}
	return nil
}

func (s *FileStore) Get(t ioc.Type, value string) (Entry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return Entry{}, false, err
	}
	e, ok := m[string(t)+":"+value]
	return e, ok, nil
}

func (s *FileStore) Put(entries ...Entry) (added, updated int, err error) {
	if len(entries) == 0 {
		return 0, 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return 0, 0, err
	}
	m = clone(m)
	now := time.Now().UTC()
	for _, in := range entries {
		in, ok := Normalize(in, now)
		if !ok {
			continue
		}
		if old, exists := m[in.Key()]; exists {
			m[in.Key()] = Merge(old, in)
			updated++
		} else {
			m[in.Key()] = in
			added++
		}
	}
	if added+updated == 0 {
		return 0, 0, nil
	}
	return added, updated, s.save(m)
}

func (s *FileStore) Touch(at time.Time, iocs ...ioc.IOC) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return err
	}
	m = clone(m)
	changed := false
	for _, i := range iocs {
		if e, ok := m[i.Key()]; ok {
			e.Hits++
			if at.After(e.LastSeen) {
				e.LastSeen = at
			}
			m[i.Key()] = e
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.save(m)
}

func (s *FileStore) Delete(iocs ...ioc.IOC) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return 0, err
	}
	m = clone(m)
	n := 0
	for _, i := range iocs {
		if _, ok := m[i.Key()]; ok {
			delete(m, i.Key())
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	return n, s.save(m)
}

func (s *FileStore) List(f Filter) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range m {
		if f.Match(e) {
			out = append(out, e)
		}
	}
	sortEntries(out)
	return out, nil
}

func clone(m map[string]Entry) map[string]Entry {
	c := make(map[string]Entry, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}
