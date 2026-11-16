// Package warninglist matches IOCs against MISP warninglists
// (https://github.com/MISP/misp-warninglists, CC0): lists of known benign
// infrastructure (public DNS resolvers, private ranges, popular domains,
// known false-positive hashes…) and of neutral context (cloud and hosting
// ranges, Tor exit nodes, scanners, URL shorteners…).
//
// A snapshot of every list up to 1.5 MB ships inside the binary; `zuhan
// warninglists update` downloads the current lists into the config folder,
// and that file is used instead when present.
package warninglist

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

//go:embed default.jsonl.gz
var embedded []byte

// Kind says what a match means.
const (
	KindBenign  = "benign"  // known-good: should not be treated as an IOC
	KindContext = "context" // neutral context: hosting, Tor, scanners…
)

// List is one warninglist in ZUHAN's storage format (one JSON object per
// line in a gzip file).
type List struct {
	ID      string   `json:"id"`   // MISP folder name, e.g. public-dns-v4
	Name    string   `json:"name"` // MISP display name
	Type    string   `json:"type"` // string | hostname | cidr | substring | regex
	Kind    string   `json:"kind"`
	Attrs   []string `json:"attrs"` // MISP matching_attributes
	Version int64    `json:"version"`
	Entries []string `json:"list"`
}

// Label is a short human name: "Tor exit nodes" for "List of known Tor exit nodes".
func (l List) Label() string {
	n := l.Name
	for _, p := range []string{"List of known ", "List of ", "Known "} {
		if strings.HasPrefix(n, p) {
			n = n[len(p):]
			break
		}
	}
	if n == "" {
		n = l.ID
	}
	return strings.ToUpper(n[:1]) + n[1:]
}

// benignIDs are lists whose exact matches mean "known good". Everything
// else (cloud and hosting ranges, scanners, Tor, VPNs, shorteners, dynamic
// DNS…) is context: malicious things are hosted there all the time.
var benignIDs = map[string]bool{
	"common-ioc-false-positive": true, "empty-hashes": true, "ti-falsepositives": true,
	"mozilla-CA": true, "mozilla-IntermediateCA": true, "nioc-filehash": true, "windows-binary-hashes": true,
	"public-dns-v4": true, "public-dns-v6": true, "public-dns-hostname": true,
	"rfc1918": true, "rfc3849": true, "rfc5735": true, "rfc6598": true, "rfc6761": true,
	"multicast": true, "ipv6-linklocal": true, "crl-hostname": true, "crl-ip": true,
	"googlebot": true, "google-gmail-sending-ips": true, "google": true, "microsoft": true,
	"microsoft-office365": true, "microsoft-office365-ip": true, "microsoft-office365-cn": true,
	"microsoft-win10-connection-endpoints": true, "microsoft-win11-connection-endpoints": true,
	"apple-domains": true, "umbrella-blockpage-hostname": true, "umbrella-blockpage-v4": true,
	"umbrella-blockpage-v6": true, "captive-portals": true, "security-provider-blogpost": true,
	"bank-website": true, "dax30": true, "tlds": true, "second-level-tlds": true, "university_domains": true,
	"covid-19-cyber-threat-coalition-whitelist": true, "covid-19-krassi-whitelist": true,
}

// KindOf classifies a MISP list ID.
func KindOf(id string) string {
	if benignIDs[id] || IsPopularity(id) {
		return KindBenign // popularity lists: the exact domain is a well-known site
	}
	return KindContext
}

// IsPopularity reports whether id is a "top N websites" list.
func IsPopularity(id string) bool {
	for _, p := range []string{"tranco", "cisco_top", "cloudflare-top", "alexa", "majestic", "moz-top", "netapi-top", "google-chrome-crux"} {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

// FromMISP converts one MISP list.json into a List. ok=false for lists that
// cannot match ZUHAN's IOC types.
func FromMISP(id string, data []byte) (List, bool, error) {
	var m struct {
		Name    string   `json:"name"`
		Type    string   `json:"type"`
		Version int64    `json:"version"`
		Attrs   []string `json:"matching_attributes"`
		List    []string `json:"list"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return List{}, false, fmt.Errorf("%s: %w", id, err)
	}
	l := List{ID: id, Name: m.Name, Type: m.Type, Kind: KindOf(id), Attrs: m.Attrs, Version: m.Version, Entries: m.List}
	switch m.Type {
	case "string", "hostname", "cidr", "substring", "regex":
	default:
		return l, false, nil
	}
	useful := false
	for _, a := range m.Attrs {
		if attrTypes[a] {
			useful = true
			break
		}
	}
	return l, useful && len(m.List) > 0, nil
}

// attrTypes are the MISP attribute types ZUHAN IOCs map to.
var attrTypes = map[string]bool{
	"md5": true, "sha1": true, "sha256": true, "filename|md5": true, "filename|sha1": true, "filename|sha256": true,
	"ip-src": true, "ip-dst": true, "ip-src|port": true, "ip-dst|port": true, "domain|ip": true,
	"domain": true, "hostname": true, "url": true, "uri": true,
}

// candidate is a value to test plus the MISP attribute types it counts as.
type candidate struct {
	value string
	attrs []string
	exact bool // the IOC itself (not a URL's host or a parent domain)
	addr  netip.Addr
}

func candidates(i ioc.IOC) []candidate {
	switch i.Type {
	case ioc.MD5, ioc.SHA1, ioc.SHA256:
		t := string(i.Type)
		return []candidate{{value: i.Value, attrs: []string{t, "filename|" + t}, exact: true}}
	case ioc.IPv4, ioc.IPv6:
		a, _ := netip.ParseAddr(i.Value)
		return []candidate{{value: i.Value, attrs: []string{"ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "domain|ip"}, exact: true, addr: a}}
	case ioc.Domain:
		return []candidate{{value: i.Value, attrs: []string{"domain", "hostname", "domain|ip"}, exact: true}}
	case ioc.URL:
		out := []candidate{{value: strings.ToLower(i.Value), attrs: []string{"url", "uri"}, exact: true}}
		if u, err := url.Parse(i.Value); err == nil && u.Hostname() != "" {
			h := strings.ToLower(u.Hostname())
			if a, err := netip.ParseAddr(h); err == nil {
				out = append(out, candidate{value: h, attrs: []string{"ip-dst", "domain|ip"}, addr: a})
			} else {
				out = append(out, candidate{value: h, attrs: []string{"domain", "hostname", "domain|ip"}})
			}
		}
		return out
	}
	return nil
}

// compiled is a List prepared for fast matching.
type compiled struct {
	List
	attrs    map[string]bool
	strs     map[string]struct{}
	hosts    map[string]struct{}
	addrs    map[netip.Addr]struct{}
	prefixes []netip.Prefix
	subs     []string
	res      []*regexp.Regexp
}

func compile(l List) *compiled {
	c := &compiled{List: l, attrs: map[string]bool{}}
	for _, a := range l.Attrs {
		c.attrs[a] = true
	}
	switch l.Type {
	case "string":
		c.strs = make(map[string]struct{}, len(l.Entries))
		for _, e := range l.Entries {
			c.strs[strings.ToLower(strings.TrimSpace(e))] = struct{}{}
		}
	case "hostname":
		c.hosts = make(map[string]struct{}, len(l.Entries))
		for _, e := range l.Entries {
			c.hosts[strings.Trim(strings.ToLower(strings.TrimSpace(e)), ".")] = struct{}{}
		}
	case "cidr":
		c.addrs = map[netip.Addr]struct{}{}
		for _, e := range l.Entries {
			e = strings.TrimSpace(e)
			if p, err := netip.ParsePrefix(e); err == nil {
				p = p.Masked()
				if p.IsSingleIP() {
					c.addrs[p.Addr()] = struct{}{}
				} else {
					c.prefixes = append(c.prefixes, p)
				}
			} else if a, err := netip.ParseAddr(e); err == nil {
				c.addrs[a.Unmap()] = struct{}{}
			}
		}
	case "substring":
		for _, e := range l.Entries {
			if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
				c.subs = append(c.subs, e)
			}
		}
	case "regex":
		for _, e := range l.Entries {
			if re, err := regexp.Compile(e); err == nil {
				c.res = append(c.res, re)
			}
		}
	}
	return c
}

func (c *compiled) applies(cd candidate) bool {
	for _, a := range cd.attrs {
		if c.attrs[a] {
			return true
		}
	}
	return false
}

// match reports whether cd matches; parent=true when only a parent domain did.
func (c *compiled) match(cd candidate) (hit, parent bool) {
	v := strings.ToLower(cd.value)
	switch c.Type {
	case "string":
		_, hit = c.strs[v]
	case "hostname":
		if _, ok := c.hosts[v]; ok {
			return true, false
		}
		for d := v; strings.Contains(d, "."); {
			d = d[strings.IndexByte(d, '.')+1:]
			if _, ok := c.hosts[d]; ok {
				return true, true
			}
		}
	case "cidr":
		if !cd.addr.IsValid() {
			return false, false
		}
		a := cd.addr.Unmap()
		if _, ok := c.addrs[a]; ok {
			return true, false
		}
		for _, p := range c.prefixes {
			if p.Contains(a) {
				return true, false
			}
		}
	case "substring":
		for _, s := range c.subs {
			if strings.Contains(v, s) {
				return true, false
			}
		}
	case "regex":
		for _, re := range c.res {
			if re.MatchString(cd.value) {
				return true, false
			}
		}
	}
	return hit, false
}

// Match is one list an IOC matched.
type Match struct {
	ListID string `json:"list_id"`
	Label  string `json:"label"`
	// Kind is benign only for an exact match on a benign list; a match on
	// a URL's host or a parent domain is always context ("hosted on…").
	Kind string `json:"kind"`
	How  string `json:"how"` // exact | parent domain | URL host
}

// Set is a loaded collection of lists.
type Set struct {
	lists   []*compiled
	Source  string    // "embedded" or the file path
	Updated time.Time // newest list version
}

// Lists returns the loaded lists' metadata (entries omitted), sorted by ID.
func (s *Set) Lists() []List {
	out := make([]List, 0, len(s.lists))
	for _, c := range s.lists {
		l := c.List
		n := len(l.Entries)
		l.Entries = nil
		l.Version = int64(n) // reused as entry count for display
		out = append(out, l)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out
}

// Len is the number of lists.
func (s *Set) Len() int { return len(s.lists) }

// Match tests an IOC against every list.
func (s *Set) Match(i ioc.IOC) []Match {
	var out []Match
	seen := map[string]bool{}
	for _, cd := range candidates(i) {
		for _, c := range s.lists {
			if seen[c.ID] || !c.applies(cd) {
				continue
			}
			hit, parent := c.match(cd)
			if !hit {
				continue
			}
			seen[c.ID] = true
			m := Match{ListID: c.ID, Label: c.Label(), Kind: c.Kind, How: "exact"}
			switch {
			case !cd.exact:
				m.How, m.Kind = "URL host", KindContext
			case parent:
				m.How, m.Kind = "parent domain", KindContext
			}
			out = append(out, m)
		}
	}
	return out
}

// Read loads lists from a gzip'ed JSON-lines stream.
func Read(r io.Reader) (*Set, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	s := &Set{}
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 128<<20)
	for sc.Scan() {
		var l List
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return nil, fmt.Errorf("warninglists: %w", err)
		}
		if l.Kind == "" {
			l.Kind = KindOf(l.ID)
		}
		if v := versionTime(l.Version); v.After(s.Updated) {
			s.Updated = v
		}
		s.lists = append(s.lists, compile(l))
	}
	return s, sc.Err()
}

// Write stores lists as gzip'ed JSON lines.
func Write(w io.Writer, lists []List) error {
	zw, _ := gzip.NewWriterLevel(w, gzip.BestCompression)
	enc := json.NewEncoder(zw)
	enc.SetEscapeHTML(false)
	for _, l := range lists {
		if err := enc.Encode(l); err != nil {
			return err
		}
	}
	return zw.Close()
}

// versionTime reads MISP versions, which are usually yyyymmdd.
func versionTime(v int64) time.Time {
	t, err := time.Parse("20060102", fmt.Sprint(v))
	if err != nil || t.After(time.Now().Add(48*time.Hour)) {
		return time.Time{}
	}
	return t
}

var (
	mu    sync.Mutex
	cache = map[string]*Set{}
)

// Load returns the lists from path if that file exists, else the embedded
// snapshot. Results are cached per path for the life of the process;
// Reset drops the cache (after an update).
func Load(path string) (*Set, error) {
	mu.Lock()
	defer mu.Unlock()
	if s, ok := cache[path]; ok {
		return s, nil
	}
	var s *Set
	b, err := os.ReadFile(path)
	switch {
	case path != "" && err == nil:
		if s, err = Read(bytes.NewReader(b)); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		s.Source = path
	case path == "" || errors.Is(err, fs.ErrNotExist):
		if s, err = Read(bytes.NewReader(embedded)); err != nil {
			return nil, err
		}
		s.Source = "embedded"
	default:
		return nil, err
	}
	cache[path] = s
	return s, nil
}

// Reset clears the Load cache.
func Reset() {
	mu.Lock()
	cache = map[string]*Set{}
	mu.Unlock()
}
