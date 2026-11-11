// Package extract pulls IOCs (hashes, IPs, domains, URLs) out of free-form
// text: sandbox API-call traces, proxy/firewall logs, raw JSON API
// responses, e-mail headers, threat reports…
//
// It refangs defanged indicators first, un-escapes JSON slashes, and then
// filters the usual false positives: private/reserved IPs, file names that
// look like domains (kernel32.dll, report.pdf.exe, main.py), version
// numbers, and all-zero hashes.
package extract

import (
	"io"
	"net/netip"
	"regexp"
	"strings"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

// Options tunes extraction.
type Options struct {
	KeepPrivate bool       // keep private/loopback/link-local/multicast IPs
	Types       []ioc.Type // only these types (empty = all)
	Max         int        // stop after this many IOCs (0 = unlimited)
}

// Result is what came out of a dump.
type Result struct {
	IOCs      []ioc.IOC        `json:"iocs"`
	Counts    map[ioc.Type]int `json:"counts"`
	Truncated int              `json:"truncated,omitempty"` // dropped because of Max
}

// MaxInput is the largest dump FromReader accepts.
const MaxInput = 256 << 20

// FromReader reads r (up to MaxInput bytes) and extracts IOCs.
func FromReader(r io.Reader, opt Options) (Result, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxInput))
	if err != nil {
		return Result{}, err
	}
	return FromText(string(b), opt), nil
}

var (
	textRefang = strings.NewReplacer(
		`\/`, "/", // JSON-escaped slashes
		"[://]", "://", "[:]", ":", "[.]", ".", "(.)", ".", "{.}", ".",
		"[dot]", ".", "(dot)", ".", "[DOT]", ".", "(DOT)", ".", " [.] ", ".",
		"[@]", "@", "[at]", "@", "[/]", "/",
	)
	hxxpRe = regexp.MustCompile(`(?i)\bh(?:xx|tt)p(s?)(?:\[:\]|:)//`)
	fxpRe  = regexp.MustCompile(`(?i)\bfxp(s?)://`)

	urlRe    = regexp.MustCompile(`(?i)\b(?:https?|ftps?|wss?)://[^\s"'<>` + "`" + `{}|\\^\[\]]+`)
	hashRe   = regexp.MustCompile(`[A-Fa-f0-9]{32,128}`)
	ipv4Re   = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`)
	ipv6Re   = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}`)
	domainRe = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}`)
)

// Refang normalizes defanged text (hxxp, [.], [:], …).
func Refang(s string) string {
	s = textRefang.Replace(s)
	s = hxxpRe.ReplaceAllString(s, "http$1://")
	s = fxpRe.ReplaceAllString(s, "ftp$1://")
	return s
}

// FromText extracts IOCs from s.
func FromText(s string, opt Options) Result {
	s = Refang(s)
	want := map[ioc.Type]bool{}
	for _, t := range opt.Types {
		want[t] = true
	}
	ok := func(t ioc.Type) bool { return len(want) == 0 || want[t] }

	res := Result{Counts: map[ioc.Type]int{}}
	seen := map[string]bool{}
	add := func(raw string, i ioc.IOC) {
		if !i.Type.Valid() || !ok(i.Type) || seen[i.Key()] {
			return
		}
		seen[i.Key()] = true
		if opt.Max > 0 && len(res.IOCs) >= opt.Max {
			res.Truncated++
			return
		}
		i.Raw = raw
		res.IOCs = append(res.IOCs, i)
		res.Counts[i.Type]++
	}

	// 1. hashes
	for _, loc := range hashRe.FindAllStringIndex(s, -1) {
		if !bounded(s, loc, isAlnum) {
			continue
		}
		h := s[loc[0]:loc[1]]
		if n := len(h); n != 32 && n != 40 && n != 64 {
			continue
		}
		if boring(h) {
			continue
		}
		add(h, ioc.Parse(h))
	}

	// 2. URLs
	for _, m := range urlRe.FindAllString(s, -1) {
		m = strings.TrimRight(m, ".,;:)!?'\"*>")
		i := ioc.Parse(m)
		if i.Type == ioc.URL {
			add(m, i)
		}
	}

	// 3. domains
	for _, loc := range domainRe.FindAllStringIndex(s, -1) {
		if !bounded(s, loc, func(c byte) bool { return isAlnum(c) || c == '-' || c == '_' }) {
			continue
		}
		// "evil.com.exe" or "foo.dll." style: skip if followed by ".<alnum>"
		if loc[1]+1 < len(s) && s[loc[1]] == '.' && isAlnum(s[loc[1]+1]) {
			continue
		}
		d := strings.ToLower(s[loc[0]:loc[1]])
		tld := d[strings.LastIndexByte(d, '.')+1:]
		if !validTLD[tld] || fileExt[tld] {
			continue
		}
		add(d, ioc.Parse(d))
	}

	// 4. IPv4
	for _, loc := range ipv4Re.FindAllStringIndex(s, -1) {
		if !bounded(s, loc, func(c byte) bool { return isDigit(c) || c == '.' }) {
			continue
		}
		raw := s[loc[0]:loc[1]]
		a, err := netip.ParseAddr(raw)
		if err != nil || (!opt.KeepPrivate && !public(a)) {
			continue
		}
		add(raw, ioc.Parse(raw))
	}

	// 5. IPv6
	for _, loc := range ipv6Re.FindAllStringIndex(s, -1) {
		if !bounded(s, loc, func(c byte) bool { return isAlnum(c) || c == ':' || c == '.' }) {
			continue
		}
		raw := s[loc[0]:loc[1]]
		if strings.Count(raw, ":") < 2 || len(raw) < 6 {
			continue
		}
		a, err := netip.ParseAddr(raw)
		if err != nil || !a.Is6() || a.Is4In6() || (!opt.KeepPrivate && !public(a)) {
			continue
		}
		add(raw, ioc.Parse(raw))
	}
	return res
}

func public(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return false
	}
	if a.Is4() {
		b := a.As4()
		switch {
		case b[0] == 0, b[0] >= 240, // "this network", reserved + broadcast
			b[0] == 100 && b[1]&0xc0 == 64: // 100.64/10 CGNAT
			return false
		}
	}
	return true
}

func bounded(s string, loc []int, inWord func(byte) bool) bool {
	if loc[0] > 0 && inWord(s[loc[0]-1]) {
		return false
	}
	if loc[1] < len(s) && inWord(s[loc[1]]) {
		return false
	}
	return true
}

func boring(h string) bool {
	h = strings.ToLower(h)
	return strings.Count(h, string(h[0])) == len(h)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlnum(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
