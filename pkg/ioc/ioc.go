// Package ioc detects and normalizes Indicators of Compromise.
package ioc

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

// Type is the kind of an indicator.
type Type string

const (
	MD5     Type = "md5"
	SHA1    Type = "sha1"
	SHA256  Type = "sha256"
	SHA512  Type = "sha512"
	IPv4    Type = "ipv4"
	IPv6    Type = "ipv6"
	Domain  Type = "domain"
	URL     Type = "url"
	Unknown Type = "unknown"
)

// IsHash reports whether t is a file hash type.
func (t Type) IsHash() bool {
	switch t {
	case MD5, SHA1, SHA256, SHA512:
		return true
	}
	return false
}

// IsIP reports whether t is an IP address type.
func (t Type) IsIP() bool { return t == IPv4 || t == IPv6 }

// Types lists every supported (queryable) type.
var Types = []Type{MD5, SHA1, SHA256, IPv4, IPv6, Domain, URL}

// Valid reports whether t is a supported type.
func (t Type) Valid() bool {
	for _, x := range Types {
		if t == x {
			return true
		}
	}
	return false
}

// ParseTypes turns a comma list like "ip,hash,domain" into types.
// Group aliases: ip = ipv4+ipv6, hash = md5+sha1+sha256.
func ParseTypes(list string) ([]Type, error) {
	var out []Type
	for _, n := range strings.Split(list, ",") {
		switch n = strings.ToLower(strings.TrimSpace(n)); n {
		case "":
		case "ip":
			out = append(out, IPv4, IPv6)
		case "hash":
			out = append(out, MD5, SHA1, SHA256)
		default:
			if !Type(n).Valid() {
				return nil, fmt.Errorf("unknown IOC type %q (md5, sha1, sha256, hash, ipv4, ipv6, ip, domain, url)", n)
			}
			out = append(out, Type(n))
		}
	}
	return out, nil
}

// IOC is a single normalized indicator.
type IOC struct {
	Raw   string            `json:"raw"`
	Value string            `json:"value"`
	Type  Type              `json:"type"`
	Meta  map[string]string `json:"meta,omitempty"`
}

// Key is a unique identity for the indicator (type + normalized value).
func (i IOC) Key() string { return string(i.Type) + ":" + i.Value }

var (
	hexRe    = regexp.MustCompile(`^[a-fA-F0-9]+$`)
	domainRe = regexp.MustCompile(`^([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$`)
	hxxpRe   = regexp.MustCompile(`(?i)^h[x]{2}p(s?)(\[?:\]?)//`)
	refanger = strings.NewReplacer(
		"[://]", "://",
		"[:]", ":",
		"[.]", ".", "(.)", ".", "{.}", ".",
		"[dot]", ".", "(dot)", ".", "[DOT]", ".", "(DOT)", ".",
		"[@]", "@", "[at]", "@",
		"[/]", "/",
	)
)

// Refang turns defanged indicators (hxxp://evil[.]com) back into usable form.
func Refang(s string) string {
	s = refanger.Replace(s)
	s = hxxpRe.ReplaceAllString(s, "http$1://")
	return s
}

// Parse detects the type of raw and returns a normalized IOC.
func Parse(raw string) IOC {
	v := strings.TrimSpace(raw)
	v = strings.Trim(v, "\"'<>`,;")
	v = Refang(v)
	i := IOC{Raw: strings.TrimSpace(raw), Value: v, Type: Unknown}
	if v == "" {
		return i
	}

	if hexRe.MatchString(v) {
		switch len(v) {
		case 32:
			i.Type = MD5
		case 40:
			i.Type = SHA1
		case 64:
			i.Type = SHA256
		case 128:
			i.Type = SHA512
		}
		if i.Type != Unknown {
			i.Value = strings.ToLower(v)
			return i
		}
	}

	if a, err := netip.ParseAddr(v); err == nil {
		a = a.Unmap()
		if a.Is4() {
			i.Type = IPv4
		} else {
			i.Type = IPv6
		}
		i.Value = a.String()
		return i
	}

	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil && u.Host != "" {
			switch strings.ToLower(u.Scheme) {
			case "http", "https", "ftp", "ftps", "ws", "wss":
				i.Type = URL
				return i
			}
		}
		return i
	}

	d := strings.ToLower(strings.TrimSuffix(v, "."))
	if domainRe.MatchString(d) {
		i.Type = Domain
		i.Value = d
	}
	return i
}
