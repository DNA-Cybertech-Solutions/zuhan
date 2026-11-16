package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

// hostOf returns the host an IOC points at: the domain itself, or a URL's
// host. ok=false for hashes.
func hostOf(i ioc.IOC) (host string, isIP bool, ok bool) {
	switch i.Type {
	case ioc.Domain:
		return i.Value, false, true
	case ioc.IPv4, ioc.IPv6:
		return i.Value, true, true
	case ioc.URL:
		u, err := url.Parse(i.Value)
		if err != nil || u.Hostname() == "" {
			return "", false, false
		}
		h := strings.ToLower(u.Hostname())
		_, err = netip.ParseAddr(h)
		return h, err == nil, true
	}
	return "", false, false
}

// ---------------- live DNS (opt-in) ----------------

// Resolver is the subset of *net.Resolver the DNS source uses.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// DNS resolves domains (A/AAAA, CNAME, MX, NS) and IPs (PTR) live through
// this machine's resolver. It is opt-in: a lookup can reach a name server
// the attacker runs and tell them someone is looking.
type DNS struct {
	Resolver Resolver // nil = net.DefaultResolver
}

func (s *DNS) ID() string        { return "dns" }
func (s *DNS) Name() string      { return "DNS (live)" }
func (s *DNS) RequiresKey() bool { return false }
func (s *DNS) Configured() bool  { return true }
func (s *DNS) OptIn() bool       { return true }
func (s *DNS) Supports(t ioc.Type) bool {
	return typeIn(t, ioc.Domain, ioc.URL, ioc.IPv4, ioc.IPv6)
}

func (s *DNS) Query(ctx context.Context, i ioc.IOC) Result {
	r := Result{Source: s.Name(), Status: StatusInfo}
	res := s.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	host, isIP, ok := hostOf(i)
	if !ok {
		r.Status = StatusSkipped
		return r
	}
	if isIP {
		names, err := res.LookupAddr(ctx, host)
		if err != nil || len(names) == 0 {
			r.Summary = "no reverse DNS (PTR) record"
			return r
		}
		for k := range names {
			names[k] = strings.TrimSuffix(names[k], ".")
		}
		r.addList("PTR", names, 5)
		r.Score = "PTR"
		r.Summary = "reverse DNS: " + strings.Join(uniq(names), ", ")
		return r
	}

	addrs, err := res.LookupIPAddr(ctx, host)
	var de *net.DNSError
	if errors.As(err, &de) && de.IsNotFound {
		r.Summary = "does not resolve (NXDOMAIN)"
		r.Context = "Does not resolve"
		r.Score = "NXDOMAIN"
		return r
	}
	if err != nil {
		return fail(r, err)
	}
	var ips []string
	private := false
	for _, a := range addrs {
		ips = append(ips, a.IP.String())
		if a.IP.IsPrivate() || a.IP.IsLoopback() || a.IP.IsUnspecified() {
			private = true
		}
	}
	sort.Strings(ips)
	r.addList("A/AAAA", ips, 12)
	if c, err := res.LookupCNAME(ctx, host); err == nil {
		if c = strings.TrimSuffix(c, "."); c != "" && !strings.EqualFold(c, host) {
			r.add("CNAME", c)
		}
	}
	if mx, err := res.LookupMX(ctx, host); err == nil {
		var v []string
		for _, m := range mx {
			v = append(v, strings.TrimSuffix(m.Host, "."))
		}
		r.addList("MX", v, 6)
	}
	if ns, err := res.LookupNS(ctx, host); err == nil {
		var v []string
		for _, n := range ns {
			v = append(v, strings.TrimSuffix(n.Host, "."))
		}
		r.addList("NS", v, 6)
	}
	r.Score = fmt.Sprintf("%d IPs", len(ips))
	r.Summary = "resolves to " + strings.Join(firstN(ips, 4), ", ")
	if len(ips) > 4 {
		r.Summary += fmt.Sprintf(" (+%d)", len(ips)-4)
	}
	if private {
		r.Context = "Resolves to a private/loopback address"
		r.Summary += " · private/loopback address"
	}
	return r
}

func firstN(v []string, n int) []string {
	if len(v) > n {
		return v[:n]
	}
	return v
}

// ---------------- passive DNS (mnemonic) ----------------

// PassiveDNS queries mnemonic's free passive DNS service: which IPs a
// domain resolved to over time, or which domains pointed at an IP.
// The key (Argus API key) is optional.
type PassiveDNS struct {
	Key     string
	BaseURL string
}

func (s *PassiveDNS) ID() string        { return "pdns" }
func (s *PassiveDNS) Name() string      { return "Passive DNS" }
func (s *PassiveDNS) RequiresKey() bool { return false }
func (s *PassiveDNS) Configured() bool  { return true }
func (s *PassiveDNS) Supports(t ioc.Type) bool {
	return typeIn(t, ioc.Domain, ioc.URL, ioc.IPv4, ioc.IPv6)
}

func (s *PassiveDNS) Query(ctx context.Context, i ioc.IOC) Result {
	r := Result{Source: s.Name()}
	host, isIP, ok := hostOf(i)
	if !ok {
		r.Status = StatusSkipped
		return r
	}
	r.Link = "https://passivedns.mnemonic.no/search/" + url.PathEscape(host)
	var resp struct {
		Count int `json:"count"`
		Data  []struct {
			Query  string `json:"query"`
			Answer string `json:"answer"`
			RRType string `json:"rrtype"`
			First  int64  `json:"firstSeenTimestamp"`
			Last   int64  `json:"lastSeenTimestamp"`
		} `json:"data"`
	}
	u := orDefault(s.BaseURL, "https://api.mnemonic.no") + "/pdns/v3/" + url.PathEscape(host) + "?limit=100"
	code, err := getJSON(ctx, u, map[string]string{"Argus-API-Key": s.Key}, &resp)
	if err != nil {
		return fail(r, err)
	}
	if code == 404 || len(resp.Data) == 0 {
		r.Status = StatusNotFound
		r.Summary = "no passive DNS records"
		return r
	}
	r.Status = StatusInfo
	sort.Slice(resp.Data, func(a, b int) bool { return resp.Data[a].Last > resp.Data[b].Last })
	var first, last int64
	var addrs, names, cnames []string
	day := func(ms int64) string { return time.UnixMilli(ms).UTC().Format("2006-01-02") }
	for _, d := range resp.Data {
		if d.First > 0 && (first == 0 || d.First < first) {
			first = d.First
		}
		if d.Last > last {
			last = d.Last
		}
		span := fmt.Sprintf("%s (%s → %s)", "%s", day(d.First), day(d.Last))
		switch strings.ToLower(d.RRType) {
		case "a", "aaaa":
			if isIP {
				names = append(names, fmt.Sprintf(span, strings.TrimSuffix(d.Query, ".")))
			} else {
				addrs = append(addrs, fmt.Sprintf(span, d.Answer))
			}
		case "cname":
			cnames = append(cnames, fmt.Sprintf(span, strings.TrimSuffix(d.Answer, ".")))
		}
	}
	n := resp.Count
	if n < len(resp.Data) {
		n = len(resp.Data)
	}
	r.Score = fmt.Sprintf("%d records", n)
	if isIP {
		r.addList("Domains seen on this IP", names, 12)
	} else {
		r.addList("Resolved to", addrs, 12)
		r.addList("CNAME", cnames, 6)
	}
	if first > 0 {
		r.add("First observed", day(first))
		r.add("Last observed", day(last))
	}
	what := "IPs"
	count := len(uniqPrefix(addrs))
	if isIP {
		what, count = "domains", len(uniqPrefix(names))
	}
	r.Summary = fmt.Sprintf("%d %s seen", count, what)
	if first > 0 {
		r.Summary += fmt.Sprintf(" · %s → %s", day(first), day(last))
	}
	return r
}

// uniqPrefix counts distinct values of "value (span)" strings.
func uniqPrefix(v []string) []string {
	var out []string
	for _, s := range v {
		out = append(out, strings.SplitN(s, " (", 2)[0])
	}
	return uniq(out)
}

// ---------------- RDAP / WHOIS ----------------

// RDAP fetches registration data (the modern WHOIS) through rdap.org's
// bootstrap service: registrar, creation and expiry dates for domains;
// network name, owner and range for IPs. Domains registered less than
// NewDays ago are flagged suspicious.
type RDAP struct {
	BaseURL string
	NewDays int // default 30
	Now     func() time.Time
}

func (s *RDAP) ID() string        { return "rdap" }
func (s *RDAP) Name() string      { return "RDAP/WHOIS" }
func (s *RDAP) RequiresKey() bool { return false }
func (s *RDAP) Configured() bool  { return true }
func (s *RDAP) Supports(t ioc.Type) bool {
	return typeIn(t, ioc.Domain, ioc.URL, ioc.IPv4, ioc.IPv6)
}

type rdapEntity struct {
	Roles    []string        `json:"roles"`
	VCard    json.RawMessage `json:"vcardArray"`
	Entities []rdapEntity    `json:"entities"`
}

func (e rdapEntity) fn() string {
	var v []json.RawMessage
	if json.Unmarshal(e.VCard, &v) != nil || len(v) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if json.Unmarshal(v[1], &props) != nil {
		return ""
	}
	for _, p := range props {
		var name string
		if len(p) >= 4 && json.Unmarshal(p[0], &name) == nil && name == "fn" {
			var val string
			if json.Unmarshal(p[3], &val) == nil {
				return val
			}
		}
	}
	return ""
}

func findRole(es []rdapEntity, role string) string {
	for _, e := range es {
		for _, r := range e.Roles {
			if r == role {
				if n := e.fn(); n != "" {
					return n
				}
			}
		}
		if n := findRole(e.Entities, role); n != "" {
			return n
		}
	}
	return ""
}

type rdapResp struct {
	LDHName      string       `json:"ldhName"`
	Handle       string       `json:"handle"`
	Name         string       `json:"name"`
	Country      string       `json:"country"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	Status       []string     `json:"status"`
	Entities     []rdapEntity `json:"entities"`
	Events       []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
}

func (s *RDAP) Query(ctx context.Context, i ioc.IOC) Result {
	r := Result{Source: s.Name()}
	host, isIP, ok := hostOf(i)
	if !ok {
		r.Status = StatusSkipped
		return r
	}
	base := orDefault(s.BaseURL, "https://rdap.org")
	headers := map[string]string{"Accept": "application/rdap+json, application/json"}
	var resp rdapResp

	if isIP {
		u := base + "/ip/" + host
		r.Link = u
		code, err := getJSON(ctx, u, headers, &resp)
		if err != nil {
			return fail(r, err)
		}
		if code == 404 {
			r.Status = StatusNotFound
			r.Summary = "no RDAP record"
			return r
		}
		r.Status = StatusInfo
		org := findRole(resp.Entities, "registrant")
		if org == "" {
			org = findRole(resp.Entities, "administrative")
		}
		r.add("Network", strings.Trim(resp.Name+" ("+resp.Handle+")", " ()"))
		r.add("Owner", org)
		r.add("Country", resp.Country)
		if resp.StartAddress != "" {
			r.add("Range", resp.StartAddress+" – "+resp.EndAddress)
		}
		r.add("Abuse contact", findRole(resp.Entities, "abuse"))
		r.Score = resp.Country
		r.Summary = strings.Trim(strings.Join([]string{resp.Name, org, resp.Country}, " · "), " ·")
		return r
	}

	// domains: walk up from the full name until the registry answers
	name := host
	var code int
	var err error
	for tries := 0; tries < 4; tries++ {
		r.Link = base + "/domain/" + name
		resp = rdapResp{}
		code, err = getJSON(ctx, r.Link, headers, &resp)
		if err != nil || code != 404 || strings.Count(name, ".") < 2 {
			break
		}
		name = name[strings.IndexByte(name, '.')+1:]
	}
	if err != nil {
		return fail(r, err)
	}
	if code == 404 {
		r.Status = StatusNotFound
		r.Summary = "no RDAP record (the TLD may not offer RDAP)"
		return r
	}

	var created, expires, changed string
	for _, e := range resp.Events {
		switch e.Action {
		case "registration":
			created = e.Date
		case "expiration":
			expires = e.Date
		case "last changed":
			changed = e.Date
		}
	}
	var ns []string
	for _, n := range resp.Nameservers {
		ns = append(ns, strings.ToLower(n.LDHName))
	}
	registrar := findRole(resp.Entities, "registrar")
	r.add("Domain", strings.ToLower(resp.LDHName))
	r.add("Registrar", registrar)
	r.add("Registered", created)
	r.add("Expires", expires)
	r.add("Last changed", changed)
	r.addList("Status", resp.Status, 6)
	r.addList("Name servers", ns, 6)

	r.Status = StatusInfo
	sum := []string{}
	if t, ok := parseTime(created); ok {
		now := time.Now()
		if s.Now != nil {
			now = s.Now()
		}
		age := int(now.Sub(t).Hours() / 24)
		limit := s.NewDays
		if limit <= 0 {
			limit = 30
		}
		r.add("Age", fmt.Sprintf("%d days", age))
		r.Score = fmt.Sprintf("%d days old", age)
		if age >= 0 && age < limit {
			r.Status = StatusSuspicious
			r.Context = fmt.Sprintf("Newly registered domain (%d days)", age)
			sum = append(sum, fmt.Sprintf("newly registered: %d days ago", age))
		} else {
			sum = append(sum, "registered "+t.Format("2006-01-02"))
		}
	}
	if registrar != "" {
		sum = append(sum, registrar)
	}
	r.Summary = strings.Join(sum, " · ")
	return r
}
