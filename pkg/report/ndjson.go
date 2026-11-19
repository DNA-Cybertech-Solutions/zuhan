package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/engine"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
)

// NDJSONRecord is one flat line of the ndjson format: one IOC per line, so
// log shippers (Filebeat, Logstash, jq) can read it without knowing ZUHAN's
// nested report structure. The same record is sent by the forwarder.
type NDJSONRecord struct {
	Tool       string     `json:"tool"`
	Version    string     `json:"version,omitempty"`
	TS         time.Time  `json:"ts"`         // when the IOC was looked up (UTC)
	IOC        string     `json:"ioc"`        // normalized value
	Type       string     `json:"type"`       // md5, sha1, sha256, ipv4, ipv6, domain, url
	IOCType    string     `json:"ioc_type"`   // hash, ip, domain, url (coarse class for rules)
	Verdict    string     `json:"verdict"`    // malicious, suspicious, clean, not_found, ...
	Flagged    int        `json:"flagged"`    // sources that flagged it
	Queried    int        `json:"queried"`    // sources that were asked
	Confidence int        `json:"confidence"` // flagged / queried, 0-100
	Sources    []string   `json:"sources"`    // names of the sources that said malicious
	Reference  string     `json:"reference,omitempty"`
	FirstSeen  *time.Time `json:"first_seen,omitempty"`
	New        bool       `json:"new,omitempty"`
	Unknown    bool       `json:"unknown,omitempty"`
	Benign     []string   `json:"benign,omitempty"`
	Context    []string   `json:"context,omitempty"`
	Techniques []string   `json:"techniques,omitempty"` // MITRE ATT&CK IDs
}

// IOCCategory groups the detailed IOC types into the four classes detection
// rules usually care about: hash, ip, domain, url ("" for anything else).
func IOCCategory(t ioc.Type) string {
	switch t {
	case ioc.MD5, ioc.SHA1, ioc.SHA256, ioc.SHA512:
		return "hash"
	case ioc.IPv4, ioc.IPv6:
		return "ip"
	case ioc.Domain:
		return "domain"
	case ioc.URL:
		return "url"
	}
	return ""
}

// NDJSONRecords flattens scan reports into one record per IOC. Every IOC is
// included, whatever its verdict.
func NDJSONRecords(reps []engine.Report, opt Options) []NDJSONRecord {
	out := make([]NDJSONRecord, 0, len(reps))
	for _, rep := range reps {
		rec := NDJSONRecord{
			Tool:      "zuhan",
			Version:   opt.Version,
			TS:        rep.QueriedAt.UTC().Truncate(time.Second),
			IOC:       rep.IOC.Value,
			Type:      string(rep.IOC.Type),
			IOCType:   IOCCategory(rep.IOC.Type),
			Verdict:   rep.Verdict.String(),
			Flagged:   rep.Flagged,
			Queried:   rep.Queried,
			Sources:   []string{},
			FirstSeen: rep.FirstSeen,
			New:       rep.New,
			Unknown:   rep.Unknown,
			Benign:    rep.Benign,
			Context:   rep.Context,
		}
		if rec.TS.IsZero() {
			rec.TS = opt.Generated.UTC().Truncate(time.Second)
		}
		if rep.Queried > 0 {
			rec.Confidence = rep.Flagged * 100 / rep.Queried
			if rec.Confidence > 100 {
				rec.Confidence = 100
			}
		}
		for _, r := range rep.Results {
			if r.Status == sources.StatusMalicious {
				rec.Sources = append(rec.Sources, r.Source)
				if rec.Reference == "" {
					rec.Reference = r.Link
				}
			}
		}
		for _, h := range rep.Attack {
			rec.Techniques = append(rec.Techniques, h.ID)
		}
		out = append(out, rec)
	}
	return out
}

// writeNDJSON writes one compact JSON object per line (newline-delimited
// JSON). Every IOC is written, whatever its verdict; filter on "verdict"
// downstream if only malicious ones are wanted.
func writeNDJSON(w io.Writer, reps []engine.Report, opt Options) error {
	enc := json.NewEncoder(w) // Encode ends each value with "\n"
	enc.SetEscapeHTML(false)
	for _, rec := range NDJSONRecords(reps, opt) {
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}
