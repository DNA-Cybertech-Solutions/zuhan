// Package forward sends scan results to an HTTP collector, for example a
// Logstash http input, so every lookup can be indexed in Elasticsearch.
//
// Each request body is a JSON array; every element wraps one ndjson record:
//
//	[{"zuhan": {"ioc": "...", "ioc_type": "hash", "verdict": "malicious", ...},
//	  "tags": ["zuhan", "zuhan-cli"]}]
//
// Logstash's json codec turns every array element into its own event.
package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/report"
)

// EnvVar is the environment variable holding the collector URL.
const EnvVar = "ZUHAN_FORWARD_URL"

// Timeout bounds one forward request.
const Timeout = 10 * time.Second

// Envelope is one forwarded record.
type Envelope struct {
	Zuhan report.NDJSONRecord `json:"zuhan"`
	Tags  []string            `json:"tags"`
}

// Validate checks that raw is an absolute http(s) URL.
func Validate(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("forward URL must look like http://host:port/ (got %q)", raw)
	}
	return nil
}

// Send posts the records to target. channel says where the lookup came from
// ("cli", "web") and becomes the tag "zuhan-<channel>". Nothing is sent when
// there are no records.
func Send(ctx context.Context, client *http.Client, target string, recs []report.NDJSONRecord, channel string) error {
	if len(recs) == 0 {
		return nil
	}
	if err := Validate(target); err != nil {
		return err
	}
	tags := []string{"zuhan"}
	if channel != "" {
		tags = append(tags, "zuhan-"+channel)
	}
	body := make([]Envelope, len(recs))
	for i, r := range recs {
		body[i] = Envelope{Zuhan: r, Tags: tags}
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	if client == nil {
		client = &http.Client{Timeout: Timeout}
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not send results to %s: %w", target, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s answered %s", target, resp.Status)
	}
	return nil
}
