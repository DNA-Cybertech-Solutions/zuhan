package forward

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/report"
)

func TestSendPostsEnvelopes(t *testing.T) {
	var got []map[string]any
	var ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctype = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Errorf("body is not a JSON array: %v: %s", err, b)
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	recs := []report.NDJSONRecord{
		{Tool: "zuhan", IOC: "44d88612fea8a8f36de82e1278abb02f", Type: "md5", IOCType: "hash", Verdict: "malicious"},
		{Tool: "zuhan", IOC: "8.8.8.8", Type: "ipv4", IOCType: "ip", Verdict: "clean"},
	}
	if err := Send(context.Background(), nil, srv.URL, recs, "cli"); err != nil {
		t.Fatal(err)
	}
	if ctype != "application/json" {
		t.Errorf("Content-Type = %q", ctype)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 envelopes, got %d", len(got))
	}
	z := got[0]["zuhan"].(map[string]any)
	if z["ioc_type"] != "hash" || z["verdict"] != "malicious" {
		t.Errorf("first record = %v", z)
	}
	tags := got[1]["tags"].([]any)
	if len(tags) != 2 || tags[0] != "zuhan" || tags[1] != "zuhan-cli" {
		t.Errorf("tags = %v", tags)
	}
}

func TestSendNothingToSend(t *testing.T) {
	if err := Send(context.Background(), nil, "http://127.0.0.1:1/", nil, "cli"); err != nil {
		t.Fatalf("empty input must not try to connect: %v", err)
	}
}

func TestSendHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	err := Send(context.Background(), nil, srv.URL, []report.NDJSONRecord{{IOC: "x"}}, "web")
	if err == nil {
		t.Fatal("want an error for a 503 answer")
	}
}

func TestValidate(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:8080", "https://logs.example:8443/zuhan"} {
		if err := Validate(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "127.0.0.1:8080", "ftp://x", "http://", "file:///etc/passwd"} {
		if Validate(bad) == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
