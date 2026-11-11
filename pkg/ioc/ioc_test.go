package ioc

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in, want string
		typ      Type
	}{
		{"44D88612FEA8A8F36DE82E1278ABB02F", "44d88612fea8a8f36de82e1278abb02f", MD5},
		{"3395856ce81f2b7382dee72602f798b642f14140", "3395856ce81f2b7382dee72602f798b642f14140", SHA1},
		{"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", SHA256},
		{"8.8.8.8", "8.8.8.8", IPv4},
		{"1.2.3[.]4", "1.2.3.4", IPv4},
		{"::ffff:1.2.3.4", "1.2.3.4", IPv4},
		{"2001:4860:4860::8888", "2001:4860:4860::8888", IPv6},
		{"Evil-Domain[.]com", "evil-domain.com", Domain},
		{"sub.example.co.uk.", "sub.example.co.uk", Domain},
		{"hxxp://bad[.]site/payload.exe", "http://bad.site/payload.exe", URL},
		{"hXXps[:]//bad.site/x", "https://bad.site/x", URL},
		{"https://example.com/a?b=c", "https://example.com/a?b=c", URL},
		{"not an ioc", "not an ioc", Unknown},
		{"abc123", "abc123", Unknown},
		{"", "", Unknown},
	}
	for _, c := range cases {
		got := Parse(c.in)
		if got.Type != c.typ || got.Value != c.want {
			t.Errorf("Parse(%q) = (%q, %s), want (%q, %s)", c.in, got.Value, got.Type, c.want, c.typ)
		}
	}
}
