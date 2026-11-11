package extract

import (
	"sort"
	"strings"
	"testing"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/ioc"
)

const dump = `
[sandbox] pid=4412 process=C:\Users\victim\AppData\Local\Temp\invoice.pdf.exe
CreateFileW("C:\\Windows\\System32\\kernel32.dll") -> 0x1a4
LoadLibraryA("ws2_32.dll")
RegSetValueExW(HKCU\Software\Microsoft\Windows\CurrentVersion\Run, "upd", "C:\\ProgramData\\upd.exe")
InternetOpenUrlA(hInternet, "hxxp://update-check[.]xyz/gate.php?id=42", ...)
getaddrinfo("cdn.Bad-Domain.top") -> 185.220.101[.]1
connect(socket=0x2c, ip=192.168.1.10, port=445)
connect(socket=0x30, ip=45.9.148.114, port=443)
WinHttpConnect(server="2a03:2880:f12f:83:face:b00c::25de", port=443)
send(buf="GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\n")
dropped: md5=44D88612FEA8A8F36DE82E1278ABB02F sha256=5d9dc8c9a900fb171c33d36e9edf6b384762a17a380bfab97001779d8b0957e4
zero: 00000000000000000000000000000000
os.version=10.0.19041.1  build 6.1.7601.17514
script: C:\tools\collect.py and README.md and run.sh
json: {"url":"https:\/\/evil.example.ru\/payload.bin","ipv6":"fe80::1","ts":"12:30:45"}
mail from: attacker@phish-login.com, mirror ftp://files.badhost.cn/a.zip.
`

func values(r Result, t ioc.Type) []string {
	var out []string
	for _, i := range r.IOCs {
		if i.Type == t {
			out = append(out, i.Value)
		}
	}
	sort.Strings(out)
	return out
}

func eq(t *testing.T, name string, got, want []string) {
	t.Helper()
	sort.Strings(want)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("%s:\n got  %v\n want %v", name, got, want)
	}
}

func TestFromText(t *testing.T) {
	r := FromText(dump, Options{})
	eq(t, "md5", values(r, ioc.MD5), []string{"44d88612fea8a8f36de82e1278abb02f"})
	eq(t, "sha256", values(r, ioc.SHA256), []string{"5d9dc8c9a900fb171c33d36e9edf6b384762a17a380bfab97001779d8b0957e4"})
	eq(t, "url", values(r, ioc.URL), []string{
		"http://update-check.xyz/gate.php?id=42",
		"https://evil.example.ru/payload.bin",
		"ftp://files.badhost.cn/a.zip",
	})
	eq(t, "domain", values(r, ioc.Domain), []string{
		"update-check.xyz", "cdn.bad-domain.top", "evil.example.ru", "phish-login.com", "files.badhost.cn",
	})
	eq(t, "ipv4", values(r, ioc.IPv4), []string{"185.220.101.1", "45.9.148.114"})
	eq(t, "ipv6", values(r, ioc.IPv6), []string{"2a03:2880:f12f:83:face:b00c:0:25de"})
}

func TestOptions(t *testing.T) {
	r := FromText(dump, Options{KeepPrivate: true, Types: []ioc.Type{ioc.IPv4, ioc.IPv6}})
	eq(t, "ipv4 private", values(r, ioc.IPv4), []string{"185.220.101.1", "45.9.148.114", "192.168.1.10", "127.0.0.1"})
	eq(t, "ipv6 private", values(r, ioc.IPv6), []string{"2a03:2880:f12f:83:face:b00c:0:25de", "fe80::1"})
	if len(values(r, ioc.Domain)) != 0 {
		t.Error("type filter ignored")
	}
	r = FromText(dump, Options{Max: 3})
	if len(r.IOCs) != 3 || r.Truncated == 0 {
		t.Errorf("max: %d iocs, truncated %d", len(r.IOCs), r.Truncated)
	}
}
