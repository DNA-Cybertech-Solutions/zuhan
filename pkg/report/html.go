package report

import (
	"html/template"
	"io"

	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/engine"
	"github.com/DNA-Cybertech-Solutions/zuhan/pkg/sources"
)

var htmlTmpl = template.Must(template.New("r").Funcs(template.FuncMap{
	"cls":     func(s sources.Status) string { return s.String() },
	"label":   func(s sources.Status) string { return s.Label() },
	"localdb": localDBText,
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZUHAN IOC Report</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mut:#6b7385;--line:#e3e6ec;
--mal:#c62828;--sus:#b26a00;--cln:#2e7d32;--inf:#0277bd;--nf:#7a8190;--err:#8e24aa}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1a1e26;--fg:#e6e9ef;--mut:#9aa3b5;--line:#2a303b;
--mal:#ef5350;--sus:#ffb74d;--cln:#66bb6a;--inf:#4fc3f7;--nf:#8a92a3;--err:#ce93d8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 16px 60px}
h1{font-size:22px;margin:0 0 4px}.sub{color:var(--mut);margin:0 0 22px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:26px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.stat b{display:block;font-size:24px}.stat span{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;margin-bottom:18px;overflow:hidden}
.head{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid var(--line)}
.ioc{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;word-break:break-all}
.meta{color:var(--mut);font-size:12px;margin-top:2px}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.04em;border:1px solid currentColor;white-space:nowrap}
.malicious{color:var(--mal)}.suspicious{color:var(--sus)}.clean{color:var(--cln)}.info{color:var(--inf)}
.not_found,.skipped{color:var(--nf)}.error{color:var(--err)}
.big{font-size:13px;padding:4px 12px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 16px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em;font-weight:600}
tr:last-child td{border-bottom:0}
td.src{font-weight:600;white-space:nowrap}td.score{font-family:ui-monospace,Menlo,Consolas,monospace;white-space:nowrap}
a{color:var(--inf)}details{margin-top:4px}summary{cursor:pointer;color:var(--mut);font-size:12px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;margin:6px 0 0;font-size:12px}
dt{color:var(--mut)}dd{margin:0;word-break:break-word}
.tablewrap{overflow-x:auto}
footer{color:var(--mut);font-size:12px;margin-top:30px}
</style>
</head>
<body><main>
<h1>ZUHAN IOC Report</h1>
<p class="sub">Generated {{.Generated.Format "2006-01-02 15:04:05 MST"}} · ZUHAN {{.Version}}</p>
<div class="stats">
<div class="stat"><b>{{.Stats.Total}}</b><span>IOCs</span></div>
<div class="stat malicious"><b>{{.Stats.Malicious}}</b><span>Malicious</span></div>
<div class="stat suspicious"><b>{{.Stats.Suspicious}}</b><span>Suspicious</span></div>
<div class="stat clean"><b>{{.Stats.Clean}}</b><span>Clean</span></div>
<div class="stat not_found"><b>{{.Stats.NotFound}}</b><span>Not found</span></div>
</div>
{{range .Reports}}
<section class="card">
<div class="head">
<div><div class="ioc">{{.IOC.Value}}</div>
<div class="meta">{{.IOC.Type}}{{if ne .IOC.Raw .IOC.Value}} · input: {{.IOC.Raw}}{{end}}{{range $k, $v := .IOC.Meta}} · {{$k}}: {{$v}}{{end}}</div></div>
<div><span class="badge big {{cls .Verdict}}">{{label .Verdict}}</span> <span class="meta">{{.Flagged}}/{{.Queried}} sources flagged</span>{{if .LocalDB}}<div class="meta info">{{localdb .LocalDB}}</div>{{end}}</div>
</div>
<div class="tablewrap"><table>
<thead><tr><th>Source</th><th>Status</th><th>Score</th><th>Details</th></tr></thead>
<tbody>
{{range .Results}}
<tr>
<td class="src">{{if .Link}}<a href="{{.Link}}" target="_blank" rel="noopener noreferrer">{{.Source}}</a>{{else}}{{.Source}}{{end}}</td>
<td><span class="badge {{cls .Status}}">{{label .Status}}</span></td>
<td class="score">{{.Score}}</td>
<td>{{if .Error}}<span class="error">{{.Error}}</span>{{else}}{{.Summary}}{{end}}
{{if .Fields}}<details><summary>{{len .Fields}} fields</summary><dl>{{range .Fields}}<dt>{{.Key}}</dt><dd>{{.Value}}</dd>{{end}}</dl></details>{{end}}
</td>
</tr>
{{end}}
</tbody></table></div>
</section>
{{end}}
<footer>Verdicts are aggregated from third-party sources; always validate before blocking or attributing.</footer>
</main></body></html>
`))

func writeHTML(w io.Writer, reps []engine.Report, opt Options) error {
	return htmlTmpl.Execute(w, map[string]any{
		"Reports":   reps,
		"Stats":     Summarize(reps),
		"Generated": opt.Generated,
		"Version":   opt.Version,
	})
}
