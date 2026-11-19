# ZUHAN → Logstash → Elasticsearch

*Demo: lookups from the ZUHAN terminal and web UI arriving in Elasticsearch/Kibana.*

https://github.com/user-attachments/assets/8e19f492-a177-4595-9362-37b418290bbd

Send every ZUHAN lookup (terminal and web UI) to Elasticsearch and see it in Kibana:

```
zuhan <ioc> / zuhan web  --POST-->  Logstash http input  -->  zuhan-lookups-*  (every lookup)
                                                          -->  zuhan-ti         (malicious, ECS threat.indicator)
```

Tested with Elasticsearch, Logstash and Kibana 9.5.

## 1. Index template

Load it before the first record arrives, so the fields get the right types (`keyword` for
`zuhan.verdict` / `zuhan.ioc_type`, `ip` for `threat.indicator.ip`, `date` for the timestamps).
Detection rules (especially EQL) need `keyword` fields.

```bash
curl -u elastic:$ES_PASSWORD -X PUT "http://localhost:9200/_index_template/zuhan" \
  -H 'Content-Type: application/json' -d @zuhan-index-template.json
```

On a single-node cluster, add `"number_of_replicas": 0` to `settings` to keep the indices green.

## 2. Logstash pipeline

Copy `logstash/zuhan.conf` into your pipeline folder and add it to `pipelines.yml`:

```yaml
- pipeline.id: zuhan
  path.config: "/usr/share/logstash/pipeline/zuhan.conf"
```

Set `ES_HOSTS`, `ES_USER` and `ES_PASSWORD` for Logstash, publish port `8080`, and restart Logstash.
Check the file first with `bin/logstash --config.test_and_exit -f zuhan.conf`.

The http input accepts requests from anyone who can reach port 8080. Keep it on a trusted network,
or turn on the `user` / `password` lines in the file and put the credentials in the URL
(`http://zuhan:<password>@host:8080`).

## 3. ZUHAN

```bash
export ZUHAN_FORWARD_URL=http://<logstash-host>:8080   # e.g. in ~/.bashrc
zuhan 44d88612fea8a8f36de82e1278abb02f
zuhan web                                              # web UI lookups are sent too
```

Or per run: `zuhan -forward http://<logstash-host>:8080 <ioc>`. If Logstash is unreachable, ZUHAN
prints a warning (a toast in the web UI); the scan result and exit code are not affected, and the
record is not retried.

Each record looks like this in Elasticsearch:

| Field | Example |
|---|---|
| `zuhan.ioc` | `44d88612fea8a8f36de82e1278abb02f` |
| `zuhan.type` | `md5` (md5, sha1, sha256, ipv4, ipv6, domain, url) |
| `zuhan.ioc_type` | `hash` (hash, ip, domain, url) |
| `zuhan.verdict` | `malicious` (malicious, suspicious, clean, not_found, info, ...) |
| `zuhan.flagged` / `zuhan.queried` / `zuhan.confidence` | `2` / `3` / `66` |
| `zuhan.sources` | sources that said malicious |
| `tags` | `zuhan`, `zuhan-cli` or `zuhan-web` |

## 4. Kibana

Create two data views (Stack Management → Data Views):

| Name | Index pattern | Timestamp |
|---|---|---|
| ZUHAN lookups | `zuhan-lookups-*` | `@timestamp` |
| ZUHAN threat intel | `zuhan-ti` | `threat.indicator.last_seen` |

Handy Discover queries: `zuhan.verdict : "malicious"`, `zuhan.ioc : "8.8.8.8"`,
`tags : "zuhan-web"`.

To use the malicious IOCs in Indicator Match rules, add `zuhan-ti` to the Security advanced setting
`securitySolution:defaultThreatIndex`.

## 5. Example detection rules

Custom query (KQL) rules on `zuhan-lookups-*`, one per IOC class:

| Rule | Query |
|---|---|
| ZUHAN: malware hash detected | `zuhan.ioc_type : "hash" and zuhan.verdict : "malicious"` |
| ZUHAN: malicious IP | `zuhan.ioc_type : "ip" and zuhan.verdict : "malicious"` |
| ZUHAN: malicious domain | `zuhan.ioc_type : "domain" and zuhan.verdict : "malicious"` |
| ZUHAN: malicious URL | `zuhan.ioc_type : "url" and zuhan.verdict : "malicious"` |
| ZUHAN: newly reported IOC | `zuhan.verdict : "malicious" and zuhan.new : true` |

Use `zuhan.confidence >= 50` to keep only IOCs flagged by at least half of the sources asked.
