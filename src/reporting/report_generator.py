"""Shareable HTML investigation reports (Jinja2). Indicators are defanged so the
report can be e-mailed without creating clickable malicious links."""
import json
from datetime import datetime, timezone

from jinja2 import Template

from config import settings
from src.preprocessing.normalizer import defang
from src.storage import database

CLUSTER_TMPL = Template("""<!doctype html><html><head><meta charset="utf-8"><title>Cluster {{ c.id }} report</title>
<style>body{font:14px/1.5 -apple-system,Segoe UI,sans-serif;max-width:960px;margin:30px auto;padding:0 16px;color:#1d2330}
h1{margin-bottom:0}.sub{color:#667}table{border-collapse:collapse;width:100%;margin:8px 0}td,th{border-bottom:1px solid #dde;padding:5px 8px;text-align:left;vertical-align:top}
th{background:#f4f6fa}.note{background:#fff7e0;border-left:4px solid #e0a800;padding:8px 12px;margin:12px 0}code{word-break:break-all;font-size:12px}</style></head><body>
<h1>Infrastructure cluster {{ c.id }}</h1><div class="sub">Generated {{ now }} · Visualization-Based OSINT Intelligence Platform</div>
<h2>Summary</h2><table>
<tr><th>Indicators</th><td>{{ c.indicators }} ({{ c.size }} entities incl. hosts / domains / IPs)</td></tr>
<tr><th>Malware families</th><td>{% for f, n in c.families.items() %}{{ f }} ({{ n }}){% if not loop.last %}, {% endif %}{% else %}unattributed{% endfor %}</td></tr>
<tr><th>Family purity</th><td>{{ c.purity if c.purity is not none else 'n/a' }}</td></tr>
<tr><th>Active (reported)</th><td>{{ c.first_seen }} → {{ c.last_seen }}</td></tr>
<tr><th>Hosting countries (geolocated)</th><td>{{ c.countries or 'n/a' }}</td></tr>
<tr><th>ASNs</th><td>{{ c.asns or 'n/a' }}</td></tr>
<tr><th>Reporting feeds</th><td>{{ c.sources }}</td></tr>
<tr><th>Confidence</th><td>{{ confidence }}</td></tr></table>
<div class="note">Cluster membership means the indicators share a host, registered domain or IP address in the source data or DNS resolution. Shared-platform hubs were excluded. It does not prove a single operator, and geolocation shows server location, not attacker location.</div>
<h2>Entities ({{ ents|length }})</h2><table><tr><th>Type</th><th>Value (defanged)</th><th>Feeds</th><th>First seen</th></tr>
{% for e in ents %}<tr><td>{{ e.type }}</td><td><code>{{ e.defanged }}</code></td><td>{{ e.sources }}</td><td>{{ e.first_seen or '' }}</td></tr>{% endfor %}</table>
<h2>Evidence trail ({{ edges|length }} relationships)</h2><table><tr><th>From</th><th>Relation</th><th>To</th><th>Source / method</th><th>Record</th></tr>
{% for x in edges %}<tr><td><code>{{ x.src }}</code></td><td>{{ x.rel }}</td><td><code>{{ x.dst }}</code></td><td>{{ x.source }} / {{ x.method }}</td><td>{{ x.record_id or '' }}</td></tr>{% endfor %}</table>
</body></html>""")

SUMMARY_TMPL = Template("""<!doctype html><html><head><meta charset="utf-8"><title>Investigation summary</title>
<style>body{font:14px/1.5 -apple-system,Segoe UI,sans-serif;max-width:960px;margin:30px auto;padding:0 16px;color:#1d2330}
table{border-collapse:collapse;width:100%;margin:8px 0}td,th{border-bottom:1px solid #dde;padding:5px 8px;text-align:left}th{background:#f4f6fa}</style></head><body>
<h1>Investigation summary report</h1><p>Generated {{ now }}. Dataset collected {{ manifest.collected_at }}.</p>
<h2>Sources and chain of custody</h2><table><tr><th>Source</th><th>Retrieved</th><th>Bytes</th><th>SHA-256</th></tr>
{% for n, e in manifest.sources.items() %}<tr><td>{{ n }}</td><td>{{ e.retrieved_at }}</td><td>{{ e.bytes }}</td><td><code>{{ e.sha256 }}</code></td></tr>{% endfor %}</table>
<h2>Knowledge graph</h2><table>{% for k, v in s.graph.by_type.items() %}<tr><td>{{ k }}</td><td>{{ v }}</td></tr>{% endfor %}</table>
<h2>Hub suppression (misinterpretation safeguard)</h2><table><tr><th></th><th>Without</th><th>With</th></tr>
{% for k in s.experiment_hub_suppression.with %}<tr><td>{{ k }}</td><td>{{ s.experiment_hub_suppression.without[k] }}</td><td>{{ s.experiment_hub_suppression.with[k] }}</td></tr>{% endfor %}</table>
<h2>Cross-source validation</h2><pre>{{ agreement }}</pre>
<h2>Top clusters</h2><table><tr><th>ID</th><th>Families</th><th>Indicators</th><th>Countries</th><th>Period</th></tr>
{% for c in s.clusters_top %}<tr><td>{{ c.id }}</td><td>{{ c.families }}</td><td>{{ c.indicators }}</td><td>{{ c.countries }}</td><td>{{ (c.first_seen or '')[:10] }} → {{ (c.last_seen or '')[:10] }}</td></tr>{% endfor %}</table>
</body></html>""")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def render_cluster_report(cid: str):
    clusters = json.loads((settings.PROCESSED_DIR / "clusters.json").read_text())
    c = next((x for x in clusters if x["id"] == cid), None)
    if not c:
        return None
    nodes = set(c["nodes"])
    with database.connect() as con:
        ents, edges = [], []
        for n in c["nodes"]:
            e = dict(con.execute("SELECT type, value, sources, first_seen FROM entities WHERE id=?", (n,)).fetchone())
            e["defanged"] = defang(e["value"])
            ents.append(e)
            for x in con.execute("SELECT * FROM edges WHERE src=?", (n,)):
                if x["dst"] in nodes or x["rel"] in ("associated_with", "in_asn", "located_in"):
                    edges.append({**dict(x), "src": defang(x["src"]), "dst": defang(x["dst"])})
    n_src = len(c["sources"])
    confidence = ("High: corroborated by several feeds" if n_src > 1 else
                  "Medium: single feed, linked by shared infrastructure" if c["indicators"] >= 5 else
                  "Low: small single-feed cluster")
    html = CLUSTER_TMPL.render(c=c, ents=ents, edges=edges[:500], now=_now(), confidence=confidence)
    settings.REPORTS_DIR.mkdir(exist_ok=True)
    (settings.REPORTS_DIR / f"cluster_{cid}.html").write_text(html)
    return html


def render_summary_report():
    s = json.loads((settings.PROCESSED_DIR / "summary.json").read_text())
    manifest = json.loads((settings.RAW_DIR / "manifest.json").read_text())
    html = SUMMARY_TMPL.render(s=s, manifest=manifest, now=_now(),
                               agreement=json.dumps(s["enrichment_agreement"], indent=2))
    settings.REPORTS_DIR.mkdir(exist_ok=True)
    (settings.REPORTS_DIR / "summary_report.html").write_text(html)
    return html
