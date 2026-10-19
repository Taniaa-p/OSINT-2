# Visualization-Based OSINT Intelligence Platform

An OSINT analytics platform that collects open threat-intelligence data, extracts and
correlates its entities, and supports investigations through **graphs, link charts,
timelines and heat maps**. Each view includes safeguards that reduce the chance of
misinterpreting the evidence.

**Report:** [`docs/OSINT_Visualization_Platform_Report.pdf`](docs/OSINT_Visualization_Platform_Report.pdf) (also `.docx`)

## What it does

1. **Collects** three public feeds: abuse.ch URLhaus (malware URLs), ThreatFox (IOCs with
   malware attribution) and OpenPhish (phishing URLs). Every file is recorded with a
   SHA-256 chain-of-custody manifest.
2. **Cleans and normalises** the records: refang, parse, validate, UTC timestamps, time
   window, de-duplication.
3. **Extracts entities** (URL, host, domain, IP, hash, malware family, pseudonymised
   reporter) and provenance-labelled relationships. It can also extract IOCs from
   pasted free text.
4. **Enriches** passively: DNS, ip-api geolocation/ASN, Team Cymru ASN and registry
   country (an independent cross-check), and NRO RIR IPv4 statistics for normalisation.
5. **Correlates and analyses:**
   * knowledge graph with hub suppression (GitHub, CDNs and the like are not used as links)
   * campaign clusters
   * centrality and Louvain communities
   * burst detection
   * normalised geographic concentration
   * reporter social network
   * cross-source agreement
6. **Visualises and reports:**
   * Flask dashboard with graph, link chart, timeline, geographic and temporal heat
     maps, social-network view and an evidence panel
   * defanged HTML reports
   * GEXF/CSV export

| Snapshot result (19 Oct 2026) | Value |
|---|---|
| Entities / relationships | 50,391 / 145,463 |
| Largest "campaign" without → with hub suppression | 13,580 → 368 entities |
| ASN agreement ip-api vs Team Cymru | 98.7 % |
| Geolocated country = registry country | 76.0 % |
| Top-10 countries kept after IPv4 normalisation | 3 / 10 |

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Reproduce the report exactly from the committed snapshot (no network needed):
OFFLINE=1 python main.py run-all
python main.py serve            # open http://127.0.0.1:5000

# Or collect fresh data from the live feeds (~10 min, because of ip-api rate limits):
python main.py run-all
```

No API keys are needed.

| Command | Phase |
|---|---|
| `python main.py check` | connectivity check |
| `python main.py collect [--freeze]` | download feeds (and freeze them as the snapshot) |
| `python main.py process` | normalise and extract entities |
| `python main.py enrich` | DNS / geo / ASN enrichment, then rebuild the graph |
| `python main.py analyze` | correlation and analytics → `data/processed/*.json` |
| `python main.py report` | HTML reports → `reports/` |
| `python main.py serve` | dashboard |
| `pytest` | unit tests |
| `python scripts/make_figures.py` | report figures |
| `bash scripts/screenshots.sh` | dashboard screenshots |
| `python scripts/build_report.py` | Word report |
| `python scripts/docx_to_pdf.py` | PDF of the report |

## Repository layout

```
main.py                    CLI entry point
config/settings.py         all sources, limits and thresholds
src/acquisition/           feed download, manifest, snapshot, parsers, RIR stats
src/preprocessing/         normalisation and cleaning
src/extraction/            entity / relationship extraction, free-text IOC extraction
src/enrichment/            DNS, ip-api, Team Cymru
src/storage/               SQLite schema and access
src/correlation/           knowledge graph, hub suppression, clusters, cross-feed
src/analytics/             graph, temporal, geographic, SNA analytics and experiments
src/web/                   Flask dashboard (Cytoscape.js, Plotly, Leaflet)
src/reporting/             HTML reports, GEXF / CSV export
tests/                     pytest suite
scripts/                   figures, screenshots, report builder
data/snapshot/             frozen, hash-verified dataset + enrichment cache
docs/                      problem definition, report, figures, screenshots
```

## Ethics

* Passive collection only. No indicator is ever visited, scanned or downloaded.
* Reporter handles are pseudonymised, and no personal data is collected.
* The snapshot is gzip-compressed and reports are defanged, so malicious URLs are never clickable.
* Free services are used within their documented limits, for academic, non-commercial purposes.
* Results are triage aids and should be verified by an analyst.

See Section 9 of the report.
