# Visualization-Based OSINT Intelligence Platform

An OSINT analytics platform that collects open threat-intelligence data (URLhaus,
ThreatFox, OpenPhish), extracts and correlates entities (URLs, hosts, domains, IPs,
ASNs, countries, malware families, reporters), and supports investigations through
**graphs, link charts, timelines and heat maps**. Each view has safeguards that reduce
the chance of misinterpreting the evidence.

> Status: Phase 1 – project foundation. See `docs/01_problem_definition.md` for the
> problem, scope, objectives and requirements.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python main.py check
```
