# 1. Problem Definition, Scope and Investigation Requirements

## 1.1 Problem statement

Threat intelligence about malicious infrastructure is published openly every day, by
community feeds such as abuse.ch URLhaus and ThreatFox and by phishing feeds such as
OpenPhish. Each feed is a long flat list of indicators (URLs, domains, IP addresses,
hashes) with timestamps and tags. The useful intelligence sits in the *relationships*
that the lists do not show: which indicators share a server, which malware families use
the same hosting provider, when a campaign started and peaked, and where the
infrastructure is concentrated.

Analysts usually piece these relationships together by hand, one indicator at a time.
Visualisation can shorten that work, but every chart form can also mislead:

* a hairball graph suggests links that do not exist,
* a heat map of raw counts mostly shows where hosting is cheap,
* a timeline of *report* dates is easily read as *attack* dates.

**This project designs and builds an OSINT analytics platform that collects open
threat-intelligence data, extracts and correlates its entities, and presents the
evidence through graphs, link charts, timelines and heat maps.** For each technique
the project states which investigative question it is suited to. The platform also
builds in safeguards against misreading the evidence.

## 1.2 Objectives

| # | Objective | Measured by |
|---|-----------|-------------|
| O1 | Collect a multi-source OSINT dataset containing **entities, relationships, timestamps, locations and threat indicators** using only free, public sources | 3 feeds + 3 enrichment sources, raw files hashed in a manifest |
| O2 | Clean, normalise and de-duplicate the data; extract typed entities (URL, host, registered domain, IP, ASN, country, malware family, reporter) | entity/relationship counts, rejected-record log |
| O3 | Correlate entities across sources and build a provenance-labelled knowledge graph | cross-feed overlap, shared-infrastructure clusters |
| O4 | Apply graph analytics (centrality, community detection), temporal analytics (burst detection) and geographic analytics (normalised concentration) | metrics stored per node / day / country |
| O5 | Evaluate the suitability of graphs, link charts, timelines and heat maps for specific investigative questions | suitability matrix (Section 4 of the report) |
| O6 | Implement an interactive dashboard and automated investigation reports | working Flask application, HTML reports, GEXF/CSV export |
| O7 | Reduce the possibility of misinterpreting evidence and show it quantitatively | before/after experiments on hub suppression, normalisation and time semantics |
| O8 | Survey at least 10 research papers and identify research gaps the architecture addresses | literature comparison table |

## 1.3 Investigation questions (drive the choice of visualisation)

| ID | Investigative question | Primary view |
|----|------------------------|--------------|
| IQ1 | Which indicators share infrastructure and probably belong to the same campaign? | Graph (cluster overview) |
| IQ2 | Starting from one suspicious indicator, what else is connected, and on what evidence? | Link chart (ego expansion) |
| IQ3 | When did activity start, peak and stop? Are there bursts? | Timeline |
| IQ4 | Where is the malicious infrastructure hosted? Which countries and providers are over-represented *relative to their size*? | Geographic heat map / choropleth |
| IQ5 | What is the operational tempo (day-of-week × hour reporting pattern)? | Temporal heat map (matrix) |
| IQ6 | Which entities are pivotal brokers between clusters? | Graph analytics (betweenness) |
| IQ7 | How is coverage distributed across the reporting community (social-network view)? | Bipartite reporter–family network |

## 1.4 Scope

**In scope**

* Passive collection from public feeds: URLhaus (malware URLs), ThreatFox (IOCs with malware attribution), OpenPhish (phishing URLs).
* Passive enrichment: DNS resolution, IP geolocation and ASN (ip-api.com), independent ASN/registry-country lookup (Team Cymru IP-to-ASN DNS service), RIR delegation statistics (NRO) for normalisation.
* Free-text entity extraction, so an analyst can paste a report and match its IOCs against the dataset.
* Graph, link-chart, timeline, geographic and temporal heat-map visualisations, an evidence panel, HTML reports and GEXF/CSV export.

**Out of scope**

* Active scanning, port probing, visiting or downloading from malicious URLs.
* Malware execution or reverse engineering.
* Attribution of attacks to real-world people.
* Collection of personal social-media data.
* Takedown or blocking actions.

The platform only analyses infrastructure. Reporter handles appear only as pseudonyms.

## 1.5 Requirements

**Functional**

* **F1** Download each feed reproducibly and record source URL, time, size and SHA-256 hash (chain of custody).
* **F2** Continue the pipeline when any single source or enrichment service fails.
* **F3** Normalise indicators (refang, lower-case, strip ports and paths, validate IPs and domains, convert timestamps to UTC) and de-duplicate them.
* **F4** Extract typed entities and typed relationships. Every edge carries its source feed, record ID, timestamp and confidence.
* **F5** Correlate across feeds and through shared infrastructure, while suppressing multi-tenant "hub" nodes.
* **F6** Compute centrality, communities, bursts and normalised geographic concentration.
* **F7** Provide an interactive dashboard with graph, link chart, timeline and heat-map views, filters and an evidence panel.
* **F8** Generate a shareable investigation report and export the graph for external tools (Gephi).
* **F9** Work fully offline from a committed snapshot, so a reviewer can reproduce every number.

**Non-functional**

* Explainability: every link on screen can be traced to a source record.
* Reproducibility: frozen snapshot plus configuration in one file.
* Resilience to unavailable third-party services.
* Ethical and legal collection only.
* Performance: the full pipeline runs on a laptop in minutes.

**Intended users:** SOC and threat-intelligence analysts who triage malicious infrastructure, and students learning OSINT analysis.
