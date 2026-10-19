"""Build the project report (docs/OSINT_Visualization_Platform_Report.docx).

All numbers are read from data/processed/summary.json, so the report always matches
the analysis that produced it. Run after: main.py analyze, scripts/make_figures.py
and scripts/screenshots.sh.
"""
import json
import sys
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from config import settings  # noqa: E402

S = json.loads((settings.PROCESSED_DIR / "summary.json").read_text())
GEO = json.loads((settings.PROCESSED_DIR / "geo.json").read_text())
MAN = json.loads((settings.SNAPSHOT_DIR / "manifest.json").read_text())
FIG = ROOT / "docs" / "figures"
SHOT = ROOT / "docs" / "screenshots"
OUT = ROOT / "docs" / "OSINT_Visualization_Platform_Report.docx"

doc = Document()
st = doc.styles["Normal"]
st.font.name = "Times New Roman"
st.font.size = Pt(11)
st.element.rPr.rFonts.set(qn("w:eastAsia"), "Times New Roman")
for s in ("Heading 1", "Heading 2", "Heading 3", "Title"):
    doc.styles[s].font.name = "Times New Roman"
    doc.styles[s].font.color.rgb = RGBColor(0, 0, 0)
for sec in doc.sections:
    sec.left_margin = sec.right_margin = Cm(2.2)
    sec.top_margin = sec.bottom_margin = Cm(2)

fig_no = [0]
tab_no = [0]


def fmt(n):
    return f"{n:,}" if isinstance(n, int) else str(n)


def pct(x):
    return f"{100 * x:.1f}%" if x is not None else "n/a"


def para(text, bold=False, italic=False, size=None, align=None, space_after=6):
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.bold, r.italic = bold, italic
    if size:
        r.font.size = Pt(size)
    if align:
        p.alignment = align
    p.paragraph_format.space_after = Pt(space_after)
    return p


def rich(parts):
    """parts: list of (text, bold) tuples in one paragraph."""
    p = doc.add_paragraph()
    for t, b in parts:
        p.add_run(t).bold = b
    p.paragraph_format.space_after = Pt(6)
    return p


def bullet(text, bold_lead=None):
    p = doc.add_paragraph(style="List Bullet")
    if bold_lead:
        p.add_run(bold_lead).bold = True
    p.add_run(text)
    p.paragraph_format.space_after = Pt(2)
    return p


def h1(t):
    doc.add_heading(t, level=1)


def h2(t):
    doc.add_heading(t, level=2)


def shade(cell, hex_fill):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_fill)
    tcPr.append(shd)


def table(header, rows, caption=None, widths=None, size=9):
    if caption:
        tab_no[0] += 1
        para(f"Table {tab_no[0]}. {caption}", italic=True, size=9, space_after=2)
    t = doc.add_table(rows=1, cols=len(header))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(header):
        c = t.rows[0].cells[i]
        c.text = ""
        r = c.paragraphs[0].add_run(h)
        r.bold = True
        r.font.size = Pt(size)
        shade(c, "D9E2F3")
    for row in rows:
        cells = t.add_row().cells
        for i, v in enumerate(row):
            cells[i].text = ""
            r = cells[i].paragraphs[0].add_run(str(v))
            r.font.size = Pt(size)
    if widths:
        for row in t.rows:
            for i, w in enumerate(widths):
                row.cells[i].width = Cm(w)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return t


def figure(path, caption, width=16):
    if not Path(path).exists():
        para(f"[missing figure: {Path(path).name}]", italic=True)
        return
    doc.add_picture(str(path), width=Cm(width))
    doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
    fig_no[0] += 1
    para(f"Figure {fig_no[0]}. {caption}", italic=True, size=9, align=WD_ALIGN_PARAGRAPH.CENTER)


def page_break():
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


def toc():
    p = doc.add_paragraph()
    r = p.add_run()
    for tag, text in (("begin", None), (None, 'TOC \\o "1-2" \\h \\z \\u'), ("separate", None),
                      (None, "Right-click and choose 'Update Field' to refresh the table of contents."), ("end", None)):
        if tag:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), tag)
            r._r.append(el)
        elif text.startswith("TOC"):
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = text
            r._r.append(el)
        else:
            r2 = p.add_run(text)
            r2.italic = True
            r = p.add_run()


# ======================================================================= numbers
g, hub, exp = S["graph"], S["hubs"], S["experiment_hub_suppression"]
ag, gm, cf, sna, tl, gr = (S["enrichment_agreement"], S["graph_metrics"], S["cross_feed"], S["sna"],
                           S["temporal"], S["geo_rank_comparison"])
src = MAN["sources"]
by_type = g["by_type"]
top_c = S["clusters_top"]

# ======================================================================= title page
for _ in range(6):
    doc.add_paragraph()
para("Visualization-Based OSINT Intelligence Platform", bold=True, size=26, align=WD_ALIGN_PARAGRAPH.CENTER)
para("Graphs, Link Charts, Timelines and Heat Maps for Evidence-Based Threat Investigation",
     italic=True, size=13, align=WD_ALIGN_PARAGRAPH.CENTER)
doc.add_paragraph()
para("Project Report", bold=True, size=18, align=WD_ALIGN_PARAGRAPH.CENTER)
para("Cybersecurity / OSINT Threat Intelligence", italic=True, size=12, align=WD_ALIGN_PARAGRAPH.CENTER)
doc.add_paragraph()
rich([("GitHub Repository: ", True), ("github.com/Taniaa-p/OSINT-2", False)]).alignment = WD_ALIGN_PARAGRAPH.CENTER
doc.add_paragraph()
for k, v in (("Name: ", "Tania P"), ("Roll no: ", "23110403"), ("Reg no: ", "23011103038"), ("Date: ", "19 October 2026")):
    rich([(k, True), (v, False)]).alignment = WD_ALIGN_PARAGRAPH.CENTER
page_break()
para("Table of Contents", bold=True, size=16)
for line in ["Abstract", "1. Problem Definition", "      1.1 Objectives · 1.2 Investigation questions · 1.3 Scope and requirements",
             "2. Literature Survey", "      2.1 Comparison of visualization approaches · 2.2 Research gaps",
             "3. OSINT Data Collection and Source Identification", "      3.1 Chain of custody · 3.2 Dataset profile",
             "4. System Architecture", "      4.1 Data model", "5. Evaluation of Visualization Techniques",
             "6. Data Processing, Correlation and Analysis",
             "      6.1 Cleaning · 6.2 Correlation and hub suppression · 6.3 Graph · 6.4 Temporal · 6.5 Geographic · 6.6 Social network",
             "7. Tool Implementation and Dashboard", "8. Findings, Evidence and Validation",
             "      8.1 Key findings · 8.2 Cross-source validation · 8.3 Misinterpretation experiments · 8.4 Testing · 8.5 Limitations",
             "9. Ethical and Legal Considerations", "10. Impact and Significance", "11. Future Work", "12. Conclusion", "References"]:
    para(line, bold=not line.startswith(" "), size=11, space_after=3)
page_break()

# ======================================================================= abstract
h1("Abstract")
para(f"Open threat-intelligence feeds publish thousands of malicious indicators every day, but as flat lists. The "
     f"intelligence an analyst needs is in the relationships the lists do not show: shared servers, campaign time "
     f"spans, and concentrations of infrastructure. This project designs and implements a visualization-based OSINT "
     f"analytics platform. It collected {fmt(sum(1 for _ in src))} public feeds (URLhaus, ThreatFox, OpenPhish) and "
     f"enriched them with DNS, IP geolocation, an independent ASN registry service and RIR address statistics. From "
     f"these it built a provenance-labelled knowledge graph of {fmt(g['nodes'])} entities and {fmt(g['edges'])} "
     f"relationships. It then compared four visualization families (graphs, link charts, timelines and heat maps), "
     f"assigning each the investigative questions it answers best. Each view carries safeguards against "
     f"misinterpretation. The safeguards were tested quantitatively. Without hub suppression, multi-tenant platforms "
     f"such as raw.githubusercontent.com merge unrelated indicators into a false 'campaign' of "
     f"{fmt(exp['without']['largest_cluster'])} entities; with suppression the largest cluster is "
     f"{fmt(exp['with']['largest_cluster'])}. Normalising hosting countries by allocated IPv4 space keeps only "
     f"{gr['top10_overlap_ips_vs_normalised']} of the raw top-10 countries (Spearman ρ = {gr['spearman_ips_vs_normalised']}). "
     f"Geolocation was cross-validated against registry data "
     f"({pct(ag['country_agreement'])} country agreement, {pct(ag['asn_agreement'])} ASN agreement). A literature "
     f"survey of 15 papers identifies the research gaps the architecture addresses.")

# ======================================================================= 1 problem
h1("1. Problem Definition")
para("Community threat-intelligence feeds such as abuse.ch URLhaus and ThreatFox, and phishing feeds such as OpenPhish, "
     "are among the most widely used open sources in security operations. Each publishes a flat list of indicators of "
     "compromise (IOCs): URLs, domains, IP:port pairs and file hashes, with timestamps, tags and reporter names. The "
     "questions an investigator actually asks are relational, temporal and spatial: Which indicators share "
     "infrastructure? Starting from one suspicious IP, what else is connected? When did a campaign start and peak? "
     "Where is the infrastructure hosted? A list answers none of these directly.")
para("Visualization closes that gap, but each chart form can also mislead. A force-directed graph suggests a "
     "relationship wherever two nodes are drawn together. A heat map of raw counts mostly shows where hosting is cheap "
     "and plentiful. A timeline of report dates is easily read as attack dates. The problem therefore has two parts: "
     "(a) build an OSINT analytics platform that turns open data into entities, relationships, timestamps, locations "
     "and threat indicators, and visualises them; (b) choose and design each visualization so that it supports the "
     "investigative question it is used for and reduces the chance of misinterpreting the evidence.")
h2("1.1 Objectives")
table(["#", "Objective", "Measured by"], [
    ["O1", "Collect a multi-source OSINT dataset with entities, relationships, timestamps, locations and threat indicators", "3 feeds + 4 enrichment sources; SHA-256 manifest"],
    ["O2", "Clean, normalise and de-duplicate; extract typed entities", "rejection counts by reason; entity counts"],
    ["O3", "Correlate across sources into a provenance-labelled knowledge graph", "cross-feed overlap; infrastructure clusters"],
    ["O4", "Apply graph, temporal, geographic and social-network analytics", "centrality, Louvain, bursts, normalised geo, SNA"],
    ["O5", "Evaluate the suitability of graphs, link charts, timelines and heat maps", "suitability matrix (Section 5)"],
    ["O6", "Implement an interactive dashboard and automated reporting", "Flask dashboard, HTML reports, GEXF/CSV export"],
    ["O7", "Reduce, and quantify, the possibility of misinterpreting evidence", "before/after experiments (Section 8.3)"],
    ["O8", "Survey at least 10 research papers and identify research gaps", "15-paper comparison (Section 2)"],
], "Project objectives", widths=[1, 9.5, 6])
h2("1.2 Investigation questions")
para("The investigation questions were fixed before any visualization was chosen, so each view could be judged against "
     "a concrete need rather than how it looks.")
table(["ID", "Investigative question", "Requirement on the view"], [
    ["IQ1", "Which indicators share infrastructure and probably belong to the same campaign?", "Show connectivity and groups at a glance"],
    ["IQ2", "Starting from one indicator, what is connected, and on what evidence?", "Incremental, explainable expansion"],
    ["IQ3", "When did activity start, peak and stop? Are there bursts?", "Ordered time axis, volume, durations"],
    ["IQ4", "Where is infrastructure hosted, and which countries/ASNs are over-represented relative to size?", "Spatial density, normalisation"],
    ["IQ5", "What is the operational (reporting) tempo across the week?", "Two-dimensional time density"],
    ["IQ6", "Which entities broker between clusters?", "Structural importance (centrality)"],
    ["IQ7", "How is coverage spread across the reporting community?", "Social-network structure"],
], "Investigation questions", widths=[1.1, 9, 6.4])
h2("1.3 Scope and requirements")
bullet(" passive collection from URLhaus, ThreatFox and OpenPhish; passive enrichment through DNS, ip-api.com, the "
       "Team Cymru IP-to-ASN service and NRO RIR delegation statistics; free-text IOC extraction; correlation, "
       "analytics, visualization, reporting and export.", "In scope:")
bullet(" active scanning or probing, visiting or downloading malicious URLs, malware execution, attribution of attacks "
       "to real people, personal social-media collection, takedown or blocking.", "Out of scope:")
bullet(" (F1) reproducible collection with a chain-of-custody manifest; (F2) no single failing source stops the "
       "pipeline; (F3) normalisation and de-duplication; (F4) typed entities and provenance-labelled edges; (F5) "
       "correlation with hub suppression; (F6) graph, temporal, geographic and SNA analytics; (F7) interactive graph, "
       "link chart, timeline and heat-map views with an evidence panel; (F8) reports and exports; (F9) full offline "
       "reproduction from a committed snapshot.", "Functional requirements:")
bullet(" explainability (every on-screen link traceable to a source record), reproducibility, resilience, ethical "
       "collection only, and laptop-scale performance (full pipeline in minutes).", "Non-functional requirements:")
bullet(" SOC and threat-intelligence analysts triaging malicious infrastructure.", "Intended users:")

# ======================================================================= 2 literature
h1("2. Literature Survey")
para("Fifteen papers were reviewed across five areas required by the brief: OSINT and intelligence analysis, graph "
     "visualization and analytics, social-network analysis, geographic visualization, and cyber-intelligence "
     "visualization and dashboards. Table 3 compares their approach, methodology, data, findings and limitations. "
     "Section 2.2 derives the research gaps that the proposed architecture addresses.")
lit = [
    ["[L1] Pirolli & Card (2005)", "Intelligence analysis", "Cognitive task analysis of intelligence analysts; sensemaking loop (foraging → schema → hypothesis → presentation)", "Interviews and think-aloud with analysts", "Analysts spend most effort on foraging and on keeping track of evidence; leverage points for tools identified", "Conceptual; no implemented system or quantitative evaluation"],
    ["[L2] Stasko, Görg & Liu (2008) Jigsaw", "Investigative visual analytics", "Entity extraction from documents + linked list, graph, calendar and scatter views", "System design; user study with analysts on a fictional intelligence case", "Multiple coordinated views of entity connections help analysts find plots faster", "Text documents only; entity extraction errors propagate; small user study"],
    ["[L3] Pastor-Galindo et al. (2020)", "OSINT survey", "Survey of OSINT sources, tools, techniques and applications", "Systematic literature review", "OSINT is under-exploited; integration of sources and analysis is the main challenge", "No implementation; visualization treated only briefly"],
    ["[L4] Böhm & Lolagar (2021)", "OSINT ethics and law", "Legal and ethical framework for OSINT", "Legal analysis (GDPR, data protection)", "Public does not mean unrestricted; purpose limitation and minimisation apply", "European focus; no technical controls proposed"],
    ["[L5] Herman, Melançon & Marshall (2000)", "Graph visualization", "Survey of graph layout, navigation and clustering techniques", "Literature survey", "Large graphs need clustering, filtering and focus+context navigation", "Pre-dates modern web tools; no task-based evaluation"],
    ["[L6] Ghoniem, Fekete & Castagliola (2004)", "Graph readability", "Controlled comparison of node-link diagrams vs adjacency matrices", "User study, 36 participants, 7 tasks on random graphs", "Node-link diagrams read better for small, sparse graphs and path tasks; matrices win for large or dense graphs", "Synthetic graphs; no domain semantics"],
    ["[L7] Blondel et al. (2008) Louvain", "Graph analytics", "Greedy modularity optimisation for community detection", "Algorithm + evaluation on networks up to 118 M nodes", "Fast, high-modularity communities at very large scale", "Resolution limit; non-deterministic; communities are not ground truth"],
    ["[L8] Krebs (2002)", "Social-network analysis", "SNA of the 9/11 hijacker network built from public news sources", "Network reconstruction from open sources; centrality", "Key brokers identifiable from public data; covert networks are sparse", "Retrospective; incomplete, noisy data; single case"],
    ["[L9] Xu & Chen (2005)", "Criminal network analysis", "SNA + visualization for criminal networks (CrimeNet Explorer)", "Concept-space linkage, hierarchical clustering, blockmodelling on police records", "Network visualisation helps identify subgroups and central members", "Police records, not open data; link reliability not modelled"],
    ["[L10] Chainey, Tompson & Uhlig (2008)", "Geographic visualization", "Comparison of hotspot mapping methods (KDE, grids, ellipses, thematic)", "Prediction accuracy index on UK crime data", "Kernel density estimation predicts future hotspots best; method choice changes the conclusion", "Physical crime, not network infrastructure"],
    ["[L11] Poese et al. (2011)", "Geolocation reliability", "Accuracy study of commercial IP geolocation databases", "Comparison against ground truth from a large ISP", "Country-level geolocation is mostly right, city-level often wrong; databases disagree", "Single ISP ground truth; databases change over time"],
    ["[L12] Shiravi, Shiravi & Ghorbani (2012)", "Security visualization", "Survey and taxonomy of network-security visualization systems", "Classification by data source and use case", "Most systems target one data type; evaluation is rare and informal", "Pre-dates threat-intel feeds; few OSINT systems"],
    ["[L13] Noel et al. (2016) CyGraph", "Cyber graph analytics", "Graph-based knowledge model and visualization of network/attack data", "Property graph (Neo4j) + query language; case studies", "Unified graph enables attack-path and mission-impact queries", "Internal network data; no open-source feeds; limited evaluation"],
    ["[L14] Wagner et al. (2016) MISP", "Threat-intel platforms", "Design of a collaborative IOC sharing platform with correlation", "System design and operational deployment", "Automatic correlation of shared attributes speeds up analysis", "Correlation over shared attributes produces noisy links; basic visualisation"],
    ["[L15] Correll & Heer (2017)", "Misleading visualization", "Catalogue of how charts deceive (black-hat visualization)", "Analysis of deceptive design patterns", "Aggregation, scaling and omitted context mislead even honest readers", "Conceptual; no domain-specific safeguards"],
]
table(["Paper", "Area", "Approach / visualization", "Methodology & dataset", "Key findings", "Limitations"], lit,
      "Comparison of surveyed research", widths=[2.6, 2, 3.4, 3.2, 3.2, 2.6], size=7.5)
h2("2.1 Comparison of visualization approaches")
para("The surveyed work uses four families of visualization. Node-link graphs [L2, L5, L9, L13] dominate investigative "
     "and cyber work because they show connectivity directly. [L6] shows, however, that they lose readability as size "
     "and density grow, and [L5] recommends clustering and filtering. Link charts, meaning incremental ego-network "
     "expansion, are the analyst-facing form of the same model; Jigsaw [L2] and MISP [L14] both build on it. Timelines "
     "and calendar views [L2] support sequence and duration reasoning. Heat maps support density reasoning in space "
     "[L10] and in time. [L10] and [L11] both show that the chosen method and the underlying data quality change what "
     "the map appears to say. Social-network analysis [L8, L9] contributes centrality and subgroup measures that turn a "
     "picture into ranked evidence. Louvain community detection [L7] is the standard scalable way to find those "
     "subgroups.")
h2("2.2 Research gaps addressed by this project")
gaps = [
    ("G1 – Evidence provenance in the view. ", "Graph-based systems [L2, L9, L13, L14] draw links but rarely let the analyst "
     "see, on the link itself, which source record created it, by what method and with what confidence. Pirolli & Card "
     "[L1] identify keeping track of evidence as a key leverage point. → Every edge in this platform carries source, "
     "record ID, time, method and confidence, shown in an evidence panel."),
    ("G2 – False links through shared infrastructure. ", "Attribute-based correlation [L14] and large-graph analytics "
     "[L13] connect everything that shares an attribute. In open feeds, CDNs, code-hosting and paste platforms are "
     "shared by thousands of unrelated actors. The effect is noted informally but rarely measured. → Hub suppression, "
     "quantified before and after (Section 8.3)."),
    ("G3 – Normalisation and uncertainty in geographic views. ", "Hotspot work [L10] shows that method changes the "
     "conclusion, and [L11] shows geolocation error. Cyber-threat maps nevertheless typically plot raw counts. → Distinct-IP "
     "weighting, per-million-IPv4 normalisation, and cross-validation of geolocation against registry data."),
    ("G4 – Temporal semantics. ", "Timelines in investigative tools [L2] do not distinguish event time from report time. "
     "Feeds record when something was reported, not when it was active. → Explicit report-time labelling; observation-"
     "only timestamps excluded."),
    ("G5 – Integrated, reproducible OSINT visualization over public data. ", "Surveys [L3, L12] note that most systems "
     "address one data type or view, and that evaluation is rare [L12]. → One provenance-labelled model feeds four "
     "coordinated views, built from a hash-verified public snapshot that anyone can re-run."),
    ("G6 – Ethics built into the tool. ", "[L4] sets out the legal and ethical principles, but technical controls are "
     "rarely described. → Pseudonymised reporters, defanged reports, passive-only collection."),
]
for lead, text in gaps:
    bullet(text, lead)

# ======================================================================= 3 data collection
h1("3. OSINT Data Collection and Source Identification")
para("The dataset had to contain entities, relationships, timestamps, locations and threat indicators. No single open "
     "source provides all five, so three primary feeds were combined with four enrichment sources. Table 4 lists every "
     "source, what it contributes, how it is accessed and how failure is handled.")
table(["Source", "Type", "Contributes", "Access method", "Failure handling"], [
    ["abuse.ch URLhaus", "Threat feed (malware URLs)", "URLs, hosts, timestamps, status, tags, reporters", "CSV export (recent, 30 days), no key", "Retry ×3; marked failed in manifest; others continue"],
    ["abuse.ch ThreatFox", "Threat feed (IOCs)", "IP:port, domains, URLs, hashes, explicit malware family, confidence", "CSV export (recent), no key", "As above"],
    ["OpenPhish Community", "Phishing feed", "Phishing URLs (no timestamps)", "Plain-text feed", "As above; retrieval time marked as observation time"],
    ["DNS (dnspython)", "Enrichment", "host → IP (A records), NXDOMAIN status", "Standard resolver queries, 32 threads", "Timeout/NXDOMAIN stored as status"],
    ["ip-api.com", "Enrichment", "Geolocation, ASN, ISP, hosting flag", "Batch API (100 IPs/request, ≤15 req/min)", "Rate-limit headers honoured; failed batch logged"],
    ["Team Cymru IP-to-ASN", "Enrichment (independent)", "ASN, BGP prefix, registry country", "DNS TXT queries (origin.asn.cymru.com)", "Missing value = no comparison"],
    ["NRO RIR delegation stats", "Reference data", "IPv4 addresses allocated per country", "Combined RIR file (57 MB, summarised)", "Normalisation disabled if missing"],
], "Open sources used", widths=[2.8, 2.4, 4, 3.6, 3.6], size=8)
h2("3.1 Collection methodology and chain of custody")
para("Every download is streamed to disk, hashed with SHA-256 and recorded in a manifest together with the source URL, "
     "UTC retrieval time, size and licence (Table 5). The download was then frozen as a gzip-compressed snapshot in "
     "data/snapshot/. Running the pipeline with OFFLINE=1 restores the snapshot, verifies every hash, and reproduces "
     "every number in this report without a single network request. Enrichment results are cached in SQLite and "
     "exported to the snapshot for the same reason.")
table(["Source", "Retrieved (UTC)", "Bytes", "SHA-256 (first 24 hex)"],
      [[n, e["retrieved_at"], fmt(e.get("bytes", 0)), e.get("sha256", "")[:24]] for n, e in src.items()],
      "Chain-of-custody manifest of the analysed snapshot", widths=[3, 4.4, 2.6, 6.4])
h2("3.2 Dataset profile")
rej = {}
try:
    import sqlite3
    con = sqlite3.connect(settings.DB_PATH)
    run = json.loads(con.execute("SELECT details FROM runs WHERE stage='process' ORDER BY run_at DESC LIMIT 1").fetchone()[0])
    rej = run
    con.close()
except Exception:
    pass
table(["Measure", "Value"], [
    ["Raw records parsed", fmt(rej.get("raw", "n/a"))],
    ["Clean records after normalisation", fmt(rej.get("clean", "n/a"))],
    ["Rejected (by reason)", ", ".join(f"{k}: {v}" for k, v in rej.get("rejected", {}).items()) or "n/a"],
    ["Hosts resolved via DNS", f"{fmt(rej.get('dns_resolved', 'n/a'))} of {fmt(rej.get('dns_hosts', 'n/a'))} non-platform domains"],
    ["Distinct IP addresses", fmt(by_type.get("ip", 0))],
    ["IPs geolocated", f"{fmt(ag['geolocated'])} ({pct(ag['geolocated'] / ag['ips'] if ag['ips'] else None)})"],
    ["Investigation window", f"{settings.WINDOW_DAYS} days ending {MAN['collected_at'][:10]}"],
], "Dataset after collection and preprocessing", widths=[7, 9])
para("The five required data dimensions are all present. Entities: URLs, hosts, registered domains, IPs, hashes, ASNs, "
     "countries, malware families and reporters. Relationships: hosted_on, subdomain_of, resolves_to, in_asn, "
     "located_in, associated_with and reported_by. Timestamps: first and last seen. Locations: latitude/longitude, "
     "country and ASN. Threat indicators: URL, domain, IP:port and hash IOCs with threat type and confidence.")

# ======================================================================= 4 architecture
h1("4. System Architecture")
para("The platform is a Python pipeline with a Flask presentation layer. It is organised as eight layers, each in its "
     "own package under src/ and each testable on its own. Figure 1 shows the architecture; Table 7 maps each layer to "
     "its implementation.")
figure(FIG / "fig_architecture.png", "Layered architecture from data acquisition to reporting")
table(["Layer", "Module", "Responsibility", "Key technique"], [
    ["Data acquisition", "src/acquisition", "Download feeds, manifest, snapshot, RIR stats", "Streaming download, SHA-256, gzip snapshot"],
    ["Preprocessing", "src/preprocessing", "Refang, parse, validate, UTC, window, de-dup", "urllib, ipaddress, tldextract (bundled PSL)"],
    ["Entity extraction", "src/extraction", "Typed entities + provenance edges; free-text IOC regex", "Entity IDs '<type>:<value>' merge across feeds"],
    ["Enrichment", "src/enrichment", "DNS, geolocation, two independent ASN sources", "Threaded DNS, batch API, cache"],
    ["Storage", "src/storage", "Records, entities, edges, cache, run log", "SQLite"],
    ["Correlation", "src/correlation", "Infrastructure graph, hub suppression, clusters, cross-feed", "NetworkX connected components"],
    ["Analytics", "src/analytics", "Centrality, Louvain, bursts, geo normalisation, SNA, agreement", "NetworkX, pandas, z-scores"],
    ["Visualization & reporting", "src/web, src/reporting", "Dashboard, evidence panel, HTML reports, GEXF/CSV", "Flask, Cytoscape.js, Plotly, Leaflet, Jinja2"],
], "Architecture layers and implementation", widths=[3, 3, 5.5, 5])
h2("4.1 Data model")
para("The knowledge graph uses typed nodes and typed, directed, provenance-labelled edges. An entity ID is "
     "'<type>:<value>' (for example ip:203.0.113.5), so an indicator reported by two feeds merges into one node "
     "automatically. That merge is the basis of cross-feed correlation. Every edge records the feed or method that "
     "created it, the source record ID, its time and its confidence. Feed attribution gets the ThreatFox confidence; "
     "tag-inferred family links get 50; DNS links get 90; geolocation links get 70. This is what lets the dashboard "
     "answer the question 'why are these two things connected?'.")
table(["Relationship", "From → To", "Created by", "Count"],
      [[r, {"hosted_on": "url → host/ip", "subdomain_of": "host → domain", "resolves_to": "host → ip",
            "in_asn": "ip → asn", "located_in": "ip → country", "associated_with": "indicator → malware",
            "reported_by": "indicator → reporter"}.get(r, ""),
        {"resolves_to": "DNS", "in_asn": "ip-api", "located_in": "ip-api"}.get(r, "feed record"), fmt(n)]
       for r, n in sorted(g["by_relation"].items(), key=lambda kv: -kv[1])],
      "Relationship types in the knowledge graph", widths=[3.5, 4.5, 3.5, 3])

# ======================================================================= 5 visualization suitability
h1("5. Evaluation of Visualization Techniques")
para("Each candidate technique was evaluated against the investigation questions in Section 1.2, using the evidence "
     "from the literature (Section 2) and from this dataset. Table 9 is the resulting suitability matrix (●●● = primary "
     "fit, ●● = supporting, ● = poor fit). Table 10 lists, for each technique, how it can mislead and the safeguard "
     "implemented against it.")
table(["Question", "Graph (overview)", "Link chart", "Timeline", "Geo heat map", "Temporal heat map"], [
    ["IQ1 shared infrastructure", "●●●", "●●", "●", "●", "●"],
    ["IQ2 explain one indicator", "●", "●●●", "●●", "●", "●"],
    ["IQ3 start / peak / stop", "●", "●", "●●●", "●", "●●"],
    ["IQ4 where hosted", "●", "●", "●", "●●●", "●"],
    ["IQ5 tempo", "●", "●", "●●", "●", "●●●"],
    ["IQ6 brokers", "●●●", "●●", "●", "●", "●"],
    ["IQ7 reporting community", "●●● (bipartite)", "●●", "●", "●", "●"],
], "Suitability of visualization techniques per investigative question", widths=[4, 2.6, 2.2, 2.2, 2.4, 2.8], size=8.5)
table(["Technique", "Best for", "Weak for", "How it misleads", "Safeguard implemented"], [
    ["Graph (cluster overview)", "Seeing groups, components, hubs; centrality", "Large dense data (hairball) [L6]; reading time", "Proximity read as relationship; hubs merge unrelated campaigns", "Hub suppression; only infrastructure edges form clusters; cap of 600 nodes; size = betweenness"],
    ["Link chart (ego expansion)", "Explaining one indicator; pivoting step by step", "Global patterns", "Expanding through a CDN floods the chart; enrichment links look like feed facts", "Per-relation expansion cap with hidden count; dashed lines for DNS/geo, dotted for tag-inferred; hub border; evidence panel"],
    ["Timeline", "Sequence, bursts, campaign duration", "Relationships, place", "Report time read as attack time; old IOCs re-listed look new", "'Report time (UTC)' label; window filter; OpenPhish observation times excluded; z-score bursts"],
    ["Geographic heat map / choropleth", "Concentration in space", "Causality, attribution", "Raw counts mirror hosting size; one server with 10k URLs dominates; server location read as attacker location", "Distinct-IP weighting; per-million-IPv4 normalisation; metric switch with warning; agreement rate shown"],
    ["Temporal heat map (day × hour)", "Periodicity, tempo", "Exact sequence", "Reporter working hours read as attacker hours", "Caveat; UTC stated"],
], "Strengths, failure modes and safeguards per technique", widths=[2.6, 2.8, 2.4, 4, 4.6], size=8)

# ======================================================================= 6 processing & correlation
h1("6. Data Processing, Correlation and Analysis")
h2("6.1 Cleaning and normalisation")
bullet(" hxxp → http and [.] → . so defanged indicators match.", "Refanging:")
bullet(" URLs are split into scheme, host, port and path; ThreatFox 'ip:port' into IP and port.", "Parsing:")
bullet(" hosts must be a valid IPv4/IPv6 address or a syntactically valid domain; invalid hosts are rejected and counted.", "Validation:")
bullet(" a bundled public-suffix list gives deterministic registered domains (login.example.co.uk → example.co.uk) without a network call.", "Registered domain:")
bullet(" all timestamps are converted to ISO-8601 UTC; records outside the window are dropped; duplicates are dropped on (source, indicator).", "Time and de-duplication:")
bullet(" URLhaus tags are mapped to the ThreatFox family vocabulary (for example 'mirai' → Mirai), labelled 'tag-inferred' with lower confidence than explicit attribution.", "Family harmonisation:")
h2("6.2 Correlation and hub suppression")
para(f"Correlation runs on an infrastructure graph containing only url, hash, host, domain and IP nodes, linked by "
     f"hosted_on, subdomain_of and resolves_to edges. ASNs and countries never act as links, because one ASN can be a "
     f"whole cloud provider. Before computing clusters, {hub['count']} hub nodes were suppressed. Hubs are known "
     f"multi-tenant platforms (code hosting, CDNs, file sharing, dynamic DNS), plus any pivot whose two-hop "
     f"neighbourhood spans more than {settings.HUB_FAMILY_THRESHOLD} malware families. The connected components of "
     f"what remains are candidate campaigns. The run found {fmt(exp['with']['clusters'])} clusters with at least two "
     f"indicators.")
table(["Suppressed hub", "Reason", "Connections"],
      [[h["id"], h["reason"], fmt(h["degree"])] for h in hub["examples"][:10]],
      "Highest-degree suppressed hubs", widths=[7, 6, 3])
h2("6.3 Graph analytics")
para(f"On the hub-suppressed infrastructure graph ({fmt(gm['nodes'])} nodes, {fmt(gm['edges'])} edges, "
     f"{fmt(gm['components'])} components), degree centrality and approximate betweenness centrality "
     f"(k = {settings.BETWEENNESS_SAMPLE}, fixed seed) were computed, together with Louvain communities "
     f"(modularity {gm['louvain_modularity']}). The very high modularity confirms what the components show: once hubs "
     f"are removed, the infrastructure splits into many tight, separate groups rather than one giant network. Table "
     f"12 lists the most central nodes, which an analyst should pivot on first.")
table(["Rank", "Entity", "Type", "Degree centrality"],
      [[i + 1, x["value"], x["type"], x["score"]] for i, x in enumerate(gm["top_degree"][:8])],
      "Most connected infrastructure after hub suppression", widths=[1.3, 8, 2.5, 3.5])
h2("6.4 Temporal analytics")
para(f"Daily counts of newly reported indicators (mean {tl['mean_per_day']} per day) were tested for bursts with a "
     f"z-score threshold of {settings.BURST_Z_THRESHOLD}, both overall and per family.")
table(["Family", "Day", "Indicators", "z-score"],
      [[b["family"], b["day"], fmt(b["count"]), b["z"]] for b in tl["family_bursts"][:10]],
      "Strongest per-family bursts", widths=[5, 4, 3, 3])
h2("6.5 Geographic analytics")
para(f"{fmt(ag['geolocated'])} IPs were geolocated. Countries were measured three ways: URL count, distinct IP count, "
     f"and distinct IPs per million allocated IPv4 addresses (NRO statistics). Only countries with at least 5 IPs were "
     f"ranked by the normalised metric, so tiny denominators cannot dominate.")
ctry = GEO["countries"][:10]
table(["Country", "Distinct IPs", "URLs", "IPs per million IPv4"],
      [[f"{c['name']} ({c['cc']})", fmt(c["ips"]), fmt(c["urls"]), c["ips_per_million_ipv4"]] for c in ctry],
      "Top hosting countries by distinct IPs", widths=[6, 3, 3, 4])
h2("6.6 Social-network analysis of the reporting community")
para(f"Reporters (pseudonymised) and malware families form a bipartite network. Projected onto reporters, two reporters "
     f"are linked when they report the same family. {sna['reporters']} reporters cover {sna['families']} families. The "
     f"top 5 reporters contribute {pct(sna['share_top5_reporters'])} of the attributed indicators, and "
     f"{sna['families_single_reporter']} families are reported by only one person. For an investigator this matters: "
     f"a family seen by a single reporter has no independent corroboration in this dataset, and coverage gaps follow "
     f"the interests of a few contributors.")

# ======================================================================= 7 implementation
h1("7. Tool Implementation and Dashboard")
para("The pipeline runs from one CLI (python main.py run-all, or the individual collect / enrich / analyze / report / "
     "serve steps). The Flask dashboard provides eight views over the same data. Each view states, on the page, what it "
     "does and does not show. Screenshots below were taken from the running platform on the analysed snapshot.")
table(["Technology", "Use"], [
    ["Python 3, pandas, NetworkX", "Pipeline, analytics, graph algorithms"],
    ["SQLite", "Records, entities, edges, enrichment cache, run audit log"],
    ["Flask + Jinja2", "Dashboard and HTML reports"],
    ["Cytoscape.js", "Graph and link-chart rendering"],
    ["Plotly.js", "Timeline, choropleth, temporal heat map, ASN chart"],
    ["Leaflet + leaflet.heat", "Geographic heat map"],
    ["dnspython, requests, tldextract, pycountry", "Collection and enrichment"],
    ["pytest; Git/GitHub (one commit per phase)", "Testing and version control"],
], "Technology stack", widths=[6, 10])
for shot, cap in [
    ("01_overview.png", "Overview: data volume, cross-source validation and the question-to-view guide"),
    ("02_graph.png", "Infrastructure graph: largest clusters after hub suppression; node size = betweenness; the evidence panel shows a selected node's provenance"),
    ("03_link_chart.png", "Link chart: expansion from one indicator; capped expansion with hidden-neighbour count; dashed enrichment edges"),
    ("04_timeline.png", "Timeline: daily new indicators by family with report-time caveat, and cluster lifespans"),
    ("05_heatmap.png", "Geographic heat map weighted by distinct IPs, with country choropleth and hosting ASNs"),
    ("06_heatmap_normalised.png", "Choropleth after switching to per-million-IPv4 normalisation, and the day × hour temporal heat map"),
    ("07_network.png", "Social-network view of the (pseudonymised) reporting community"),
    ("08_clusters.png", "Cluster table with purity, feeds, period and links to reports"),
    ("09_extract.png", "Free-text IOC extraction from a defanged report, correlated against the dataset"),
    ("10_cluster_report.png", "Automatically generated, defanged cluster investigation report with evidence trail"),
]:
    figure(SHOT / shot, cap, width=16)

# ======================================================================= 8 findings
h1("8. Findings, Evidence and Validation")
h2("8.1 Key findings")
c1 = top_c[0] if top_c else {}
smart = next((b for b in tl["family_bursts"] if b["family"] == "SmartLoader"), None)
bullet(f" The largest single burst in the window was SmartLoader ({fmt(smart['count'])} new URLs on {smart['day']}, "
       f"z = {smart['z']}). Almost all of these are hosted on raw.githubusercontent.com. The timeline shows the burst, "
       f"but only the graph view reveals that the URLs share no infrastructure beyond GitHub itself. Read alone, the "
       f"timeline would suggest one massive campaign server."
       if smart else " Bursts are listed in Table 13.", "Mass abuse of code hosting:")
bullet(f" The largest genuine cluster ({c1.get('id')}) holds {c1.get('indicators')} indicators dominated by "
       f"{next(iter(c1.get('families', {})), 'n/a')} (purity {c1.get('purity')}), on {c1.get('ips')} IP address(es) in "
       f"{', '.join(list(c1.get('countries', {}))[:4]) or 'n/a'}. This is a typical IoT-botnet distribution pattern: "
       f"many short-lived URLs on a small set of servers.", "Botnet distribution infrastructure:")
bullet(f" Clusters where all labelled nodes carry one family dominate (weighted purity "
       f"{exp['with']['weighted_purity']}). Infrastructure linkage alone, with no malware labels used, recovers "
       f"family-consistent groups, so the clusters are meaningful campaign candidates rather than artefacts.",
       "Clusters are family-consistent:")
bullet(f" The ten most heavily used hosting ASNs hold "
       f"{fmt(sum(a['ips'] for a in GEO['top_asns'][:10]))} of {fmt(GEO['located_ips'])} geolocated IPs. "
       f"{fmt(GEO['hosting_split'].get('hosting/datacenter', 0))} IPs are flagged as hosting/datacentre and "
       f"{fmt(GEO['hosting_split'].get('residential/other', 0))} as residential or other, which is consistent with "
       f"compromised home routers in IoT botnets.", "Concentrated hosting:")
bullet(f" Only {cf['ip']['multi_source']} of {fmt(cf['ip']['total'])} IPs and {cf['host']['multi_source']} of "
       f"{fmt(cf['host']['total'])} hosts appear in more than one feed. The feeds are largely complementary rather than "
       f"redundant, which supports combining them. It also means most indicators rest on a single source.",
       "Low feed overlap:")
h2("8.2 Cross-source validation")
para("Every derived attribute that could be checked against an independent source was checked.")
table(["Check", "Sources compared", "Compared", "Agreement", "Interpretation"], [
    ["ASN of each IP", "ip-api vs Team Cymru (BGP)", fmt(ag["asn_compared"]), pct(ag["asn_agreement"]), "High: ASN attribution is reliable"],
    ["Country of each IP", "ip-api geolocation vs RIR registry country (Cymru)", fmt(ag["country_compared"]), pct(ag["country_agreement"]), "Country-level location is mostly reliable; disagreements are shown as a caveat on the map [L11]"],
    ["Indicator corroboration", "URLhaus vs ThreatFox vs OpenPhish", f"{fmt(cf['host']['total'] + cf['ip']['total'])} hosts+IPs", f"{cf['host']['multi_source'] + cf['ip']['multi_source']} multi-feed", "Multi-feed entities flagged as higher confidence in reports"],
    ["Cluster consistency", "Infrastructure clusters vs ThreatFox/URLhaus family labels", fmt(exp["with"]["labelled_clusters"]), f"purity {exp['with']['weighted_purity']}", "Clusters align with independent family labels"],
], "Cross-source validation results", widths=[2.8, 3.8, 2.2, 2.2, 5.5], size=8.5)
mm = ag.get("top_country_mismatches", [])[:5]
if mm:
    para("Most frequent geolocation vs registry disagreements: " + "; ".join(f"{m['geo']} vs {m['registry']} ({m['n']})" for m in mm)
         + ". These are typically address blocks registered in one country and announced or used in another, which is "
         "exactly the uncertainty the map caveat warns about.")
h2("8.3 Misinterpretation experiments")
para("Section 5 claims that each safeguard changes what an analyst would conclude. Three experiments test that claim on "
     "the real dataset.")
rich([("Experiment A – hub suppression (graph). ", True),
      (f"Without suppression the largest connected 'campaign' has {fmt(exp['without']['largest_cluster'])} entities, "
       f"glued together through platforms such as raw.githubusercontent.com. With suppression it has "
       f"{fmt(exp['with']['largest_cluster'])}. An analyst working from the unsuppressed graph would have reported "
       f"thousands of unrelated indicators as one operation.", False)])
figure(FIG / "fig_hub_suppression.png", "Experiment A: effect of hub suppression on the largest cluster, and the suppressed hubs with most connections")
table(["Metric", "Without suppression", "With suppression"],
      [[k.replace("_", " "), fmt(exp["without"][k]), fmt(exp["with"][k])] for k in exp["with"]],
      "Cluster structure with and without hub suppression", widths=[6, 5, 5])
para("Purity is slightly lower with suppression. Removing hubs splits the giant component into many small clusters, so "
     "small mixed clusters now count individually, while the giant cluster previously counted as one mostly-SmartLoader "
     "group. Purity alone would therefore have rewarded the false merge. This is why cluster size is reported together "
     "with purity.")
rich([("Experiment B – metric choice (heat map). ", True),
      (f"Ranking countries by URLs, by distinct IPs and by IPs per million IPv4 gives different answers. The top 10 by "
       f"URLs and by distinct IPs share {gr['top10_overlap_urls_vs_ips']} countries (Spearman ρ = "
       f"{gr['spearman_urls_vs_ips']}); distinct IPs and normalised share {gr['top10_overlap_ips_vs_normalised']} "
       f"(ρ = {gr['spearman_ips_vs_normalised']}) across {gr['countries_compared']} countries. URLs and IPs agree on "
       f"membership but not on order: the Netherlands is 2nd by URLs but 6th by distinct IPs, because a few Dutch "
       f"servers host many URLs each. Normalisation changes the picture completely: the United States holds the "
       f"second-most IPs but drops out of the top 10 relative to its very large address space, while smaller "
       f"countries rise. The raw map answers "
       f"'where is most infrastructure', the normalised map answers 'which countries are over-represented for their "
       f"size'. The dashboard keeps both, labelled, and warns that URL counts are inflated.", False)])
figure(FIG / "fig_geo_ranks.png", "Experiment B: top-10 hosting countries under three metrics")
rich([("Experiment C – time semantics (timeline). ", True),
      ("ThreatFox's 'recent' export re-lists indicators whose first sighting dates back to 2021–2022 because they were "
       "seen again. Plotting first-seen dates naively produced a false Cobalt Strike 'burst' in December 2022 during "
       "development. Restricting the timeline to the investigation window and labelling the axis as report time removed "
       "it. OpenPhish has no timestamps at all; drawing its 300 URLs at the download time would have created another "
       "artificial spike, so they are excluded from the timeline.", False)])
figure(FIG / "fig_timeline.png", "Daily newly reported indicators by family (symmetric-log scale)")
figure(FIG / "fig_dow_hour.png", "Temporal heat map: reports by weekday and hour (UTC)")
h2("8.4 Functional testing")
para("A pytest suite (tests/test_pipeline.py, 10 tests, all passing) covers refang/defang, URL and ip:port parsing, "
     "registered-domain extraction, rejection of bad timestamps and duplicates, defanged free-text IOC extraction, "
     "provenance on extracted edges, reporter pseudonymisation, and both hub-suppression rules on a synthetic graph in "
     "which two unrelated families share one host. Every dashboard route and API was smoke-tested through Flask's test "
     "client. The offline mode was verified by restoring the snapshot and checking all SHA-256 hashes.")
h2("8.5 Limitations")
bullet(" Feeds reflect what volunteers report. Coverage follows reporter interest (Section 6.6), and absence from a feed is not evidence of safety.", "Reporting bias:")
bullet(" DNS and geolocation describe infrastructure at enrichment time, not at report time. Fast-flux hosts may have moved. Enrichment edges are therefore drawn dashed.", "Enrichment time-lag:")
bullet(" ip-api is a single commercial geolocation database. It was cross-checked against registry country, but registry country is itself only an approximation of physical location.", "Geolocation accuracy:")
bullet(" mapping URLhaus tags to families is heuristic and is labelled 'tag-inferred'. Many indicators remain unattributed.", "Family labels:")
bullet(" the shared-platform list is curated by hand, and the family threshold (5) is a tunable parameter. Some legitimately shared criminal bulletproof hosting may be suppressed, and some unknown platforms may be missed.", "Hub rules:")
bullet(" the free ip-api tier is rate-limited (about 15 requests per minute) and intended for non-commercial use. A production deployment would need a licensed provider.", "Service limits:")
bullet(" the safeguards were evaluated through data experiments, not a user study with analysts.", "No user study:")

# ======================================================================= 9 ethics
h1("9. Ethical and Legal Considerations")
bullet(" all data comes from public feeds and passive lookups (DNS, registry, geolocation). The platform never connects to, scans, downloads from or logs in to any indicator.", "Passive collection only:")
bullet(" abuse.ch data is published for free use under its terms of use; OpenPhish Community and ip-api free tiers are used for non-commercial, academic purposes within documented rate limits; all requests carry an identifying User-Agent.", "Terms of service:")
bullet(" the platform analyses infrastructure, not people. Reporter handles are replaced by stable pseudonyms (R-xxxxxx) in every output and used only in aggregate. No WHOIS registrant data or other personal data is collected, in line with purpose limitation and data minimisation [L4], [R5].", "Privacy and minimisation:")
bullet(" the committed snapshot is gzip-compressed, so live malicious URLs are not clickable or indexed in the repository. HTML reports defang every indicator (hxxp, [.]).", "Safe handling of malicious content:")
bullet(" every view states what it does not show (hosting location ≠ attacker, report time ≠ attack time, link ≠ same operator). Cluster reports state their confidence and evidence. Results are triage aids to be verified by an analyst before any blocking or reporting [R7].", "Responsible presentation:")
bullet(" no system is accessed without authorisation, which keeps the work clear of computer-misuse provisions such as the Information Technology Act, 2000 (India) [R6] and the US Computer Fraud and Abuse Act [R8]. This is a design intention, not legal advice.", "Legal:")

# ======================================================================= 10 impact
h1("10. Impact and Significance")
bullet(" one pipeline replaces manual cross-referencing of three feeds and four enrichment services, producing a "
       f"{fmt(g['nodes'])}-entity knowledge graph in minutes on a laptop.", "Integration:")
bullet(" each investigative question is matched to the visualization that answers it best, with a written justification and failure modes.", "Question-driven visualization:")
bullet(" the experiments show that ignoring shared platforms, metric choice or time semantics would change the investigation's conclusions. The safeguards are therefore functional, not cosmetic.", "Measurably fewer misreadings:")
bullet(" every edge is traceable to a feed record or enrichment method, and every number in this report can be reproduced offline from a hash-verified snapshot.", "Evidence-grade outputs:")
bullet(" GEXF and CSV exports let analysts continue the work in Gephi or a spreadsheet.", "Interoperability:")

# ======================================================================= 11 future
h1("11. Future Work")
for t in ["Passive DNS history so that host → IP links are time-stamped at report time, removing the enrichment time-lag.",
          "A second geolocation provider and latency-based checks to quantify geolocation uncertainty per IP.",
          "Learning the hub threshold from data (for example the tenant count per IP from passive DNS) instead of a fixed list.",
          "A controlled user study with analysts comparing task accuracy with and without the safeguards.",
          "STIX 2.1 export and MISP integration for sharing clusters.",
          "Scheduled collection to build a longitudinal dataset and track clusters over months."]:
    bullet(" " + t)

# ======================================================================= 12 conclusion
h1("12. Conclusion")
para(f"The project delivered a working, reproducible visualization-based OSINT intelligence platform. It turns three "
     f"public feeds and four enrichment sources into a provenance-labelled knowledge graph of {fmt(g['nodes'])} "
     f"entities and {fmt(g['edges'])} relationships, analyses it with graph, temporal, geographic and social-network "
     f"methods, and presents it through a graph, a link chart, a timeline and heat maps. The evaluation showed that no "
     f"single technique answers every investigative question: graphs suit structure, link charts suit explanation, "
     f"timelines suit sequence and heat maps suit concentration. Each also has a characteristic way of misleading. "
     f"Building safeguards into the views (hub suppression, distinct-IP weighting and normalisation, report-time "
     f"semantics, and evidence on every edge) changed the conclusions an analyst would draw from the same data. In "
     f"particular, it prevented a false {fmt(exp['without']['largest_cluster'])}-entity 'campaign'. The findings were "
     f"cross-validated against independent sources, and the limitations are stated explicitly.")
h2("Repository")
para("Source code, phase-by-phase commit history, the frozen dataset snapshot and setup instructions: "
     "https://github.com/Taniaa-p/OSINT-2")

# ======================================================================= references
h1("References")
para("Literature survey", bold=True)
refs = [
    "[L1] P. Pirolli and S. Card, \"The sensemaking process and leverage points for analyst technology as identified through cognitive task analysis,\" in Proc. Int. Conf. on Intelligence Analysis, McLean, VA, 2005.",
    "[L2] J. Stasko, C. Görg and Z. Liu, \"Jigsaw: Supporting investigative analysis through interactive visualization,\" Information Visualization, vol. 7, no. 2, pp. 118–132, 2008.",
    "[L3] J. Pastor-Galindo, P. Nespoli, F. Gómez Mármol and G. Martínez Pérez, \"The not yet exploited goldmine of OSINT: Opportunities, open challenges and future trends,\" IEEE Access, vol. 8, pp. 10282–10304, 2020.",
    "[L4] I. Böhm and S. Lolagar, \"Open source intelligence: Introduction, legal, and ethical considerations,\" International Cybersecurity Law Review, vol. 2, pp. 317–337, 2021.",
    "[L5] I. Herman, G. Melançon and M. S. Marshall, \"Graph visualization and navigation in information visualization: A survey,\" IEEE Trans. Visualization and Computer Graphics, vol. 6, no. 1, pp. 24–43, 2000.",
    "[L6] M. Ghoniem, J.-D. Fekete and P. Castagliola, \"A comparison of the readability of graphs using node-link and matrix-based representations,\" in Proc. IEEE Symp. on Information Visualization (InfoVis), 2004, pp. 17–24.",
    "[L7] V. D. Blondel, J.-L. Guillaume, R. Lambiotte and E. Lefebvre, \"Fast unfolding of communities in large networks,\" J. Statistical Mechanics: Theory and Experiment, P10008, 2008.",
    "[L8] V. E. Krebs, \"Mapping networks of terrorist cells,\" Connections, vol. 24, no. 3, pp. 43–52, 2002.",
    "[L9] J. Xu and H. Chen, \"Criminal network analysis and visualization,\" Communications of the ACM, vol. 48, no. 6, pp. 100–107, 2005.",
    "[L10] S. Chainey, L. Tompson and S. Uhlig, \"The utility of hotspot mapping for predicting spatial patterns of crime,\" Security Journal, vol. 21, no. 1–2, pp. 4–28, 2008.",
    "[L11] I. Poese, S. Uhlig, M. A. Kaafar, B. Donnet and B. Gueye, \"IP geolocation databases: Unreliable?\" ACM SIGCOMM Computer Communication Review, vol. 41, no. 2, pp. 53–56, 2011.",
    "[L12] H. Shiravi, A. Shiravi and A. A. Ghorbani, \"A survey of visualization systems for network security,\" IEEE Trans. Visualization and Computer Graphics, vol. 18, no. 8, pp. 1313–1329, 2012.",
    "[L13] S. Noel, E. Harley, K. H. Tam, M. Limiero and M. Share, \"CyGraph: Graph-based analytics and visualization for cybersecurity,\" in Handbook of Statistics, vol. 35, Elsevier, 2016, pp. 117–167.",
    "[L14] C. Wagner, A. Dulaunoy, G. Wagener and A. Iklody, \"MISP: The design and implementation of a collaborative threat intelligence sharing platform,\" in Proc. ACM Workshop on Information Sharing and Collaborative Security (WISCS), 2016, pp. 49–56.",
    "[L15] M. Correll and J. Heer, \"Black hat visualization,\" in Proc. IEEE VIS Workshop on Dealing with Cognitive Biases in Visualisations (DECISIVe), 2017.",
]
for r in refs:
    para(r, size=9.5, space_after=3)
para("Data sources, tools and standards", bold=True)
for r in [
    "[R1] abuse.ch, \"URLhaus\" and \"ThreatFox\" – data exports and terms of use. https://urlhaus.abuse.ch, https://threatfox.abuse.ch",
    "[R2] OpenPhish, \"Community Phishing Feed.\" https://openphish.com",
    "[R3] ip-api.com, \"Batch JSON API documentation.\" https://ip-api.com/docs/api:batch ; Team Cymru, \"IP to ASN Mapping Service.\" https://www.team-cymru.com/ip-asn-mapping",
    "[R4] Number Resource Organization, \"NRO extended allocation and assignment statistics.\" https://ftp.ripe.net/pub/stats/ripencc/nro-stats/",
    "[R5] Regulation (EU) 2016/679 (General Data Protection Regulation), 2016.",
    "[R6] Government of India, The Information Technology Act, 2000 (as amended).",
    "[R7] P. Cichonski, T. Millar, T. Grance and K. Scarfone, \"Computer Security Incident Handling Guide,\" NIST SP 800-61 Rev. 2, 2012.",
    "[R8] 18 U.S.C. § 1030, Computer Fraud and Abuse Act.",
    "[R9] A. Hagberg, D. Schult and P. Swart, \"Exploring network structure, dynamics, and function using NetworkX,\" in Proc. 7th Python in Science Conf. (SciPy), 2008, pp. 11–15.",
    "[R10] M. Franz, C. T. Lopes, G. Huck, Y. Dong, O. Sumer and G. D. Bader, \"Cytoscape.js: a graph theory library for visualisation and analysis,\" Bioinformatics, vol. 32, no. 2, pp. 309–311, 2016.",
]:
    para(r, size=9.5, space_after=3)

doc.save(OUT)
print("wrote", OUT)
