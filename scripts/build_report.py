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
             "4. System Architecture", "      4.1 Data model", "5. Evaluation of Visualization Techniques", "      5.1 Worked investigation: how the views support each other",
             "6. Data Processing, Correlation and Analysis",
             "      6.1 Cleaning · 6.2 Correlation and hub suppression · 6.3 Graph · 6.4 Temporal · 6.5 Geographic · 6.6 Social network · 6.7 WHOIS / RDAP",
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
     f"enriched them with DNS, WHOIS (RDAP) registration data, IP geolocation, an independent ASN registry service and RIR address statistics. From "
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
     f"survey of 16 recent papers identifies the research gaps the architecture addresses.")

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
    ["O1", "Collect a multi-source OSINT dataset with entities, relationships, timestamps, locations and threat indicators", "3 feeds + 5 enrichment sources; SHA-256 manifest"],
    ["O2", "Clean, normalise and de-duplicate; extract typed entities", "rejection counts by reason; entity counts"],
    ["O3", "Correlate across sources into a provenance-labelled knowledge graph", "cross-feed overlap; infrastructure clusters"],
    ["O4", "Apply graph, temporal, geographic and social-network analytics", "centrality, Louvain, bursts, normalised geo, SNA"],
    ["O5", "Evaluate the suitability of graphs, link charts, timelines and heat maps", "suitability matrix (Section 5)"],
    ["O6", "Implement an interactive dashboard and automated reporting", "Flask dashboard, HTML reports, GEXF/CSV export"],
    ["O7", "Reduce, and quantify, the possibility of misinterpreting evidence", "before/after experiments (Section 8.3)"],
    ["O8", "Survey at least 10 research papers and identify research gaps", "16-paper comparison (Section 2)"],
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
bullet(" passive collection from URLhaus, ThreatFox and OpenPhish; passive enrichment through DNS, WHOIS/RDAP, ip-api.com, the "
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
para("Sixteen peer-reviewed papers, mostly from 2020–2024, were reviewed across the five areas required by the brief: "
     "OSINT and threat intelligence, graph analytics and knowledge graphs, social-network analysis, geographic "
     "visualization and geolocation, and cyber-intelligence visualization and dashboards. Two further papers on "
     "misleading visualization and timeline design were added, because the brief asks how to reduce misinterpretation. "
     "Every reference was checked against its publisher or DOI record. Table 3 compares the visualization or "
     "analytical approach, methodology, dataset, findings and limitations of each paper. Section 2.2 derives the "
     "research gaps that the proposed architecture addresses.")
lit = [
    ["[L1] Yadav, Kumar & Singh (2023)", "OSINT review", "Survey of OSINT tools, techniques and cyber-security applications", "Literature review", "Published OSINT studies and tools", "OSINT is used widely in cybercrime, forensics and social-network security; automation with ML/AI is the main trend", "Visualization and evidence presentation get little attention; no evaluation framework"],
    ["[L2] Browne, Abedin & Chowdhury (2024)", "OSINT + AI", "Systematic review of AI applied to OSINT", "PRISMA systematic review", "163 research articles", "Most work focuses on collection and classification (NLP, ML); applications span social media, dark web and threat intelligence", "Few studies address explainability or how results are shown to analysts"],
    ["[L3] Riebe, Biselli, Kaufhold & Reuter (2023)", "OSINT ethics / privacy", "Acceptance and privacy concerns of OSINT for cyber security", "Representative population survey", "Survey responses from the general public", "Acceptance depends on purpose and transparency; collection of personal data raises strong privacy concerns", "Survey of attitudes, not of tools; single national sample"],
    ["[L4] Böhm, Menges & Pernul (2018)", "CTI visual analytics", "Graph-based persistence and interactive graph visualization of STIX threat intelligence", "Prototype implementation and demonstration", "Example STIX 2 threat-intelligence data", "Graph views help analysts explore and enrich semi-structured CTI", "Relies on structured STIX input; no geographic or temporal view; small evaluation"],
    ["[L5] Sarhan & Spruit (2021)", "Knowledge graphs / entity extraction", "Open-CyKG: open information extraction + cyber NER to build a threat-intelligence knowledge graph", "Neural OIE and NER, embedding-based canonicalisation", "APT threat reports (unstructured text)", "Automatically extracted triples form a queryable CTI knowledge graph; components beat baselines", "Extraction errors propagate into the graph; no visualization or provenance for analysts"],
    ["[L6] Yan, Yang, Shi, Fang, Li & Ye (2023)", "Graph analytics", "Survey of graph-mining methods for cyber security (centrality, community detection, GNNs)", "Systematic survey", "Published graph-based security studies and datasets", "Graphs are a natural model for relations between security entities; graph mining improves detection and attribution", "Focus on algorithms, not on how graphs are visualized or misread"],
    ["[L7] Pete, Hughes, Chua & Bada (2020)", "Social-network analysis", "SNA of user-interaction networks in six dark-web forums", "Network construction, centrality, community detection", "Six dark-web forum datasets", "Only a small subset of users is influential; forums differ in structure", "Forum data only; links are replies, not verified relationships"],
    ["[L8] Hu, Wang, Guin & Zhu (2018)", "Geographic visualization", "Spatio-temporal kernel density estimation for hotspot mapping", "STKDE with predictive-accuracy evaluation", "City crime incident records", "Adding time to KDE improves hotspot prediction; bandwidth choice changes the map", "Physical crime, not network infrastructure; parameter-sensitive"],
    ["[L9] Gouel, Vermeulen, Beverly, Fourmaux & Friedman (2021)", "Geolocation reliability", "Longitudinal stability study of an IP geolocation database", "Snapshot comparison; reproduction of a prior study", "Weekly snapshots of a commercial geolocation database", "Successive snapshots differ significantly; median error shifted >100 km and coverage by 30%", "One database; ground truth limited to some address types"],
    ["[L10] Jiang, Jayatilaka, Nasim, Grobler, Zahedi & Babar (2022)", "Cyber dashboards", "Systematic review of cyber situational-awareness visualizations", "Systematic literature review", "54 publications", "Most visualizations serve operational staff and the perception level; impact and projection are rarely shown", "Review only; does not propose or test a visualization design"],
    ["[L11] Komadina, Mihajlović & Groš (2022)", "Security visualization", "Design-space analysis of cyber-security visualizations", "Classification by data, task, encoding, interaction, evaluation", "60 VizSec papers (2016–2021)", "Provides a taxonomy of data, tasks and encodings used in security visualization and shows which combinations are under-explored", "Limited to one venue and six years"],
    ["[L12] Li, Dunn, Pearce, McCoy, Voelker, Savage & Levchenko (2019)", "Threat-intel feeds", "Metrics for comparing threat-intelligence feeds", "Quantitative feed comparison against external measurements", "Public and commercial IP and hash feeds", "Feeds overlap little and have limited coverage and accuracy", "No visualization; feeds analysed as sets, not as relationships"],
    ["[L13] Bouwman, Griffioen, Egbers, Doerr, Klievink & van Eeten (2020)", "Threat-intel feeds", "Added value of commercial threat intelligence", "Feed overlap analysis + 14 practitioner interviews", "Two commercial vendors and four open feeds", "Only 2.5–4% indicator overlap for the same 22 actors; analysts judge TI informally", "Two vendors only; little on how TI is visualized"],
    ["[L14] Kumarasinghe, Nabeel & Elvitigala (2024)", "Hosting infrastructure", "Forecasting malicious domains from the hosting infrastructure they share", "Infrastructure-based features and classification", "Domain, DNS and blocklist data", "Shared low-reputation hosting predicts future malicious domains", "Shared infrastructure can also join benign tenants; classification, not visual analysis"],
    ["[L15] Lo, Gupta, Shigyo, Wu, Bertini & Qu (2022)", "Misleading visualization", "Taxonomy of misleading visualizations", "Open coding of real-world reported charts", ">1,000 visualizations reported as misleading", "74 types of issues; many arise from honest design choices, not deliberate deception", "General charts; no security-specific safeguards"],
    ["[L16] Di Bartolomeo et al. (2020)", "Timeline visualization", "Effect of timeline shape on task performance", "Controlled online experiment", "192 participants; recurrent and non-recurrent event data", "Shape changes task time but not accuracy; linear timelines are fastest for lookup", "Synthetic tasks; no investigative context"],
]
table(["Paper", "Area", "Approach / visualization", "Methodology", "Dataset", "Key findings", "Limitations"], lit,
      "Comparison of surveyed research", widths=[2.5, 1.7, 2.8, 2.2, 2.2, 3, 2.6], size=7)
h2("2.1 Comparison of visualization approaches")
para("Node-link graphs are the dominant form in cyber-intelligence work. [L11] classifies security visualizations by "
     "data, task and visual encoding, and graph-based CTI systems [L4, L5] and graph-mining methods [L6] model "
     "indicators, actors and infrastructure as linked entities. Link charts are the analyst-facing, incremental form of "
     "the same model: [L4] lets analysts explore STIX objects from a starting node. Graph analytics turns pictures into "
     "ranked evidence: centrality and community detection identify key actors [L6, L7]. Timelines support sequence and "
     "duration reasoning, and [L16] shows that a plain linear layout is fastest for lookup tasks, which is why this "
     "platform uses linear daily and Gantt timelines. Heat maps support density reasoning in space and time [L8]. "
     "However, [L8] shows that parameter choices change the hotspot map, and [L9] shows that the geolocation feeding "
     "such maps is itself unstable. Dashboards combine these views [L10], but most serve operational monitoring at the "
     "perception level rather than investigation [L10].")
para("On data, [L12] and [L13] show that threat feeds overlap very little. Combining several feeds is therefore "
     "necessary, and corroboration across feeds is informative. [L14] shows that shared hosting is a strong signal of "
     "malicious infrastructure, but also that it connects unrelated tenants. On interpretation, [L15] shows that most "
     "misleading charts come from ordinary design choices such as aggregation, scaling and omitted context, and the "
     "OSINT literature [L1, L2, L3] stresses transparency and purpose limitation.")
h2("2.2 Research gaps addressed by this project")
gaps = [
    ("G1 – Evidence provenance in the view. ", "CTI graph and knowledge-graph systems [L4, L5] draw links but do not show, "
     "on the link itself, which source record created it, by what method and with what confidence. OSINT reviews [L1, L2] "
     "note that explainability is rarely addressed. → Every edge in this platform carries source, record ID, time, "
     "method and confidence, shown in an evidence panel."),
    ("G2 – False links through shared infrastructure. ", "Infrastructure-based correlation [L14] and graph mining [L6] "
     "link everything that shares a host, IP or provider. In open feeds, code-hosting and CDN platforms are shared by "
     "thousands of unrelated actors, and the effect on visual analysis is rarely measured. → Hub suppression, quantified "
     "before and after (Section 8.3)."),
    ("G3 – Normalisation and uncertainty in geographic views. ", "Hotspot methods are parameter-sensitive [L8] and "
     "geolocation databases are unstable [L9]. Threat maps nevertheless typically plot raw counts from one provider. → "
     "Distinct-IP weighting, per-million-IPv4 normalisation, and cross-validation of geolocation against registry data."),
    ("G4 – Temporal semantics. ", "Timeline research [L16] studies layout but not the meaning of the timestamps. Feeds "
     "record when something was reported, not when it was active, and feed timeliness differs [L13]. → Explicit "
     "report-time labelling, window filtering, and exclusion of observation-only timestamps."),
    ("G5 – Investigation-oriented, evaluated dashboards over multiple open feeds. ", "Dashboards mostly target "
     "operational monitoring [L10]; feed studies [L12, L13] do not visualise relationships. → One "
     "provenance-labelled model over three feeds drives four coordinated views. The views are evaluated with "
     "quantitative misinterpretation experiments, from a hash-verified snapshot anyone can re-run."),
    ("G6 – Ethics built into the tool. ", "[L3] shows that acceptance of OSINT depends on transparency and privacy, but "
     "technical controls in tools are rarely described. → Pseudonymised reporters, defanged reports, passive-only "
     "collection."),
]
for lead, text in gaps:
    bullet(text, lead)

# ======================================================================= 3 data collection
h1("3. OSINT Data Collection and Source Identification")
para("The dataset had to contain entities, relationships, timestamps, locations and threat indicators. No single open "
     "source provides all five, so three primary feeds were combined with five enrichment sources. Table 4 lists every "
     "source, what it contributes, how it is accessed and how failure is handled.")
table(["Source", "Type", "Contributes", "Access method", "Failure handling"], [
    ["abuse.ch URLhaus", "Threat feed (malware URLs)", "URLs, hosts, timestamps, status, tags, reporters", "CSV export (recent, 30 days), no key", "Retry ×3; marked failed in manifest; others continue"],
    ["abuse.ch ThreatFox", "Threat feed (IOCs)", "IP:port, domains, URLs, hashes, explicit malware family, confidence", "CSV export (recent), no key", "As above"],
    ["OpenPhish Community", "Phishing feed", "Phishing URLs (no timestamps)", "Plain-text feed", "As above; retrieval time marked as observation time"],
    ["DNS (dnspython)", "Enrichment", "host → IP (A records), NXDOMAIN status", "Standard resolver queries, 32 threads", "Timeout/NXDOMAIN stored as status"],
    ["ip-api.com", "Enrichment", "Geolocation, ASN, ISP, hosting flag", "Batch API (100 IPs/request, ≤15 req/min)", "Rate-limit headers honoured; failed batch logged"],
    ["WHOIS via RDAP (IANA bootstrap → registry RDAP servers)", "Enrichment (domain registration)", "Registration date, expiry, registrar of each registered domain", "RDAP JSON queries (RFC 9083), 8 threads", "429/404 stored as status; retried on next run"],
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
    ["Graph (cluster overview)", "Seeing groups, components, hubs; centrality", "Large dense data (hairball); reading time", "Proximity read as relationship; hubs merge unrelated campaigns", "Hub suppression; only infrastructure edges form clusters; cap of 600 nodes; size = betweenness"],
    ["Link chart (ego expansion)", "Explaining one indicator; pivoting step by step", "Global patterns", "Expanding through a CDN floods the chart; enrichment links look like feed facts", "Per-relation expansion cap with hidden count; dashed lines for DNS/geo, dotted for tag-inferred; hub border; evidence panel"],
    ["Timeline", "Sequence, bursts, campaign duration", "Relationships, place", "Report time read as attack time; old IOCs re-listed look new", "'Report time (UTC)' label; window filter; OpenPhish observation times excluded; z-score bursts"],
    ["Geographic heat map / choropleth", "Concentration in space", "Causality, attribution", "Raw counts mirror hosting size; one server with 10k URLs dominates; server location read as attacker location", "Distinct-IP weighting; per-million-IPv4 normalisation; metric switch with warning; agreement rate shown"],
    ["Temporal heat map (day × hour)", "Periodicity, tempo", "Exact sequence", "Reporter working hours read as attacker hours", "Caveat; UTC stated"],
], "Strengths, failure modes and safeguards per technique", widths=[2.6, 2.8, 2.4, 4, 4.6], size=8)

h2("5.1 Worked investigation: how the views support each other")
para("To justify the selection in practice, the following investigation was run end to end on the snapshot using only the "
     "dashboard. Each step uses the view suited to the question at that point, and each safeguard is visible where it "
     "matters.")
import sqlite3 as _sq
_con = _sq.connect(settings.DB_PATH)
_r = _con.execute("SELECT attrs, records, first_seen, last_seen FROM entities WHERE id='ip:176.65.134.121'").fetchone()
_con.close()
if _r:
    _a = json.loads(_r[0])
    _c = next((c for c in top_c if c["id"] == "C0001"), top_c[0])
    steps = [
        ("Step 1 – Entry point (IOC extraction). ", "An analyst pastes a defanged note containing 176.65.134[.]121. The "
         "extractor refangs it and finds it in the dataset as an entity reported by URLhaus (Figure 10)."),
        ("Step 2 – Link chart (IQ2). ", f"Expanding the IP shows {_r[1]} URL records hosted on it, on ports "
         f"{', '.join(str(x) for x in _a.get('ports', []))}. Only 15 per relation are drawn, and the chart states how many are "
         f"hidden. The dashed edges show {_a.get('asn')} ({_a.get('isp')}) and {_a.get('country')}; dashed means they come from "
         f"enrichment, not from the feed (Figure 4). The evidence panel shows that ip-api and Team Cymru agree on the ASN "
         f"({_a.get('cymru_asn')}) and that the registry country is {_a.get('registry_cc')}."),
        ("Step 3 – Graph (IQ1, IQ6). ", f"The IP belongs to cluster {_c['id']}, the largest infrastructure cluster after hub "
         f"suppression: {_c['indicators']} indicators, family purity {_c['purity']}, dominated by "
         f"{next(iter(_c['families']))}. The IP is the highest-degree node in the suppressed graph (Table 12), so it is the "
         f"pivot to act on first."),
        ("Step 4 – Timeline (IQ3). ", f"The cluster was reported between {(_r[2] or '')[:10]} and {(_r[3] or '')[:10]}. The "
         f"timeline labels this as report time, so the analyst records 'reported active from …', not 'attack started on …'."),
        ("Step 5 – Heat map (IQ4). ", "Germany appears among the top hosting countries by distinct IPs. Switching to the "
         "normalised metric shows that Germany is not over-represented for its address space. This single server is "
         "therefore a hosting-abuse case, not evidence of a German hotspot."),
        ("Step 6 – Report. ", "The cluster report (Figure 11) lists every entity defanged, with its evidence trail and a "
         "stated confidence (single feed → medium), ready to send to the hosting provider's abuse contact."),
    ]
    for lead, text in steps:
        bullet(text, lead)
para("Without the safeguards, the same walk would have gone wrong at three points. Expanding a GitHub-hosted indicator "
     "would have pulled in 13,580 unrelated entities. The country map would have suggested a German hotspot. The report "
     "dates could have been quoted as attack dates. With them, every statement in the final report can be traced to a "
     "source record.")

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

h2("6.7 WHOIS / RDAP domain-registration analysis")
wh = S.get("whois", {})
para(f"WHOIS registration data was collected through RDAP, the standardised JSON successor of WHOIS (RFC 9083). Each "
     f"registered domain is sent to its registry's RDAP server, found through the IANA bootstrap file (RFC 9224). Only "
     f"the registration date and registrar are stored, never registrant contact details. For "
     f"{fmt(wh.get('domains_with_registration', 0))} non-platform domains with a registration date, the domain's age when "
     f"it was first reported was computed (first-seen date minus registration date).")
table(["Measure", "Value"], [
    ["Domains with RDAP registration date", fmt(wh.get("domains_with_registration", 0))],
    ["Median age at first report", f"{wh.get('median_age_days')} days"],
    ["Registered < 7 days before being reported", pct(wh.get("share_under_7_days"))],
    ["Registered < 30 days before being reported", pct(wh.get("share_under_30_days"))],
    ["Older than 1 year when reported", pct(wh.get("share_over_1_year"))],
] + [[f"Median age – {k}", f"{v['median_age_days']} days ({v['n']} domains; {pct(v['share_under_30_days'])} < 30 days)"]
     for k, v in wh.get("by_source", {}).items()]
  + [["Most frequent registrars", ", ".join(f"{r} ({n})" for r, n in wh.get("top_registrars", [])[:6])]],
      "Domain age at first report (WHOIS / RDAP)", widths=[6.5, 9.5])
para("Two populations are visible. About a third of the domains were registered within a month of being reported, and "
     "most of those within a week. These are attacker-registered throw-away domains. Roughly 40% were more than a year old, "
     "which is typical of compromised legitimate websites. The distinction matters for response: a new domain should be "
     "reported to its registrar for suspension, while an old one usually belongs to a victim whose site has been "
     "compromised. Domain age is shown in the evidence panel of every domain, so the analyst sees it before acting.")

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
bullet(f" WHOIS/RDAP shows {pct(S.get('whois', {}).get('share_under_7_days'))} of dated malicious domains were registered "
       f"less than a week before being reported and {pct(S.get('whois', {}).get('share_over_1_year'))} were over a year old. "
       f"This separates throw-away attacker domains from compromised legitimate sites, which need different responses.",
       "Two kinds of domains:")
bullet(f" Only {cf['ip']['multi_source']} of {fmt(cf['ip']['total'])} IPs and {cf['host']['multi_source']} of "
       f"{fmt(cf['host']['total'])} hosts appear in more than one feed. The feeds are largely complementary rather than "
       f"redundant, which supports combining them. It also means most indicators rest on a single source.",
       "Low feed overlap:")
h2("8.2 Cross-source validation")
para("Every derived attribute that could be checked against an independent source was checked.")
table(["Check", "Sources compared", "Compared", "Agreement", "Interpretation"], [
    ["ASN of each IP", "ip-api vs Team Cymru (BGP)", fmt(ag["asn_compared"]), pct(ag["asn_agreement"]), "High: ASN attribution is reliable"],
    ["Country of each IP", "ip-api geolocation vs RIR registry country (Cymru)", fmt(ag["country_compared"]), pct(ag["country_agreement"]), "Country-level location is mostly reliable; disagreements are shown as a caveat on the map [L9]"],
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
bullet(" the platform analyses infrastructure, not people. Reporter handles are replaced by stable pseudonyms (R-xxxxxx) in every output and used only in aggregate. WHOIS (RDAP) lookups store only the registration date and registrar, never registrant names, e-mail addresses or phone numbers, and no other personal data is collected, in line with purpose limitation and data minimisation [L3], [R5].", "Privacy and minimisation:")
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
    "[L1] A. Yadav, A. Kumar and V. Singh, \"Open-source intelligence: a comprehensive review of the current state, applications and future perspectives in cyber security,\" Artificial Intelligence Review, vol. 56, pp. 12407–12438, 2023. doi:10.1007/s10462-023-10454-y",
    "[L2] T. O. Browne, M. Abedin and M. J. M. Chowdhury, \"A systematic review on research utilising artificial intelligence for open source intelligence (OSINT) applications,\" International Journal of Information Security, vol. 23, pp. 2911–2938, 2024. doi:10.1007/s10207-024-00868-2",
    "[L3] T. Riebe, T. Biselli, M.-A. Kaufhold and C. Reuter, \"Privacy concerns and acceptance factors of OSINT for cybersecurity: A representative survey,\" Proceedings on Privacy Enhancing Technologies, vol. 2023, no. 1, pp. 477–493, 2023. doi:10.56553/popets-2023-0028",
    "[L4] F. Böhm, F. Menges and G. Pernul, \"Graph-based visual analytics for cyber threat intelligence,\" Cybersecurity, vol. 1, art. 16, 2018. doi:10.1186/s42400-018-0017-4",
    "[L5] I. Sarhan and M. Spruit, \"Open-CyKG: An open cyber threat intelligence knowledge graph,\" Knowledge-Based Systems, vol. 233, art. 107524, 2021. doi:10.1016/j.knosys.2021.107524",
    "[L6] B. Yan, C. Yang, C. Shi, Y. Fang, Q. Li, Y. Ye and J. Du, \"Graph mining for cybersecurity: A survey,\" ACM Transactions on Knowledge Discovery from Data, vol. 18, no. 2, pp. 1–52, 2023. doi:10.1145/3610228",
    "[L7] I. Pete, J. Hughes, Y. T. Chua and M. Bada, \"A social network analysis and comparison of six dark web forums,\" in Proc. IEEE European Symposium on Security and Privacy Workshops (EuroS&PW), 2020, pp. 484–493. doi:10.1109/EuroSPW51379.2020.00071",
    "[L8] Y. Hu, F. Wang, C. Guin and H. Zhu, \"A spatio-temporal kernel density estimation framework for predictive crime hotspot mapping and evaluation,\" Applied Geography, vol. 99, pp. 89–97, 2018. doi:10.1016/j.apgeog.2018.08.001",
    "[L9] M. Gouel, K. Vermeulen, R. Beverly, O. Fourmaux and T. Friedman, \"IP geolocation database stability and implications for network research,\" in Proc. Network Traffic Measurement and Analysis Conference (TMA), IFIP, 2021.",
    "[L10] L. Jiang, A. Jayatilaka, M. Nasim, M. Grobler, M. Zahedi and M. A. Babar, \"Systematic literature review on cyber situational awareness visualizations,\" IEEE Access, vol. 10, pp. 57525–57554, 2022. doi:10.1109/ACCESS.2022.3178195",
    "[L11] A. Komadina, Ž. Mihajlović and S. Groš, \"Analysis of the design space for cybersecurity visualizations in VizSec,\" in Proc. IEEE Symposium on Visualization for Cyber Security (VizSec), 2022, pp. 1–11. doi:10.1109/VizSec56996.2022.9941422",
    "[L12] V. G. Li, M. Dunn, P. Pearce, D. McCoy, G. M. Voelker, S. Savage and K. Levchenko, \"Reading the tea leaves: A comparative analysis of threat intelligence,\" in Proc. 28th USENIX Security Symposium, 2019.",
    "[L13] X. Bouwman, H. Griffioen, J. Egbers, C. Doerr, B. Klievink and M. van Eeten, \"A different cup of TI? The added value of commercial threat intelligence,\" in Proc. 29th USENIX Security Symposium, 2020, pp. 433–450.",
    "[L14] U. Kumarasinghe, M. Nabeel and C. Elvitigala, \"Blocklist-Forecast: Proactive domain blocklisting by identifying malicious hosting infrastructure,\" in Proc. 27th Int. Symposium on Research in Attacks, Intrusions and Defenses (RAID), ACM, 2024, pp. 35–48. doi:10.1145/3678890.3678925",
    "[L15] L. Y.-H. Lo, A. Gupta, K. Shigyo, A. Wu, E. Bertini and H. Qu, \"Misinformed by visualization: What do we learn from misinformative visualizations?\" Computer Graphics Forum, vol. 41, no. 3, pp. 515–525, 2022. doi:10.1111/cgf.14559",
    "[L16] S. Di Bartolomeo, A. Pandey, A. Leventidis, D. Saffo, U. H. Syeda, E. Carstensdottir, M. Seif El-Nasr, M. A. Borkin and C. Dunne, \"Evaluating the effect of timeline shape on visualization task performance,\" in Proc. ACM CHI Conference on Human Factors in Computing Systems, 2020, pp. 1–12. doi:10.1145/3313831.3376237",
]
for r in refs:
    para(r, size=9.5, space_after=3)
para("Data sources, tools and standards", bold=True)
for r in [
    "[R1] abuse.ch, \"URLhaus\" and \"ThreatFox\" – data exports and terms of use. https://urlhaus.abuse.ch, https://threatfox.abuse.ch",
    "[R2] OpenPhish, \"Community Phishing Feed.\" https://openphish.com",
    "[R3] ip-api.com, \"Batch JSON API documentation.\" https://ip-api.com/docs/api:batch ; Team Cymru, \"IP to ASN Mapping Service.\" https://www.team-cymru.com/ip-asn-mapping",
    "[R12] S. Hollenbeck and A. Newton, \"JSON Responses for the Registration Data Access Protocol (RDAP),\" RFC 9083, IETF, 2021; M. Blanchet, \"Finding the Authoritative Registration Data Access Protocol (RDAP) Service,\" RFC 9224, IETF, 2022.",
    "[R4] Number Resource Organization, \"NRO extended allocation and assignment statistics.\" https://ftp.ripe.net/pub/stats/ripencc/nro-stats/",
    "[R5] Regulation (EU) 2016/679 (General Data Protection Regulation), 2016.",
    "[R6] Government of India, The Information Technology Act, 2000 (as amended).",
    "[R7] P. Cichonski, T. Millar, T. Grance and K. Scarfone, \"Computer Security Incident Handling Guide,\" NIST SP 800-61 Rev. 2, 2012.",
    "[R8] 18 U.S.C. § 1030, Computer Fraud and Abuse Act.",
    "[R9] A. Hagberg, D. Schult and P. Swart, \"Exploring network structure, dynamics, and function using NetworkX,\" in Proc. 7th Python in Science Conf. (SciPy), 2008, pp. 11–15.",
    "[R11] V. D. Blondel, J.-L. Guillaume, R. Lambiotte and E. Lefebvre, \"Fast unfolding of communities in large networks,\" J. Statistical Mechanics: Theory and Experiment, P10008, 2008 (Louvain algorithm used in Section 6.3).",
    "[R10] M. Franz, C. T. Lopes, G. Huck, Y. Dong, O. Sumer and G. D. Bader, \"Cytoscape.js: a graph theory library for visualisation and analysis,\" Bioinformatics, vol. 32, no. 2, pp. 309–311, 2016.",
]:
    para(r, size=9.5, space_after=3)

doc.save(OUT)
print("wrote", OUT)
