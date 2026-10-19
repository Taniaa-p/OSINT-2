"""Flask dashboard: overview, graph, link chart, timeline, heat maps, social network,
free-text IOC extraction, evidence panel, reports and exports (requirement F7/F8)."""
import json
from functools import lru_cache

from flask import Flask, Response, abort, jsonify, render_template, request

from config import settings
from src.storage import database

app = Flask(__name__)
P = settings.PROCESSED_DIR


@lru_cache(maxsize=None)
def load(name):
    return json.loads((P / name).read_text())


def entity_row(con, eid):
    e = con.execute("SELECT * FROM entities WHERE id=?", (eid,)).fetchone()
    if not e:
        return None
    d = dict(e)
    d["attrs"] = json.loads(d["attrs"])
    d["sources"] = d["sources"].split(",") if d["sources"] else []
    d["cluster"] = cluster_of().get(eid)
    d["hub"] = load("hubs.json").get(eid)
    return d


@lru_cache(maxsize=1)
def cluster_of():
    return {n: c["id"] for c in load("clusters.json") for n in c["nodes"]}


# ------------------------------------------------------------------ pages
@app.route("/")
def overview():
    return render_template("overview.html", s=load("summary.json"), active="overview")


@app.route("/graph")
def graph():
    return render_template("graph.html", s=load("summary.json"), active="graph")


@app.route("/link")
def link():
    return render_template("link.html", start=request.args.get("id", ""), active="link")


@app.route("/timeline")
def timeline():
    return render_template("timeline.html", s=load("summary.json"), window_days=settings.WINDOW_DAYS, active="timeline")


@app.route("/heatmap")
def heatmap():
    return render_template("heatmap.html", s=load("summary.json"), active="heatmap")


@app.route("/network")
def network():
    return render_template("network.html", s=load("summary.json"), active="network")


@app.route("/clusters")
def clusters():
    return render_template("clusters.html", clusters=load("clusters.json")[:200], active="clusters")


@app.route("/extract", methods=["GET", "POST"])
def extract_page():
    from src.extraction.entities import extract_iocs
    text, found, matches = request.values.get("text", ""), None, []
    if text:
        found = extract_iocs(text)
        keys = ([f"url:{u}" for u in found["url"]] + [f"ip:{i}" for i in found["ip"]] +
                [f"host:{d}" for d in found["domain"]] + [f"domain:{d}" for d in found["domain"]] +
                [f"hash:{h}" for h in found["sha256"] + found["md5"]])
        with database.connect() as con:
            matches = [m for m in (entity_row(con, k) for k in keys) if m]
    return render_template("extract.html", text=text, found=found, matches=matches, active="extract")


# ------------------------------------------------------------------ data APIs
@app.route("/api/<name>")
def api(name):
    files = {"graph": "graph_view.json", "timeline": "timeline.json", "geo": "geo.json", "sna": "sna.json"}
    if name not in files:
        abort(404)
    return jsonify(load(files[name]))


@app.route("/api/entity")
def api_entity():
    """Evidence panel: the entity plus every edge with its provenance."""
    eid = request.args.get("id", "")
    with database.connect() as con:
        e = entity_row(con, eid)
        if not e:
            abort(404)
        edges = [dict(r) for r in con.execute(
            "SELECT * FROM edges WHERE src=? OR dst=? LIMIT 200", (eid, eid))]
    return jsonify({"entity": e, "edges": edges})


@app.route("/api/ego")
def api_ego():
    """Link chart expansion: 1-hop neighbourhood, capped per relation so a hub never
    floods the chart; the number of hidden neighbours is reported instead."""
    eid, cap = request.args.get("id", ""), int(request.args.get("cap", 15))
    with database.connect() as con:
        if not con.execute("SELECT 1 FROM entities WHERE id=?", (eid,)).fetchone():
            # allow bare values: try every entity type
            row = con.execute("SELECT id FROM entities WHERE value=? ORDER BY type='url' LIMIT 1", (eid,)).fetchone()
            if not row:
                return jsonify({"error": f"'{eid}' not found in dataset"}), 404
            eid = row["id"]
        rows = con.execute("SELECT * FROM edges WHERE src=? OR dst=?", (eid, eid)).fetchall()
        groups = {}
        for r in rows:
            other = r["dst"] if r["src"] == eid else r["src"]
            groups.setdefault(r["rel"], {}).setdefault(other, dict(r))
        nodes, edges, hidden = {eid}, [], {}
        for rel, others in groups.items():
            items = list(others.items())
            for other, r in items[:cap]:
                nodes.add(other)
                edges.append({"data": {"id": f"{r['src']}|{rel}|{r['dst']}", "source": r["src"], "target": r["dst"],
                                       "rel": rel, "method": r["method"], "evidence": r["source"],
                                       "confidence": r["confidence"]}})
            if len(items) > cap:
                hidden[rel] = len(items) - cap
        hubs = load("hubs.json")
        els = []
        for n in nodes:
            e = con.execute("SELECT type, value, sources FROM entities WHERE id=?", (n,)).fetchone()
            els.append({"data": {"id": n, "label": e["value"][:40], "type": e["type"],
                                 "hub": bool(hubs.get(n)), "sources": e["sources"]}})
    return jsonify({"center": eid, "elements": els + edges, "hidden": hidden})


# ------------------------------------------------------------------ reports & exports
@app.route("/report/cluster/<cid>")
def cluster_report(cid):
    from src.reporting.report_generator import render_cluster_report
    html = render_cluster_report(cid)
    if html is None:
        abort(404)
    return html


@app.route("/report/summary")
def summary_report():
    from src.reporting.report_generator import render_summary_report
    return render_summary_report()


@app.route("/export/<fmt>")
def export(fmt):
    from src.reporting import exporters
    if fmt == "gexf":
        return Response(exporters.gexf(), mimetype="application/xml",
                        headers={"Content-Disposition": "attachment; filename=osint_graph.gexf"})
    if fmt == "clusters.csv":
        return Response(exporters.clusters_csv(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=clusters.csv"})
    abort(404)


def main():
    app.run(host=settings.FLASK_HOST, port=settings.FLASK_PORT, debug=False)
