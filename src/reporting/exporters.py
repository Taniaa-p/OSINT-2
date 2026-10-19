"""Exports for external tools: GEXF (Gephi) for the clustered graph and CSV for clusters."""
import csv
import io
import json

import networkx as nx

from config import settings
from src.correlation import correlator


def gexf() -> str:
    clusters = json.loads((settings.PROCESSED_DIR / "clusters.json").read_text())
    g = correlator.load_graph()
    keep = {n for c in clusters[:300] for n in c["nodes"]}
    cid = {n: c["id"] for c in clusters[:300] for n in c["nodes"]}
    out = nx.Graph()
    for n in keep:
        d = g.nodes[n]
        out.add_node(n, label=d["value"][:60], type=d["type"], cluster=cid[n])
    for s, t, rel in g.edges(data="rel"):
        if s in keep and t in keep:
            out.add_edge(s, t, rel=rel)
    buf = io.BytesIO()
    nx.write_gexf(out, buf)
    return buf.getvalue().decode()


def clusters_csv() -> str:
    clusters = json.loads((settings.PROCESSED_DIR / "clusters.json").read_text())
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "indicators", "entities", "ips", "dominant_family", "families", "purity",
                "countries", "asns", "sources", "first_seen", "last_seen"])
    for c in clusters:
        w.writerow([c["id"], c["indicators"], c["size"], c["ips"], next(iter(c["families"]), ""),
                    json.dumps(c["families"]), c["purity"], json.dumps(c["countries"]),
                    json.dumps(c["asns"]), json.dumps(c["sources"]), c["first_seen"], c["last_seen"]])
    return buf.getvalue()
