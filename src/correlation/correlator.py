"""Correlation engine (requirement F5).

1. Load the knowledge graph from SQLite into NetworkX.
2. Build the *infrastructure correlation graph*: url / hash / host / domain / ip nodes
   linked by hosted_on, subdomain_of and resolves_to edges.
3. Detect hub nodes (multi-tenant platforms such as GitHub or Cloudflare Pages, plus
   any pivot shared by more than HUB_FAMILY_THRESHOLD malware families) and remove
   them as pivots. This is the main safeguard against false "same campaign" links.
4. Connected components of what remains = candidate campaigns (clusters).
5. Cross-feed corroboration: entities reported by more than one independent feed.
"""
import json
from collections import Counter, defaultdict

import networkx as nx

from config import settings
from src.storage import database

INFRA_RELS = {"hosted_on", "subdomain_of", "resolves_to"}
INFRA_TYPES = {"url", "hash", "host", "domain", "ip"}
PIVOT_TYPES = {"host", "domain", "ip"}


def load_graph() -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    with database.connect() as con:
        for e in con.execute("SELECT * FROM entities"):
            g.add_node(e["id"], type=e["type"], value=e["value"], first_seen=e["first_seen"],
                       last_seen=e["last_seen"], sources=e["sources"].split(",") if e["sources"] else [],
                       records=e["records"], **json.loads(e["attrs"]))
        for x in con.execute("SELECT * FROM edges"):
            g.add_edge(x["src"], x["dst"], rel=x["rel"], source=x["source"], record_id=x["record_id"],
                       first_seen=x["first_seen"], confidence=x["confidence"], method=x["method"])
    return g


def families_of(g, node) -> set:
    return {g.nodes[d]["value"] for _, d, k in g.out_edges(node, data="rel") if k == "associated_with"}


def infra_graph(g) -> nx.Graph:
    ig = nx.Graph()
    for n, d in g.nodes(data=True):
        if d["type"] in INFRA_TYPES:
            ig.add_node(n)
    for s, t, rel in g.edges(data="rel"):
        if rel in INFRA_RELS:
            ig.add_edge(s, t)
    return ig


def detect_hubs(g, ig) -> dict:
    """Return {node: reason} for pivots that must not be used to link indicators."""
    fam = {n: families_of(g, n) for n in ig if g.nodes[n]["type"] in ("url", "hash", "host", "ip")}
    hubs = {}
    for n in ig:
        d = g.nodes[n]
        if d["type"] not in PIVOT_TYPES:
            continue
        if d.get("shared_platform"):
            hubs[n] = "known multi-tenant platform"
            continue
        reach = set(fam.get(n, set()))
        for nb in ig[n]:
            reach |= fam.get(nb, set())
            if g.nodes[nb]["type"] in PIVOT_TYPES:
                for nb2 in ig[nb]:
                    reach |= fam.get(nb2, set())
        if len(reach) > settings.HUB_FAMILY_THRESHOLD:
            hubs[n] = f"shared by {len(reach)} malware families"
    return hubs


def clusters(g, ig, hubs) -> list:
    sub = ig.subgraph([n for n in ig if n not in hubs])
    out = []
    for comp in nx.connected_components(sub):
        anchors = [n for n in comp if g.nodes[n]["type"] in ("url", "hash")
                   or (g.nodes[n]["type"] in ("host", "ip") and not any(
                       g.nodes[m]["type"] == "url" for m in sub[n]))]
        if len(anchors) < 2:
            continue
        fam = Counter()
        for n in comp:
            for f in families_of(g, n):
                fam[f] += 1
        times = sorted(t for n in comp for t in [g.nodes[n].get("first_seen")] if t)
        lasts = sorted(t for n in comp for t in [g.nodes[n].get("last_seen")] if t)
        ips = [n for n in comp if g.nodes[n]["type"] == "ip"]
        countries = Counter(g.nodes[i].get("country") for i in ips if g.nodes[i].get("country"))
        asns = Counter(g.nodes[i].get("asn") for i in ips if g.nodes[i].get("asn"))
        sources = Counter(s for n in comp for s in g.nodes[n].get("sources", []))
        out.append({"nodes": sorted(comp), "size": len(comp), "indicators": len(anchors),
                    "families": dict(fam.most_common()), "first_seen": times[0] if times else None,
                    "last_seen": lasts[-1] if lasts else (times[-1] if times else None),
                    "ips": len(ips), "countries": dict(countries.most_common()),
                    "asns": dict(asns.most_common()), "sources": dict(sources)})
    out.sort(key=lambda c: -c["indicators"])
    for i, c in enumerate(out, 1):
        c["id"] = f"C{i:04d}"
        top = next(iter(c["families"]), "Unattributed")
        c["label"] = f"{top} cluster ({c['indicators']} indicators)"
        labelled = sum(c["families"].values())
        c["purity"] = round(max(c["families"].values()) / labelled, 3) if labelled else None
    return out


def cluster_quality(g, cl) -> dict:
    """Purity: share of family-labelled nodes that carry the cluster's dominant family.
    Mixed clusters are the typical symptom of false links through shared infrastructure."""
    labelled = [c for c in cl if c["families"]]
    tot = sum(sum(c["families"].values()) for c in labelled)
    dom = sum(max(c["families"].values()) for c in labelled)
    return {"clusters": len(cl), "largest_cluster": max((c["size"] for c in cl), default=0),
            "labelled_clusters": len(labelled),
            "mixed_family_clusters": sum(len(c["families"]) > 1 for c in labelled),
            "weighted_purity": round(dom / tot, 3) if tot else None}


def cross_feed(g) -> dict:
    """How many host/IP/domain entities are independently reported by >1 feed."""
    out = {}
    for t in ("host", "ip", "domain"):
        nodes = [d for _, d in g.nodes(data=True) if d["type"] == t and d.get("sources")]
        multi = [d for d in nodes if len(set(d["sources"])) > 1]
        pairs = Counter(" + ".join(sorted(set(d["sources"]))) for d in multi)
        out[t] = {"total": len(nodes), "multi_source": len(multi), "combinations": dict(pairs)}
    return out
