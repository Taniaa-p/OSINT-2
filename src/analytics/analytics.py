"""Graph, temporal, geographic and social-network analytics (requirement F6), plus
the misinterpretation experiments used in the report. Writes JSON consumed by the
dashboard to data/processed/."""
import json
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime

import networkx as nx
import pandas as pd
import pycountry

from config import settings
from src.acquisition.rir_stats import load_ipv4_by_country
from src.correlation import correlator
from src.utils.logger import get_logger

log = get_logger("analytics")


def _iso3(cc):
    c = pycountry.countries.get(alpha_2=cc)
    return c.alpha_3 if c else None


# ------------------------------------------------------------------ graph analytics
def graph_metrics(g, ig, hubs) -> dict:
    sub = ig.subgraph([n for n in ig if n not in hubs])
    deg = nx.degree_centrality(sub)
    k = min(settings.BETWEENNESS_SAMPLE, len(sub))
    btw = nx.betweenness_centrality(sub, k=k, seed=42) if k else {}
    comms = nx.community.louvain_communities(sub, seed=42) if len(sub) else []
    community_of = {n: i for i, c in enumerate(comms) for n in c}
    def top(d, n=15):
        return [{"id": x, "type": g.nodes[x]["type"], "value": g.nodes[x]["value"], "score": round(s, 5)}
                for x, s in sorted(d.items(), key=lambda kv: -kv[1])[:n]]
    return {"nodes": sub.number_of_nodes(), "edges": sub.number_of_edges(),
            "components": nx.number_connected_components(sub),
            "density": round(nx.density(sub), 8),
            "louvain_communities": len(comms),
            "louvain_modularity": round(nx.community.modularity(sub, comms), 4) if comms else None,
            "top_degree": top(deg), "top_betweenness": top(btw),
            "_btw": btw, "_community": community_of}


# ------------------------------------------------------------------ temporal analytics
def temporal(g) -> dict:
    rows = []
    for n, d in g.nodes(data=True):
        if d["type"] in ("url", "hash") or (d["type"] in ("ip", "host") and d.get("first_seen")
                                            and not any(g.nodes[p]["type"] == "url" for p in g.predecessors(n))):
            if not d.get("first_seen") or d.get("observation_time"):
                continue
            fams = correlator.families_of(g, n) or {"Unattributed"}
            for f in fams:
                rows.append({"t": d["first_seen"], "family": f, "source": d["sources"][0] if d["sources"] else "?"})
    df = pd.DataFrame(rows)
    df["t"] = pd.to_datetime(df["t"], utc=True)
    # ThreatFox "recent" also re-lists old IOCs that were seen again; keep the timeline
    # inside the investigation window so a 2022 first-seen date is not drawn as a new event
    df = df[df["t"] >= df["t"].max() - pd.Timedelta(days=settings.WINDOW_DAYS)]
    df["day"] = df["t"].dt.strftime("%Y-%m-%d")
    top = df["family"].value_counts().head(8).index.tolist()
    df["fam_top"] = df["family"].where(df["family"].isin(top), "Other")
    daily = df.groupby(["day", "fam_top"]).size().unstack(fill_value=0).sort_index()
    totals = df.groupby("day").size()
    mu, sd = totals.mean(), totals.std() or 1
    bursts = [{"day": d, "count": int(v), "z": round((v - mu) / sd, 2)}
              for d, v in totals.items() if (v - mu) / sd >= settings.BURST_Z_THRESHOLD]
    # per-family bursts: a family's day counts as a burst if >= 2 sd above its own mean
    fam_bursts = []
    for f in top:
        s = df[df.family == f].groupby("day").size().reindex(totals.index, fill_value=0)
        m, v = s.mean(), s.std() or 1
        for d, c in s.items():
            if c >= 5 and (c - m) / v >= settings.BURST_Z_THRESHOLD:
                fam_bursts.append({"family": f, "day": d, "count": int(c), "z": round((c - m) / v, 2)})
    df["dow"] = df["t"].dt.dayofweek
    df["hour"] = df["t"].dt.hour
    matrix = df.groupby(["dow", "hour"]).size().unstack(fill_value=0).reindex(index=range(7), columns=range(24), fill_value=0)
    return {"days": daily.index.tolist(), "series": {c: daily[c].astype(int).tolist() for c in daily.columns},
            "totals": totals.astype(int).tolist(), "mean_per_day": round(mu, 1), "bursts": bursts,
            "family_bursts": sorted(fam_bursts, key=lambda b: -b["z"])[:20],
            "dow_hour": matrix.astype(int).values.tolist(), "events": len(df)}


# ------------------------------------------------------------------ geographic analytics
def geographic(g) -> dict:
    ipv4 = load_ipv4_by_country()
    ip_nodes = [(n, d) for n, d in g.nodes(data=True) if d["type"] == "ip" and d.get("country")]
    url_count, ip_count, points = Counter(), Counter(), []
    for n, d in ip_nodes:
        ip_count[d["country"]] += 1
        # URLs that sit on this IP, directly or through a resolving host
        urls = sum(1 for p in g.predecessors(n) if g.nodes[p]["type"] == "url")
        for p in g.predecessors(n):
            if g.nodes[p]["type"] == "host":
                urls += sum(1 for q in g.predecessors(p) if g.nodes[q]["type"] == "url")
        url_count[d["country"]] += max(urls, 1)
        points.append([round(d["lat"], 3), round(d["lon"], 3), 1])
    countries = []
    for cc in ip_count:
        space = ipv4.get(cc)
        countries.append({"cc": cc, "iso3": _iso3(cc), "name": (pycountry.countries.get(alpha_2=cc).name
                          if pycountry.countries.get(alpha_2=cc) else cc),
                          "urls": url_count[cc], "ips": ip_count[cc], "ipv4_space": space,
                          "ips_per_million_ipv4": round(ip_count[cc] / space * 1e6, 2) if space else None})
    asn = Counter((d.get("asn"), g.nodes.get(f"asn:{d.get('asn')}", {}).get("name")) for _, d in ip_nodes if d.get("asn"))
    hosting = Counter("hosting/datacenter" if d.get("hosting") else "residential/other" for _, d in ip_nodes)
    return {"countries": sorted(countries, key=lambda c: -c["ips"]), "points": points,
            "top_asns": [{"asn": a, "name": nm, "ips": c} for (a, nm), c in asn.most_common(15)],
            "hosting_split": dict(hosting), "located_ips": len(ip_nodes)}


def rank_comparison(countries) -> dict:
    """How much the 'top countries' story changes with the metric chosen (experiment B)."""
    eligible = [c for c in countries if c["ips_per_million_ipv4"] is not None and c["ips"] >= 5]
    by = {m: [c["cc"] for c in sorted(eligible, key=lambda c: -c[m])] for m in
          ("urls", "ips", "ips_per_million_ipv4")}
    def overlap(a, b, k=10):
        return len(set(by[a][:k]) & set(by[b][:k]))
    def spearman(a, b):
        ra = {cc: i for i, cc in enumerate(by[a])}
        rb = {cc: i for i, cc in enumerate(by[b])}
        n = len(ra)
        return round(1 - 6 * sum((ra[c] - rb[c]) ** 2 for c in ra) / (n * (n * n - 1)), 3) if n > 2 else None
    return {"countries_compared": len(eligible),
            "top10": {m: by[m][:10] for m in by},
            "top10_overlap_urls_vs_ips": overlap("urls", "ips"),
            "top10_overlap_ips_vs_normalised": overlap("ips", "ips_per_million_ipv4"),
            "spearman_urls_vs_ips": spearman("urls", "ips"),
            "spearman_ips_vs_normalised": spearman("ips", "ips_per_million_ipv4")}


# ------------------------------------------------------------------ social-network analysis
def social_network(g) -> dict:
    """Bipartite reporter <-> malware-family network, projected onto reporters
    (two reporters are linked when they report the same family)."""
    rep_fam = defaultdict(Counter)
    for n, d in g.nodes(data=True):
        if d["type"] not in ("url", "hash", "ip", "host"):
            continue
        reps = [g.nodes[t]["value"] for _, t, r in g.out_edges(n, data="rel") if r == "reported_by"]
        fams = correlator.families_of(g, n)
        for r in reps:
            for f in fams:
                rep_fam[r][f] += 1
    b = nx.Graph()
    for r, fams in rep_fam.items():
        for f, c in fams.items():
            b.add_edge(("R", r), ("F", f), weight=c)
    reps = [n for n in b if n[0] == "R"]
    proj = nx.bipartite.weighted_projected_graph(b, reps) if reps else nx.Graph()
    deg = nx.degree_centrality(proj) if len(proj) > 1 else {}
    btw = nx.betweenness_centrality(proj) if len(proj) > 2 else {}
    fam_cov = Counter({f: sum(1 for r in rep_fam if f in rep_fam[r]) for r2 in [0] for f in {f for c in rep_fam.values() for f in c}})
    single = sum(1 for f, c in fam_cov.items() if c == 1)
    top_reps = sorted(rep_fam, key=lambda r: -sum(rep_fam[r].values()))[:25]
    elements = []
    for r in top_reps:
        elements.append({"data": {"id": "R:" + r, "label": r, "kind": "reporter",
                                  "size": sum(rep_fam[r].values()), "degree": round(deg.get(("R", r), 0), 3)}})
    fams_shown = {f for r in top_reps for f, _ in rep_fam[r].most_common(6)}
    for f in fams_shown:
        elements.append({"data": {"id": "F:" + f, "label": f, "kind": "family", "size": fam_cov[f]}})
    for r in top_reps:
        for f, c in rep_fam[r].most_common(6):
            elements.append({"data": {"id": f"e:{r}:{f}", "source": "R:" + r, "target": "F:" + f, "weight": c}})
    totals = sorted((sum(c.values()) for c in rep_fam.values()), reverse=True)
    share_top5 = round(sum(totals[:5]) / sum(totals), 3) if totals else None
    return {"reporters": len(rep_fam), "families": len(fam_cov),
            "families_single_reporter": single, "share_top5_reporters": share_top5,
            "projection_density": round(nx.density(proj), 4) if len(proj) > 1 else None,
            "top_brokers": [{"reporter": n[1], "betweenness": round(v, 3)} for n, v in
                            sorted(btw.items(), key=lambda kv: -kv[1])[:5]],
            "elements": elements}


# ------------------------------------------------------------------ cross-source validation
def enrichment_agreement(g) -> dict:
    ips = [d for _, d in g.nodes(data=True) if d["type"] == "ip"]
    both_asn = [d for d in ips if d.get("asn") and d.get("cymru_asn")]
    both_cc = [d for d in ips if d.get("country") and d.get("registry_cc")]
    asn_ok = sum(d["asn"] == d["cymru_asn"] for d in both_asn)
    cc_ok = sum(d["country"] == d["registry_cc"] for d in both_cc)
    mism = Counter((d["country"], d["registry_cc"]) for d in both_cc if d["country"] != d["registry_cc"])
    return {"ips": len(ips), "geolocated": sum(1 for d in ips if d.get("country")),
            "asn_compared": len(both_asn), "asn_agree": asn_ok,
            "asn_agreement": round(asn_ok / len(both_asn), 4) if both_asn else None,
            "country_compared": len(both_cc), "country_agree": cc_ok,
            "country_agreement": round(cc_ok / len(both_cc), 4) if both_cc else None,
            "top_country_mismatches": [{"geo": a, "registry": b, "n": n} for (a, b), n in mism.most_common(8)]}


# ------------------------------------------------------------------ graph view for the browser
def cluster_view(g, cl, btw, community_of, hubs, max_nodes) -> dict:
    """Cytoscape elements for the largest clusters, capped so the view stays readable.
    Hub nodes are included only as faded, dashed 'suppressed' nodes on request."""
    elements, used = [], set()
    for c in cl:
        if len(used) + c["size"] > max_nodes:
            continue
        for n in c["nodes"]:
            used.add(n)
        if len(used) >= max_nodes:
            break
    for n in used:
        d = g.nodes[n]
        fams = sorted(correlator.families_of(g, n))
        elements.append({"data": {"id": n, "label": _short(d["value"]), "type": d["type"],
                                  "family": fams[0] if fams else "", "btw": round(btw.get(n, 0), 5),
                                  "community": community_of.get(n, -1),
                                  "cluster": next((c["id"] for c in cl if n in c["nodes"]), ""),
                                  "sources": ",".join(d.get("sources", []))}})
    for s, t, rel in g.edges(data="rel"):
        if s in used and t in used and rel in correlator.INFRA_RELS:
            elements.append({"data": {"id": f"{s}->{t}", "source": s, "target": t, "rel": rel}})
    return {"elements": elements, "clusters_shown": len({e["data"].get("cluster") for e in elements if "cluster" in e["data"]})}


def _short(v, n=38):
    return v if len(v) <= n else v[:n - 1] + "…"


# ------------------------------------------------------------------ orchestration
def run() -> dict:
    out = settings.PROCESSED_DIR
    out.mkdir(parents=True, exist_ok=True)
    g = correlator.load_graph()
    ig = correlator.infra_graph(g)
    hubs = correlator.detect_hubs(g, ig)
    log.info("graph: %d nodes, %d edges, %d hubs", g.number_of_nodes(), g.number_of_edges(), len(hubs))

    cl = correlator.clusters(g, ig, hubs)
    cl_raw = correlator.clusters(g, ig, {})          # experiment A: no hub suppression
    gm = graph_metrics(g, ig, hubs)
    btw, community_of = gm.pop("_btw"), gm.pop("_community")
    geo = geographic(g)
    summary = {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "graph": {"nodes": g.number_of_nodes(), "edges": g.number_of_edges(),
                  "by_type": dict(Counter(d["type"] for _, d in g.nodes(data=True))),
                  "by_relation": dict(Counter(r for _, _, r in g.edges(data="rel")))},
        "hubs": {"count": len(hubs), "reasons": dict(Counter(r if r.startswith("known") else "family threshold" for r in hubs.values())),
                 "examples": [{"id": h, "reason": r, "degree": ig.degree(h)} for h, r in
                              sorted(hubs.items(), key=lambda kv: -ig.degree(kv[0]))[:12]]},
        "experiment_hub_suppression": {"without": correlator.cluster_quality(g, cl_raw),
                                       "with": correlator.cluster_quality(g, cl)},
        "graph_metrics": gm,
        "cross_feed": correlator.cross_feed(g),
        "enrichment_agreement": enrichment_agreement(g),
        "geo_rank_comparison": rank_comparison(geo["countries"]),
    }
    tl = temporal(g)
    sna = social_network(g)
    summary["temporal"] = {k: tl[k] for k in ("mean_per_day", "bursts", "family_bursts", "events")}
    summary["sna"] = {k: v for k, v in sna.items() if k != "elements"}
    summary["clusters_top"] = [{k: c[k] for k in c if k != "nodes"} for c in cl[:25]]
    for c in cl:
        for n in c["nodes"]:
            g.nodes[n]["cluster"] = c["id"]

    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    (out / "clusters.json").write_text(json.dumps(cl, default=str))
    (out / "timeline.json").write_text(json.dumps(tl))
    (out / "geo.json").write_text(json.dumps(geo))
    (out / "sna.json").write_text(json.dumps(sna))
    (out / "graph_view.json").write_text(json.dumps(cluster_view(g, cl, btw, community_of, hubs,
                                                                 settings.GRAPH_VIEW_MAX_NODES)))
    (out / "hubs.json").write_text(json.dumps(hubs))
    (out / "node_metrics.json").write_text(json.dumps(
        {n: {"btw": round(v, 6), "community": community_of.get(n)} for n, v in btw.items() if v > 0}))
    log.info("analytics written to %s (%d clusters)", out, len(cl))
    return summary
