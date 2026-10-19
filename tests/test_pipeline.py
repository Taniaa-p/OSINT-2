"""Unit tests for normalisation, extraction, correlation safeguards and analytics helpers."""
import networkx as nx

from src.correlation import correlator
from src.extraction.entities import GraphBuilder, extract, extract_iocs, pseudonym
from src.preprocessing.normalizer import defang, normalise_all, normalise_record, refang, registered_domain


def raw(indicator, itype="url", source="urlhaus", rid="1", malware=None, tags=(), ts="2026-10-10 10:00:00"):
    return {"source": source, "record_id": rid, "indicator": indicator, "indicator_type": itype,
            "first_seen": ts, "last_seen": None, "threat_type": "malware_download", "malware": malware,
            "tags": list(tags), "confidence": 100, "status": "online", "reporter": "alice", "reference": None}


# ------------------------------------------------------------------ normalisation
def test_refang_and_defang_roundtrip():
    assert refang("hxxps://evil[.]com/a") == "https://evil.com/a"
    assert refang(defang("http://evil.com")) == "http://evil.com"


def test_url_is_split_into_host_port_and_registered_domain():
    r, why = normalise_record(raw("http://Login.Paypal-Secure.co.uk:8080/x"))
    assert why is None
    assert (r["host"], r["port"], r["reg_domain"], r["host_kind"]) == ("login.paypal-secure.co.uk", 8080, "paypal-secure.co.uk", "domain")


def test_ip_port_and_invalid_hosts():
    r, _ = normalise_record(raw("1.2.3.4:443", itype="ip:port", source="threatfox"))
    assert (r["host"], r["port"], r["host_kind"]) == ("1.2.3.4", 443, "ip")
    assert normalise_record(raw("http://not a host/"))[1] in ("invalid_host", "unparseable_url")


def test_bad_timestamp_rejected_and_duplicates_removed():
    recs = [raw("http://a.com/1"), raw("http://a.com/1", rid="2"), raw("http://b.com/", ts="garbage")]
    clean, rejected = normalise_all(recs, window_days=3650)
    assert len(clean) == 1 and rejected == {"duplicate": 1, "bad_timestamp": 1}


def test_registered_domain_uses_public_suffix_list():
    assert registered_domain("a.b.example.com.br") == "example.com.br"


# ------------------------------------------------------------------ extraction
def test_free_text_ioc_extraction_handles_defanged_indicators():
    text = "C2 at hxxp://bad[.]example[.]net/gate.php and 45.33.32[.]156; sample " + "a" * 64
    f = extract_iocs(text)
    assert "http://bad.example.net/gate.php" in f["url"]
    assert "45.33.32.156" in f["ip"]
    assert "a" * 64 in f["sha256"] and not f["md5"]
    assert "gate.php" not in f["domain"]


def test_extraction_builds_typed_edges_with_provenance():
    clean, _ = normalise_all([raw("http://x.evil.com/p", tags=["Mozi"])], window_days=3650)
    g = extract(clean)
    rels = {(e["src"].split(":")[0], e["rel"], e["dst"].split(":")[0], e["method"]) for e in g.edges}
    assert ("url", "hosted_on", "host", "feed") in rels
    assert ("host", "subdomain_of", "domain", "feed") in rels
    assert ("url", "associated_with", "malware", "tag-inferred") in rels
    assert all(e["source"] == "urlhaus" and e["record_id"] == "1" for e in g.edges)


def test_reporters_are_pseudonymised():
    assert pseudonym("alice").startswith("R-") and "alice" not in pseudonym("alice")


# ------------------------------------------------------------------ correlation safeguards
def _toy_graph(shared_platform):
    """Two unrelated families whose URLs both sit on the same host."""
    b = GraphBuilder()
    h = b.entity("host", "files.example.org", shared_platform=shared_platform)
    for fam, n in (("A", 3), ("B", 3)):
        m = b.entity("malware", fam)
        for i in range(n):
            u = b.entity("url", f"http://files.example.org/{fam}{i}")
            b.edge(u, h, "hosted_on")
            b.edge(u, m, "associated_with")
    g = nx.MultiDiGraph()
    for e in b.entities.values():
        g.add_node(e["id"], type=e["type"], value=e["value"], sources=[], **e["attrs"])
    for x in b.edges:
        g.add_edge(x["src"], x["dst"], rel=x["rel"])
    return g


def test_shared_platform_hub_is_not_used_as_pivot():
    g = _toy_graph(shared_platform=True)
    ig = correlator.infra_graph(g)
    hubs = correlator.detect_hubs(g, ig)
    assert "host:files.example.org" in hubs
    assert correlator.clusters(g, ig, hubs) == []          # no false campaign
    merged = correlator.clusters(g, ig, {})                # without the safeguard
    assert len(merged) == 1 and set(merged[0]["families"]) == {"A", "B"}


def test_family_threshold_hub_detection(monkeypatch):
    monkeypatch.setattr(correlator.settings, "HUB_FAMILY_THRESHOLD", 1)
    g = _toy_graph(shared_platform=None)
    hubs = correlator.detect_hubs(g, correlator.infra_graph(g))
    assert hubs["host:files.example.org"].startswith("shared by 2")
