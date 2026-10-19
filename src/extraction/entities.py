"""Entity and relationship extraction (requirement F4).

Turns normalised records into typed entities and typed, provenance-labelled edges.
Entity ids are "<type>:<value>" so the same entity reported by different feeds
merges automatically. That merge is what cross-feed correlation is built on.

Entity types : url, host, domain, ip, hash, malware, reporter (pseudonymised)
Enrichment   : asn, country (added later by src/enrichment)
Every edge   : src, dst, rel, source, record_id, first_seen, confidence, method
"""
import hashlib
import re

from config import settings

# Free-text IOC patterns (accept defanged forms).
_DOT = r"(?:\.|\[\.\]|\(\.\))"
IOC_PATTERNS = {
    "url": re.compile(r"\b(?:hxxps?|https?)(?:://|\[://\])[^\s\"'<>]+", re.I),
    "ip": re.compile(rf"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d){_DOT}){{3}}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "domain": re.compile(rf"\b(?:[a-z0-9-]{{1,63}}{_DOT})+[a-z]{{2,24}}\b", re.I),
}
_FILE_EXT = {"exe", "dll", "zip", "jar", "sh", "bin", "js", "ps1", "txt", "php", "html", "htm", "png", "jpg"}


def pseudonym(handle: str) -> str:
    """Stable pseudonym for a reporter handle (data minimisation)."""
    if not settings.PSEUDONYMISE_REPORTERS:
        return handle
    return "R-" + hashlib.sha256(handle.encode()).hexdigest()[:6]


def extract_iocs(text: str) -> dict:
    """Extract IOCs from unstructured text (threat reports, e-mails, chat logs)."""
    from src.preprocessing.normalizer import refang, host_kind
    found = {k: set() for k in IOC_PATTERNS}
    for kind, pat in IOC_PATTERNS.items():
        for m in pat.findall(text):
            v = refang(m).rstrip(".,);]").lower()
            if kind == "domain":
                if v.rsplit(".", 1)[-1] in _FILE_EXT or host_kind(v) != "domain":
                    continue
            found[kind].add(v)
    found["md5"] -= {h[:32] for h in found["sha256"]}
    # domains that are only the host part of an extracted URL are still useful pivots
    return {k: sorted(v) for k, v in found.items()}


def build_family_vocabulary(records: list) -> dict:
    """Malware family names as ThreatFox labels them, used to map URLhaus tags
    (e.g. 'mirai', 'Mozi') to the same family entity. Matching is case-insensitive."""
    vocab = {}
    for r in records:
        if r["malware"]:
            vocab.setdefault(r["malware"].lower(), r["malware"])
    for name in ("Mozi", "Mirai", "SmartLoader", "Stealc", "Gafgyt", "AsyncRAT", "Vidar",
                 "AgentTesla", "Formbook", "Remcos", "LummaStealer", "Amadey", "Emotet", "QakBot"):
        vocab.setdefault(name.lower(), name)
    return vocab


class GraphBuilder:
    def __init__(self):
        self.entities = {}   # id -> dict(type, value, first_seen, last_seen, sources set, attrs)
        self.edges = []

    def entity(self, etype, value, rec=None, **attrs):
        eid = f"{etype}:{value}"
        e = self.entities.get(eid)
        if e is None:
            e = self.entities[eid] = {"id": eid, "type": etype, "value": value, "first_seen": None,
                                      "last_seen": None, "sources": set(), "records": 0, "attrs": {}}
        if rec:
            ts = rec["first_seen"]
            e["first_seen"] = min(filter(None, [e["first_seen"], ts]), default=None)
            e["last_seen"] = max(filter(None, [e["last_seen"], rec.get("last_seen") or ts]), default=None)
            e["sources"].add(rec["source"])
            e["records"] += 1
        e["attrs"].update({k: v for k, v in attrs.items() if v is not None})
        return eid

    def edge(self, src, dst, rel, rec=None, method="feed", confidence=None):
        self.edges.append({"src": src, "dst": dst, "rel": rel,
                           "source": rec["source"] if rec else method,
                           "record_id": rec["record_id"] if rec else None,
                           "first_seen": rec["first_seen"] if rec else None,
                           "confidence": confidence if confidence is not None else (rec or {}).get("confidence"),
                           "method": method})


def extract(records: list) -> GraphBuilder:
    vocab = build_family_vocabulary(records)
    g = GraphBuilder()
    for r in records:
        threat = r.get("threat_type")
        if r["hash"]:
            anchor = g.entity("hash", r["hash"], r)
        else:
            host = g.entity("ip" if r["host_kind"] == "ip" else "host", r["host"], r,
                            shared_platform=_is_shared(r["reg_domain"] or r["host"]))
            anchor = host
            if r["url"]:
                anchor = g.entity("url", r["url"], r, status=r["status"], threat=threat,
                                  observation_time=r.get("time_is_observation"))
                g.edge(anchor, host, "hosted_on", r)
            if r["host_kind"] == "domain" and r["reg_domain"] and r["reg_domain"] != r["host"]:
                dom = g.entity("domain", r["reg_domain"], r, shared_platform=_is_shared(r["reg_domain"]))
                g.edge(host, dom, "subdomain_of", r)
            elif r["host_kind"] == "domain":
                g.entities[host]["attrs"]["is_registered_domain"] = True
            if r["port"]:
                g.entities[host]["attrs"].setdefault("ports", [])
                if r["port"] not in g.entities[host]["attrs"]["ports"]:
                    g.entities[host]["attrs"]["ports"].append(r["port"])
        g.entities[anchor]["attrs"].setdefault("threat_types", [])
        if threat and threat not in g.entities[anchor]["attrs"]["threat_types"]:
            g.entities[anchor]["attrs"]["threat_types"].append(threat)

        # malware attribution: explicit (ThreatFox) or inferred from tags (URLhaus)
        families = []
        if r["malware"]:
            families.append((r["malware"], "feed", r.get("confidence") or 75))
        for t in r["tags"]:
            fam = vocab.get(t.lower())
            if fam and fam not in [f for f, _, _ in families]:
                families.append((fam, "tag-inferred", 50))
        if r["source"] == "openphish":
            families.append(("Phishing (unattributed)", "feed", 75))
        for fam, method, conf in families:
            m = g.entity("malware", fam, r)
            g.edge(anchor, m, "associated_with", r, method=method, confidence=conf)

        if r["reporter"]:
            rep = g.entity("reporter", pseudonym(r["reporter"]), r)
            g.edge(anchor, rep, "reported_by", r)
    return g


def _is_shared(domain):
    if not domain:
        return None
    return any(domain == d or domain.endswith("." + d) for d in settings.SHARED_PLATFORM_DOMAINS) or None
