"""Passive enrichment: DNS resolution, IP geolocation/ASN (ip-api.com) and an
independent IP-to-ASN/registry-country lookup (Team Cymru DNS service).

Two independent sources for ASN and country let the validation phase measure how
far they agree, instead of trusting a single geolocation provider.
Results are cached in SQLite and exported to the snapshot, so the analysis can be
re-run offline. Any service failure leaves those fields empty; nothing aborts.
"""
import gzip
import json
import time
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver
import requests

from config import settings
from src.storage import database
from src.utils.logger import get_logger

log = get_logger("enrichment")
SNAPSHOT_CACHE = settings.SNAPSHOT_DIR / "enrichment_cache.json.gz"


def _resolver():
    r = dns.resolver.Resolver()
    r.lifetime = r.timeout = settings.DNS_TIMEOUT
    return r


def resolve_a(host: str):
    try:
        return {"a": sorted({rr.to_text() for rr in _resolver().resolve(host, "A")})}
    except dns.resolver.NXDOMAIN:
        return {"a": [], "status": "NXDOMAIN"}
    except (dns.exception.DNSException, Exception) as exc:
        return {"a": [], "status": type(exc).__name__}


_RDAP_BOOTSTRAP = {}


def _rdap_base(domain: str) -> str:
    """Registry RDAP server for the domain's TLD, from the IANA bootstrap file (RFC 9224).
    Querying registries directly avoids the shared rate limit of public redirectors."""
    if not _RDAP_BOOTSTRAP:
        try:
            for tlds, urls in requests.get(settings.RDAP_BOOTSTRAP_URL, timeout=30).json()["services"]:
                for t in tlds:
                    _RDAP_BOOTSTRAP[t] = urls[0].rstrip("/") + "/"
        except requests.RequestException:
            pass
    return _RDAP_BOOTSTRAP.get(domain.rsplit(".", 1)[-1], settings.RDAP_URL.rsplit("domain/", 1)[0])


def rdap_lookup(domain: str):
    """WHOIS data via RDAP (RFC 9083, the JSON successor of WHOIS): registration date
    and registrar only. Registrant contact data is deliberately not stored."""
    try:
        r = requests.get(_rdap_base(domain) + "domain/" + domain, timeout=15,
                         headers={"User-Agent": settings.USER_AGENT, "Accept": "application/rdap+json"})
        if r.status_code != 200:
            return {"status": f"HTTP {r.status_code}"}
        d = r.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
        registrar = next((v[3] for ent in d.get("entities", []) if "registrar" in ent.get("roles", [])
                          for v in ent.get("vcardArray", [None, []])[1] if v and v[0] == "fn"), None)
        return {"registered": events.get("registration"), "expires": events.get("expiration"),
                "registrar": registrar}
    except Exception as exc:
        return {"status": type(exc).__name__}


def cymru_lookup(ip: str):
    """'15169 | 8.8.8.0/24 | US | arin | 2023-12-28' -> asn, prefix, registry country."""
    try:
        q = ".".join(reversed(ip.split("."))) + "." + settings.CYMRU_ORIGIN_ZONE
        txt = _resolver().resolve(q, "TXT")[0].to_text().strip('"')
        asn, prefix, cc, registry, _ = [p.strip() for p in txt.split("|")]
        return {"asn": asn.split()[0], "prefix": prefix, "cc": cc, "registry": registry}
    except Exception as exc:
        return {"status": type(exc).__name__}


def ipapi_batch(ips: list) -> dict:
    """ip-api.com batch endpoint, 100 IPs per call, respecting the X-Rl / X-Ttl headers."""
    out, interval = {}, 60.0 / settings.IPAPI_REQUESTS_PER_MIN
    for i in range(0, len(ips), settings.IPAPI_BATCH_SIZE):
        chunk = ips[i:i + settings.IPAPI_BATCH_SIZE]
        try:
            r = requests.post(f"{settings.IPAPI_BATCH_URL}?fields={settings.IPAPI_FIELDS}",
                              json=chunk, timeout=settings.HTTP_TIMEOUT)
            if r.status_code == 429:
                time.sleep(int(r.headers.get("X-Ttl", 60)) + 1)
                continue
            r.raise_for_status()
            for item in r.json():
                out[item.get("query")] = item
            if r.headers.get("X-Rl") == "0":
                time.sleep(int(r.headers.get("X-Ttl", 60)) + 1)
            else:
                time.sleep(interval)
        except requests.RequestException as exc:
            log.warning("ip-api batch %d failed: %s", i // settings.IPAPI_BATCH_SIZE, exc)
        log.info("ip-api: %d/%d", min(i + settings.IPAPI_BATCH_SIZE, len(ips)), len(ips))
    return out


def _threaded(fn, keys):
    with ThreadPoolExecutor(settings.DNS_WORKERS) as pool:
        return dict(zip(keys, pool.map(fn, keys)))


def enrich(con, records: list) -> dict:
    """Fill the cache for every host/IP in the records that is not cached yet."""
    hosts = sorted({r["host"] for r in records if r["host_kind"] == "domain"
                    and not _shared(r["reg_domain"] or r["host"])})
    stats = {}
    cached = database.cache_get(con, "dns", hosts)
    todo = [h for h in hosts if h not in cached]
    if todo and not settings.OFFLINE:
        log.info("DNS: resolving %d hosts", len(todo))
        database.cache_put(con, "dns", _threaded(resolve_a, todo))
        con.commit()
    dns_res = database.cache_get(con, "dns", hosts)
    stats["dns_hosts"] = len(hosts)
    stats["dns_resolved"] = sum(bool(v.get("a")) for v in dns_res.values())

    domains = sorted({r["reg_domain"] for r in records if r["reg_domain"] and not _shared(r["reg_domain"])})
    cached = database.cache_get(con, "rdap", domains)
    todo = [d for d in domains if d not in cached or cached[d].get("status") == "HTTP 429"]
    if todo and not settings.OFFLINE:
        _rdap_base("example.com")  # load the bootstrap once before the threads start
        log.info("RDAP/WHOIS: looking up %d registered domains", len(todo))
        with ThreadPoolExecutor(8) as pool:
            database.cache_put(con, "rdap", dict(zip(todo, pool.map(rdap_lookup, todo))))
        con.commit()
    stats["rdap_domains"] = len(domains)

    ips = sorted({r["host"] for r in records if r["host_kind"] == "ip" and ":" not in r["host"]}
                 | {ip for v in dns_res.values() for ip in v.get("a", [])})
    for kind, fn in (("cymru", None), ("geo", None)):
        cached = database.cache_get(con, kind, ips)
        todo = [ip for ip in ips if ip not in cached]
        if todo and not settings.OFFLINE:
            log.info("%s: looking up %d IPs", kind, len(todo))
            res = _threaded(cymru_lookup, todo) if kind == "cymru" else ipapi_batch(todo)
            database.cache_put(con, kind, res)
            con.commit()
    stats["ips"] = len(ips)
    return stats


def apply(con, builder, records: list):
    """Add enrichment entities/edges (resolves_to, in_asn, located_in) to the graph."""
    hosts = {r["host"] for r in records if r["host_kind"] == "domain"}
    dns_res = database.cache_get(con, "dns", hosts)
    for host, v in dns_res.items():
        hid = f"host:{host}"
        if hid not in builder.entities:
            continue
        builder.entities[hid]["attrs"]["dns_status"] = v.get("status", "resolved")
        for ip in v.get("a", []):
            iid = builder.entity("ip", ip)
            builder.entities[iid]["attrs"]["via_dns"] = True
            builder.edge(hid, iid, "resolves_to", method="dns", confidence=90)

    regs = {r["reg_domain"] for r in records if r["reg_domain"]}
    for dom, v in database.cache_get(con, "rdap", regs).items():
        eid = f"domain:{dom}" if f"domain:{dom}" in builder.entities else f"host:{dom}"
        if eid in builder.entities and v.get("registered"):
            builder.entities[eid]["attrs"].update(registered=v["registered"][:10], registrar=v.get("registrar"))

    ips = [e["value"] for e in builder.entities.values() if e["type"] == "ip"]
    geo = database.cache_get(con, "geo", ips)
    cym = database.cache_get(con, "cymru", ips)
    for ip in ips:
        iid, g, c = f"ip:{ip}", geo.get(ip, {}), cym.get(ip, {})
        attrs = builder.entities[iid]["attrs"]
        if g.get("status") == "success":
            attrs.update(lat=g["lat"], lon=g["lon"], city=g.get("city"), country=g.get("countryCode"),
                         isp=g.get("isp"), org=g.get("org"), hosting=g.get("hosting"))
            if g.get("countryCode"):
                cid = builder.entity("country", g["countryCode"], name=g.get("country"))
                builder.edge(iid, cid, "located_in", method="geo:ip-api", confidence=70)
            asn = (g.get("as") or "").split(" ")[0].lstrip("AS")
            if asn.isdigit():
                aid = builder.entity("asn", f"AS{asn}", name=g.get("asname") or g.get("isp"))
                builder.edge(iid, aid, "in_asn", method="geo:ip-api", confidence=80)
                attrs["asn"] = f"AS{asn}"
        if c.get("asn"):
            attrs.update(cymru_asn=f"AS{c['asn']}", registry_cc=c.get("cc"), prefix=c.get("prefix"))


def export_cache(con):
    rows = [dict(r) for r in con.execute("SELECT * FROM enrichment")]
    with gzip.open(SNAPSHOT_CACHE, "wt", encoding="utf-8") as f:
        json.dump(rows, f)
    log.info("exported %d enrichment results to snapshot", len(rows))


def import_cache(con):
    if not SNAPSHOT_CACHE.exists():
        return
    with gzip.open(SNAPSHOT_CACHE, "rt", encoding="utf-8") as f:
        rows = json.load(f)
    con.executemany("INSERT OR REPLACE INTO enrichment VALUES (?,?,?,?)",
                    [(r["kind"], r["key"], r["payload"], r["retrieved_at"]) for r in rows])
    log.info("imported %d enrichment results from snapshot", len(rows))


def _shared(domain):
    return any(domain == d or domain.endswith("." + d) for d in settings.SHARED_PLATFORM_DOMAINS)
