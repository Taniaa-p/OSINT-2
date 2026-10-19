"""Cleaning and normalisation of raw feed records (requirement F3).

Steps applied to every record:
  1. refang  (hxxp -> http, [.] -> .)
  2. parse   URL -> scheme, host, port, path; "ip:port" -> ip, port
  3. validate host as IPv4/IPv6 or a syntactically valid domain
  4. lower-case hosts, derive the registered domain (tldextract, bundled suffix list)
  5. timestamps -> ISO-8601 UTC
  6. time-window filter and de-duplication on (source, indicator)
Rejected records are counted by reason so data quality can be reported.
"""
import ipaddress
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import tldextract

from src.utils.logger import get_logger

log = get_logger("normalizer")

# Bundled public-suffix snapshot: offline, deterministic results.
_tld = tldextract.TLDExtract(suffix_list_urls=())
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,63}$")
HASH_TYPES = {"md5_hash", "sha1_hash", "sha256_hash"}


def refang(s: str) -> str:
    s = s.strip()
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    return s.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def defang(s: str) -> str:
    """For human-facing reports: make indicators non-clickable."""
    return s.replace("http", "hxxp", 1).replace(".", "[.]")


def host_kind(host: str):
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "domain" if DOMAIN_RE.match(host) else None


def registered_domain(host: str):
    ext = _tld(host)
    return ext.top_domain_under_public_suffix if ext.suffix and ext.domain else None


def to_utc(ts):
    if not ts:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(ts[:19], fmt).replace(tzinfo=timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            continue
    return None


def normalise_record(r: dict):
    """Return (clean_record, None) or (None, rejection_reason)."""
    ind = refang(r["indicator"] or "")
    itype = r["indicator_type"]
    out = dict(r, indicator=ind, first_seen=to_utc(r["first_seen"]), last_seen=to_utc(r["last_seen"]),
               host=None, host_kind=None, port=None, reg_domain=None, url=None, hash=None)
    if not out["first_seen"]:
        return None, "bad_timestamp"

    if itype in HASH_TYPES:
        if not re.fullmatch(r"[0-9a-fA-F]{32,64}", ind):
            return None, "bad_hash"
        out["hash"] = ind.lower()
        return out, None
    if itype == "url":
        if "://" not in ind:
            ind = "http://" + ind
        try:
            parts = urlsplit(ind)
            host, port = (parts.hostname or ""), parts.port
        except ValueError:
            return None, "unparseable_url"
        out["url"] = ind
    elif itype == "ip:port":
        host, _, port = ind.rpartition(":")
        port = int(port) if port.isdigit() else None
    elif itype == "domain":
        host, port = ind, None
    else:
        return None, "unsupported_type"

    host = host.lower().strip(".")
    kind = host_kind(host)
    if not kind:
        return None, "invalid_host"
    out.update(host=host, host_kind=kind, port=port,
               reg_domain=registered_domain(host) if kind == "domain" else None)
    return out, None


def normalise_all(records: list, window_days: int, now=None):
    now = now or datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=window_days)).isoformat(timespec="seconds")
    rejected, seen, clean = Counter(), set(), []
    for r in records:
        rec, why = normalise_record(r)
        if why:
            rejected[why] += 1
            continue
        if max(rec["first_seen"], rec["last_seen"] or "") < cutoff:
            rejected["outside_window"] += 1
            continue
        key = (rec["source"], rec["url"] or rec["host"] or rec["hash"])
        if key in seen:
            rejected["duplicate"] += 1
            continue
        seen.add(key)
        clean.append(rec)
    log.info("normalised %d records, rejected %s", len(clean), dict(rejected))
    return clean, dict(rejected)
