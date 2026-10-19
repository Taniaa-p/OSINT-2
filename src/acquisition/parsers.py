"""Parse each feed's native format into one common raw-record shape.

Common shape (one dict per record):
    source, record_id, indicator, indicator_type, first_seen, last_seen,
    threat_type, malware, tags (list), confidence, status, reporter, reference
Cleaning and validation happen later in src/preprocessing; the parsers only read
the files faithfully and never drop data silently.
"""
import csv
import io
from pathlib import Path

from src.utils.logger import get_logger

log = get_logger("parsers")

URLHAUS_COLS = ["id", "dateadded", "url", "url_status", "last_online", "threat",
                "tags", "urlhaus_link", "reporter"]
THREATFOX_COLS = ["first_seen_utc", "ioc_id", "ioc_value", "ioc_type", "threat_type",
                  "fk_malware", "malware_alias", "malware_printable", "last_seen_utc",
                  "confidence_level", "is_compromised", "reference", "tags",
                  "anonymous", "reporter"]


def _none(v):
    v = (v or "").strip()
    return None if v in ("", "None", "null") else v


def _csv_rows(path: Path, columns):
    """abuse.ch CSVs start with '#' comment lines; the header itself is commented out."""
    text = path.read_text(encoding="utf-8", errors="replace")
    body = "\n".join(line for line in text.splitlines() if line and not line.startswith("#"))
    for row in csv.reader(io.StringIO(body), skipinitialspace=True):
        if len(row) != len(columns):
            log.warning("%s: skipping malformed row with %d fields", path.name, len(row))
            continue
        yield dict(zip(columns, row))


def parse_urlhaus(path: Path) -> list:
    out = []
    for r in _csv_rows(path, URLHAUS_COLS):
        tags = [t.strip() for t in (_none(r["tags"]) or "").split(",") if t.strip()]
        out.append({
            "source": "urlhaus", "record_id": r["id"], "indicator": r["url"],
            "indicator_type": "url", "first_seen": _none(r["dateadded"]),
            "last_seen": _none(r["last_online"]), "threat_type": _none(r["threat"]),
            "malware": None, "tags": tags, "confidence": None,
            "status": _none(r["url_status"]), "reporter": _none(r["reporter"]),
            "reference": _none(r["urlhaus_link"]),
        })
    return out


def parse_threatfox(path: Path) -> list:
    out = []
    for r in _csv_rows(path, THREATFOX_COLS):
        tags = [t.strip() for t in (_none(r["tags"]) or "").split(",") if t.strip()]
        conf = _none(r["confidence_level"])
        malware = _none(r["malware_printable"])
        out.append({
            "source": "threatfox", "record_id": r["ioc_id"], "indicator": r["ioc_value"],
            "indicator_type": r["ioc_type"], "first_seen": _none(r["first_seen_utc"]),
            "last_seen": _none(r["last_seen_utc"]), "threat_type": _none(r["threat_type"]),
            "malware": None if malware in (None, "Unknown malware") else malware,
            "tags": tags, "confidence": int(conf) if conf and conf.isdigit() else None,
            "status": None, "reporter": None if r["anonymous"] == "1" else _none(r["reporter"]),
            "reference": _none(r["reference"]),
        })
    return out


def parse_openphish(path: Path, retrieved_at: str) -> list:
    """OpenPhish's free feed is a plain URL list with no timestamps, so the retrieval
    time is used and labelled as an *observation* time, not a first-seen time."""
    out = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines()):
        url = line.strip()
        if not url:
            continue
        out.append({
            "source": "openphish", "record_id": f"op-{i}", "indicator": url,
            "indicator_type": "url", "first_seen": retrieved_at.replace("T", " ")[:19],
            "last_seen": None, "threat_type": "phishing", "malware": None, "tags": [],
            "confidence": None, "status": "online", "reporter": None, "reference": None,
            "time_is_observation": True,
        })
    return out


def parse_all(raw_dir: Path, manifest: dict) -> list:
    """Parse every successfully collected feed. A missing feed is logged, not fatal."""
    records = []
    src = manifest["sources"]
    jobs = {
        "urlhaus": lambda p: parse_urlhaus(p),
        "threatfox": lambda p: parse_threatfox(p),
        "openphish": lambda p: parse_openphish(p, src["openphish"]["retrieved_at"]),
    }
    for name, parser in jobs.items():
        entry = src.get(name)
        if not entry or entry["status"] != "ok":
            log.warning("source %s unavailable - continuing without it", name)
            continue
        try:
            rows = parser(raw_dir / entry["file"])
            log.info("parsed %d records from %s", len(rows), name)
            records.extend(rows)
        except Exception as exc:  # isolate one bad feed from the rest
            log.error("parser for %s failed: %s", name, exc)
    return records
