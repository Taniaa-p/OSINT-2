"""IPv4 address space delegated to each country (NRO combined RIR statistics).

Used as the denominator for geographic normalisation. A country with a lot of address
space naturally hosts more of *everything*, malicious or not, so raw counts alone
mostly reflect size.
File format (pipe-separated): registry|cc|type|start|value|date|status|...
"""
import csv
from collections import defaultdict

from config import settings
from src.acquisition.downloader import fetch
from src.utils.logger import get_logger

log = get_logger("rir")

OUTPUT = settings.SNAPSHOT_DIR / "ipv4_by_country.csv"


def build_ipv4_by_country() -> dict:
    """Download the NRO file (~57 MB, not kept) and store a small per-country summary."""
    if OUTPUT.exists():
        return load_ipv4_by_country()
    if settings.OFFLINE:
        log.warning("offline and no IPv4 summary present - normalisation disabled")
        return {}
    tmp = settings.RAW_DIR / "nro-delegated-stats"
    settings.RAW_DIR.mkdir(parents=True, exist_ok=True)
    if not fetch(settings.NRO_STATS_URL, tmp):
        log.warning("NRO statistics unavailable - normalisation disabled")
        return {}
    totals = defaultdict(int)
    with open(tmp, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) < 7 or parts[2] != "ipv4" or parts[1] in ("", "*", "ZZ"):
                continue
            if parts[6] in ("allocated", "assigned"):
                totals[parts[1].upper()] += int(parts[4])
    settings.SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["country_code", "ipv4_addresses"])
        for cc, n in sorted(totals.items(), key=lambda kv: -kv[1]):
            w.writerow([cc, n])
    tmp.unlink(missing_ok=True)
    log.info("IPv4 space summarised for %d countries", len(totals))
    return dict(totals)


def load_ipv4_by_country() -> dict:
    if not OUTPUT.exists():
        return {}
    with open(OUTPUT) as f:
        return {r["country_code"]: int(r["ipv4_addresses"]) for r in csv.DictReader(f)}
