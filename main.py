"""Command-line entry point for the Visualization-Based OSINT Intelligence Platform.

Usage:
    python main.py check          # verify environment and connectivity
    python main.py collect        # download feeds (or restore snapshot when OFFLINE=1)
    python main.py collect --freeze   # also freeze the download as the committed snapshot
    python main.py process        # clean, normalise, extract entities, store in SQLite
    python main.py enrich         # DNS / geolocation / ASN enrichment, then rebuild the graph
"""
import argparse
import sys

from config import settings
from src.utils.logger import get_logger

log = get_logger("main")


def cmd_check(_args) -> int:
    """Verify Python version, folders and reachability of every open source."""
    import requests

    log.info("Python %s", sys.version.split()[0])
    for d in (settings.RAW_DIR, settings.SNAPSHOT_DIR, settings.PROCESSED_DIR, settings.REPORTS_DIR):
        d.mkdir(parents=True, exist_ok=True)
    if settings.OFFLINE:
        log.info("OFFLINE=1: skipping connectivity checks")
        return 0
    ok = True
    targets = {name: feed["url"] for name, feed in settings.FEEDS.items()}
    targets["ip-api"] = "http://ip-api.com/json/8.8.8.8"
    for name, url in targets.items():
        try:
            r = requests.head(url, timeout=15, allow_redirects=True,
                              headers={"User-Agent": settings.USER_AGENT})
            log.info("%-10s %s -> HTTP %s", name, url, r.status_code)
            ok &= r.status_code < 400
        except requests.RequestException as exc:
            log.warning("%-10s unreachable: %s", name, exc)
            ok = False
    return 0 if ok else 1


def cmd_collect(args) -> int:
    """Phase 2: acquire the open-source dataset with a chain-of-custody manifest."""
    from src.acquisition import downloader, parsers, rir_stats

    if settings.OFFLINE:
        manifest = downloader.restore_snapshot()
    else:
        manifest = downloader.collect_feeds()
        if args.freeze:
            downloader.freeze_snapshot()
    rir_stats.build_ipv4_by_country()
    records = parsers.parse_all(settings.RAW_DIR, manifest)
    log.info("collection complete: %d raw records from %d sources",
             len(records), sum(e["status"] == "ok" for e in manifest["sources"].values()))
    return 0


def build_graph(enrich_first: bool = False) -> dict:
    """Normalise -> extract -> (enrich) -> store. Shared by process and enrich."""
    import json
    from src.acquisition import parsers
    from src.enrichment import enrichers
    from src.extraction.entities import extract
    from src.preprocessing.normalizer import normalise_all
    from src.storage import database

    manifest = json.loads((settings.RAW_DIR / "manifest.json").read_text())
    raw = parsers.parse_all(settings.RAW_DIR, manifest)
    records, rejected = normalise_all(raw, settings.WINDOW_DAYS)
    with database.connect() as con:
        if settings.OFFLINE:
            enrichers.import_cache(con)
        stats = enrichers.enrich(con, records) if enrich_first else {}
        builder = extract(records)
        enrichers.apply(con, builder, records)
        database.save_records(con, records)
        database.save_graph(con, builder.entities, builder.edges)
        if enrich_first and not settings.OFFLINE:
            enrichers.export_cache(con)
        summary = {"raw": len(raw), "clean": len(records), "rejected": rejected,
                   "entities": len(builder.entities), "edges": len(builder.edges), **stats}
        database.log_run(con, "process", summary)
    log.info("graph stored: %s", summary)
    return summary


def cmd_process(_args) -> int:
    build_graph(enrich_first=False)
    return 0


def cmd_enrich(_args) -> int:
    build_graph(enrich_first=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Visualization-Based OSINT Intelligence Platform")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="verify environment and source connectivity").set_defaults(func=cmd_check)
    c = sub.add_parser("collect", help="download the open-source feeds")
    c.add_argument("--freeze", action="store_true", help="freeze this download as data/snapshot/")
    c.set_defaults(func=cmd_collect)
    sub.add_parser("process", help="normalise and extract entities").set_defaults(func=cmd_process)
    sub.add_parser("enrich", help="enrich with DNS/geo/ASN and rebuild").set_defaults(func=cmd_enrich)
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    sys.exit(args.func(args))
