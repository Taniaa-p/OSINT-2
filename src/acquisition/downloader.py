"""Reproducible download of open sources with a chain-of-custody manifest.

Every file is stored with the URL it came from, the UTC retrieval time, its size and
its SHA-256 hash, so any number in the report can be traced back to an exact
download.
"""
import gzip
import hashlib
import json
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from config import settings
from src.utils.logger import get_logger

log = get_logger("acquisition")

MANIFEST = "manifest.json"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, dest: Path, retries: int = 3) -> bool:
    """Stream a URL to disk. Retries transient errors with exponential backoff."""
    for attempt in range(1, retries + 1):
        try:
            with requests.get(url, stream=True, timeout=settings.HTTP_TIMEOUT,
                              headers={"User-Agent": settings.USER_AGENT}) as r:
                r.raise_for_status()
                with open(dest, "wb") as f:
                    for chunk in r.iter_content(1 << 16):
                        f.write(chunk)
            return True
        except requests.RequestException as exc:
            log.warning("download %s failed (attempt %d/%d): %s", url, attempt, retries, exc)
            time.sleep(2 ** attempt)
    return False


def collect_feeds() -> dict:
    """Download every configured feed into data/raw/ and write the manifest.

    A failed feed is recorded as failed and the others continue (requirement F2).
    """
    settings.RAW_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {"collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "sources": {}}
    for name, feed in settings.FEEDS.items():
        dest = settings.RAW_DIR / feed["file"]
        log.info("collecting %s from %s", name, feed["url"])
        ok = fetch(feed["url"], dest)
        entry = {"url": feed["url"], "file": feed["file"], "licence": feed["licence"],
                 "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "status": "ok" if ok else "failed"}
        if ok:
            entry.update(bytes=dest.stat().st_size, sha256=sha256_of(dest))
            log.info("  %s: %d bytes sha256=%s", name, entry["bytes"], entry["sha256"][:16])
        manifest["sources"][name] = entry
    (settings.RAW_DIR / MANIFEST).write_text(json.dumps(manifest, indent=2))
    return manifest


def freeze_snapshot() -> None:
    """Copy the raw downloads into data/snapshot/ (gzip) so the analysis is reproducible.

    The files are compressed, which also keeps the live malicious URLs from being
    clickable or indexed as plain text in the repository.
    """
    settings.SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((settings.RAW_DIR / MANIFEST).read_text())
    for name, entry in manifest["sources"].items():
        if entry["status"] != "ok":
            continue
        src = settings.RAW_DIR / entry["file"]
        with open(src, "rb") as fi, gzip.open(settings.SNAPSHOT_DIR / (entry["file"] + ".gz"), "wb") as fo:
            shutil.copyfileobj(fi, fo)
    (settings.SNAPSHOT_DIR / MANIFEST).write_text(json.dumps(manifest, indent=2))
    log.info("snapshot frozen in %s", settings.SNAPSHOT_DIR)


def restore_snapshot() -> dict:
    """Offline mode: unpack the committed snapshot into data/raw/ and verify hashes."""
    settings.RAW_DIR.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((settings.SNAPSHOT_DIR / MANIFEST).read_text())
    for name, entry in manifest["sources"].items():
        if entry["status"] != "ok":
            continue
        dest = settings.RAW_DIR / entry["file"]
        with gzip.open(settings.SNAPSHOT_DIR / (entry["file"] + ".gz"), "rb") as fi, open(dest, "wb") as fo:
            shutil.copyfileobj(fi, fo)
        verified = sha256_of(dest) == entry["sha256"]
        log.info("restored %s (hash %s)", name, "verified" if verified else "MISMATCH")
        if not verified:
            raise RuntimeError(f"snapshot integrity check failed for {name}")
    (settings.RAW_DIR / MANIFEST).write_text(json.dumps(manifest, indent=2))
    return manifest
