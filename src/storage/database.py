"""SQLite persistence: normalised records, entities, relationships, enrichment cache
and run metadata (auditability)."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    source TEXT, record_id TEXT, indicator TEXT, indicator_type TEXT, host TEXT,
    host_kind TEXT, reg_domain TEXT, port INTEGER, url TEXT, hash TEXT,
    first_seen TEXT, last_seen TEXT, threat_type TEXT, malware TEXT, tags TEXT,
    confidence INTEGER, status TEXT, reporter TEXT, reference TEXT,
    PRIMARY KEY (source, record_id));
CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY, type TEXT, value TEXT, first_seen TEXT, last_seen TEXT,
    sources TEXT, records INTEGER, attrs TEXT);
CREATE TABLE IF NOT EXISTS edges (
    src TEXT, dst TEXT, rel TEXT, source TEXT, record_id TEXT, first_seen TEXT,
    confidence INTEGER, method TEXT);
CREATE INDEX IF NOT EXISTS ix_edges_src ON edges(src);
CREATE INDEX IF NOT EXISTS ix_edges_dst ON edges(dst);
CREATE TABLE IF NOT EXISTS enrichment (
    kind TEXT, key TEXT, payload TEXT, retrieved_at TEXT, PRIMARY KEY (kind, key));
CREATE TABLE IF NOT EXISTS runs (
    run_at TEXT, stage TEXT, details TEXT);
"""


@contextmanager
def connect():
    settings.DATA_DIR.mkdir(exist_ok=True)
    con = sqlite3.connect(settings.DB_PATH)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def log_run(con, stage: str, details: dict):
    con.execute("INSERT INTO runs VALUES (?,?,?)",
                (datetime.now(timezone.utc).isoformat(timespec="seconds"), stage, json.dumps(details)))


def save_records(con, records):
    con.execute("DELETE FROM records")
    cols = ["source", "record_id", "indicator", "indicator_type", "host", "host_kind", "reg_domain",
            "port", "url", "hash", "first_seen", "last_seen", "threat_type", "malware", "tags",
            "confidence", "status", "reporter", "reference"]
    con.executemany(f"INSERT OR REPLACE INTO records VALUES ({','.join('?' * len(cols))})",
                    [tuple(json.dumps(r[c]) if c == "tags" else r.get(c) for c in cols) for r in records])


def save_graph(con, entities: dict, edges: list):
    con.execute("DELETE FROM entities")
    con.execute("DELETE FROM edges")
    con.executemany("INSERT INTO entities VALUES (?,?,?,?,?,?,?,?)",
                    [(e["id"], e["type"], e["value"], e["first_seen"], e["last_seen"],
                      ",".join(sorted(e["sources"])), e["records"], json.dumps(e["attrs"]))
                     for e in entities.values()])
    con.executemany("INSERT INTO edges VALUES (?,?,?,?,?,?,?,?)",
                    [(x["src"], x["dst"], x["rel"], x["source"], x["record_id"], x["first_seen"],
                      x["confidence"], x["method"]) for x in edges])


def cache_get(con, kind: str, keys):
    out = {}
    keys = list(keys)
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        q = f"SELECT key, payload FROM enrichment WHERE kind=? AND key IN ({','.join('?' * len(chunk))})"
        out.update({k: json.loads(p) for k, p in con.execute(q, [kind, *chunk])})
    return out


def cache_put(con, kind: str, items: dict):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    con.executemany("INSERT OR REPLACE INTO enrichment VALUES (?,?,?,?)",
                    [(kind, k, json.dumps(v), now) for k, v in items.items()])
