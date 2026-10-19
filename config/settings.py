"""Central configuration. Everything tunable lives here so the pipeline is reproducible."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# ---------------------------------------------------------------- paths
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"              # fresh downloads (gitignored)
SNAPSHOT_DIR = DATA_DIR / "snapshot"    # frozen, committed copy used for the report
PROCESSED_DIR = DATA_DIR / "processed"  # analytics outputs (JSON for the dashboard)
DB_PATH = DATA_DIR / "osint_viz.db"
REPORTS_DIR = BASE_DIR / "reports"
LOG_DIR = BASE_DIR / "logs"

# ---------------------------------------------------------------- run options
WINDOW_DAYS = int(os.getenv("WINDOW_DAYS", "30"))
OFFLINE = os.getenv("OFFLINE", "0") == "1"
FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.getenv("FLASK_PORT", "5000"))
USER_AGENT = "OSINT-Viz-Platform/1.0 (academic research project)"
HTTP_TIMEOUT = 60

# ---------------------------------------------------------------- open sources
FEEDS = {
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "file": "urlhaus_recent.csv",
        "licence": "CC0 (abuse.ch terms of use)",
    },
    "threatfox": {
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "file": "threatfox_recent.csv",
        "licence": "CC0 (abuse.ch terms of use)",
    },
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "file": "openphish_feed.txt",
        "licence": "OpenPhish Community Feed (free, non-commercial)",
    },
}
# Regional Internet Registry delegation statistics (NRO combined file) used to
# normalise geographic counts by how much IPv4 space each country holds.
NRO_STATS_URL = "https://ftp.ripe.net/pub/stats/ripencc/nro-stats/latest/nro-delegated-stats"

# Enrichment services
IPAPI_BATCH_URL = "http://ip-api.com/batch"
IPAPI_FIELDS = "status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as,asname,hosting"
IPAPI_BATCH_SIZE = 100          # documented maximum per request
IPAPI_REQUESTS_PER_MIN = 14     # documented limit is 15/min; stay under it
CYMRU_ORIGIN_ZONE = "origin.asn.cymru.com"   # Team Cymru IP-to-ASN mapping over DNS
DNS_TIMEOUT = 3.0
DNS_WORKERS = 32

# ---------------------------------------------------------------- correlation / analytics
# Multi-tenant platforms: thousands of unrelated actors share these, so linking
# indicators through them would create false "same campaign" relationships.
SHARED_PLATFORM_DOMAINS = {
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "pages.dev", "workers.dev", "vercel.app", "netlify.app", "web.app",
    "firebaseapp.com", "appspot.com", "herokuapp.com", "glitch.me",
    "blogspot.com", "weebly.com", "wixsite.com", "000webhostapp.com",
    "dropbox.com", "dropboxusercontent.com", "google.com", "googleapis.com",
    "drive.google.com", "discord.com", "discordapp.com", "cdn.discordapp.com",
    "telegram.org", "t.me", "mediafire.com", "onedrive.live.com", "sharepoint.com",
    "amazonaws.com", "cloudfront.net", "azurewebsites.net", "r2.dev", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com", "duckdns.org", "ddns.net", "no-ip.com",
}
# Data-driven hub rule: a pivot node (IP / registered domain / ASN) is treated as
# shared infrastructure when it connects more than this many distinct malware families.
HUB_FAMILY_THRESHOLD = 5
# ASNs are never used as a correlation pivot on their own (one ASN = a whole provider).
ASN_IS_PIVOT = False
BETWEENNESS_SAMPLE = 400        # k for approximate betweenness centrality
BURST_Z_THRESHOLD = 2.0         # daily volume z-score that counts as a burst
GRAPH_VIEW_MAX_NODES = 600      # cap for the browser graph so it stays readable

# Pseudonymise reporter handles in all outputs (privacy / data minimisation).
PSEUDONYMISE_REPORTERS = True
