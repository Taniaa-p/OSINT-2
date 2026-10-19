#!/bin/bash
# Capture dashboard screenshots for the report with headless Chrome.
# Usage: start the dashboard (python main.py serve), then: bash scripts/screenshots.sh
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
OUT="$(cd "$(dirname "$0")/.." && pwd)/docs/screenshots"
BASE="http://127.0.0.1:5000"
LINK_ID="${LINK_ID:-ip%3A176.65.134.121}"
EXTRACT="Analyst%20note%3A%20Vidar%20C2%20seen%20at%20hxxps%3A%2F%2Fv2.abalbet%5B.%5Dcom%2Fea%2F%20and%20loader%20on%20176.65.134%5B.%5D121%3B%20also%20120.84.212%5B.%5D234%20and%20benign%20example%5B.%5Dorg"
mkdir -p "$OUT"
shot() {  # name path height
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --window-size=1440,"$3" \
    --virtual-time-budget=15000 --screenshot="$OUT/$1" "$BASE$2" 2>/dev/null
  echo "captured $1"
}
shot 01_overview.png "/" 1250
shot 02_graph.png "/graph" 1000
shot 03_link_chart.png "/link?id=$LINK_ID" 1050
shot 04_timeline.png "/timeline" 1250
shot 05_heatmap.png "/heatmap" 1350
shot 06_heatmap_normalised.png "/heatmap?metric=ips_per_million_ipv4" 1500
shot 07_network.png "/network" 1050
shot 08_clusters.png "/clusters" 1000
shot 09_extract.png "/extract?text=$EXTRACT" 1150
shot 10_cluster_report.png "/report/cluster/C0001" 1100
