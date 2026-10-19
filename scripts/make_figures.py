"""Generate the report figures from data/processed/*.json (run after `main.py analyze`)."""
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import settings  # noqa: E402

OUT = settings.BASE_DIR / "docs" / "figures"
OUT.mkdir(parents=True, exist_ok=True)
P = settings.PROCESSED_DIR
S = json.loads((P / "summary.json").read_text())
plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
BLUE, RED, GREY, AMBER, GREEN = "#2f6fdb", "#d64545", "#8a94a6", "#e0a020", "#2e9e6a"


def architecture():
    fig, ax = plt.subplots(figsize=(11, 5.6))
    ax.axis("off")
    ax.set_xlim(0, 11); ax.set_ylim(0, 6)
    layers = [
        ("1. Data acquisition", "URLhaus · ThreatFox · OpenPhish\nNRO RIR stats · SHA-256 manifest", "#dbe7fb"),
        ("2. Preprocessing", "refang · parse · validate\nUTC time · window · de-dup", "#dbe7fb"),
        ("3. Entity extraction", "url · host · domain · ip · hash\nmalware · reporter · free-text IOCs", "#e3f1e6"),
        ("4. Enrichment", "DNS A · ip-api geo/ASN\nTeam Cymru ASN/registry CC", "#e3f1e6"),
        ("5. Correlation", "knowledge graph (NetworkX)\nhub suppression · clusters\ncross-feed corroboration", "#fdf0d5"),
        ("6. Analytics", "centrality · Louvain · bursts\nnormalised geo · SNA\nsource agreement", "#fdf0d5"),
        ("7. Visualisation", "graph · link chart · timeline\ngeo + temporal heat maps\nevidence panel", "#ece3f6"),
        ("8. Reporting", "HTML reports (defanged)\nGEXF / CSV export\nSQLite audit log", "#ece3f6"),
    ]
    for i, (title, body, col) in enumerate(layers):
        row, col_i = divmod(i, 4)
        x, y = 0.25 + col_i * 2.7, 3.4 - row * 2.9
        ax.add_patch(FancyBboxPatch((x, y), 2.35, 2.1, boxstyle="round,pad=0.03", fc=col, ec="#445"))
        ax.text(x + 1.175, y + 1.75, title, ha="center", weight="bold")
        ax.text(x + 1.175, y + 0.85, body, ha="center", va="center", fontsize=8.6)
        if col_i < 3:
            ax.annotate("", (x + 2.65, y + 1.05), (x + 2.38, y + 1.05), arrowprops=dict(arrowstyle="->", lw=1.4))
    ax.annotate("", (1.4, 2.55), (9.5, 3.38), arrowprops=dict(arrowstyle="->", lw=1.4, connectionstyle="arc3,rad=0"))
    ax.text(5.5, 0.05, "SQLite (records · entities · edges · enrichment cache · run log) underpins every layer",
            ha="center", style="italic", fontsize=9)
    fig.savefig(OUT / "fig_architecture.png", dpi=170, bbox_inches="tight")
    plt.close(fig)


def hub_experiment():
    e = S["experiment_hub_suppression"]
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.6))
    axes[0].bar(["Without\nsuppression", "With\nsuppression"], [e["without"]["largest_cluster"], e["with"]["largest_cluster"]],
                color=[RED, BLUE])
    axes[0].set_title("Largest 'campaign' cluster (entities)")
    for i, v in enumerate([e["without"]["largest_cluster"], e["with"]["largest_cluster"]]):
        axes[0].text(i, v, f"{v:,}", ha="center", va="bottom")
    top = S["hubs"]["examples"][:8][::-1]
    axes[1].barh([h["id"].split(":", 1)[1][:30] for h in top], [h["degree"] for h in top], color=GREY)
    axes[1].set_title("Highest-degree suppressed hubs")
    axes[1].set_xscale("log"); axes[1].set_xlabel("connections (log)")
    fig.tight_layout()
    fig.savefig(OUT / "fig_hub_suppression.png", dpi=170)
    plt.close(fig)


def timeline():
    t = json.loads((P / "timeline.json").read_text())
    fig, ax = plt.subplots(figsize=(10, 3.8))
    bottom = [0] * len(t["days"])
    cols = [BLUE, RED, GREEN, AMBER, "#8a5cd1", "#1f9e9a", "#d9772e", "#c75b9b", GREY]
    for i, (fam, ys) in enumerate(t["series"].items()):
        ax.bar(range(len(ys)), ys, bottom=bottom, label=fam, color=cols[i % len(cols)], width=0.85)
        bottom = [a + b for a, b in zip(bottom, ys)]
    ax.set_yscale("symlog", linthresh=100)
    ax.set_xticks(range(0, len(t["days"]), 3)); ax.set_xticklabels(t["days"][::3], rotation=45, ha="right", fontsize=8)
    ax.set_ylabel("new indicators / day (symlog)")
    ax.legend(ncol=5, fontsize=7.5, frameon=False, loc="upper left")
    fig.tight_layout()
    fig.savefig(OUT / "fig_timeline.png", dpi=170)
    plt.close(fig)


def geo_ranks():
    g = json.loads((P / "geo.json").read_text())
    c = [x for x in g["countries"] if x["ips_per_million_ipv4"] is not None and x["ips"] >= 5]
    fig, axes = plt.subplots(1, 3, figsize=(12, 3.8))
    for ax, (m, title, col) in zip(axes, [("urls", "By URLs (inflated)", RED), ("ips", "By distinct IPs", BLUE),
                                          ("ips_per_million_ipv4", "IPs per million IPv4 (normalised)", GREEN)]):
        top = sorted(c, key=lambda x: -x[m])[:10][::-1]
        ax.barh([x["cc"] for x in top], [x[m] for x in top], color=col)
        ax.set_title(title, fontsize=10)
    fig.tight_layout()
    fig.savefig(OUT / "fig_geo_ranks.png", dpi=170)
    plt.close(fig)


def dow_hour():
    t = json.loads((P / "timeline.json").read_text())
    fig, ax = plt.subplots(figsize=(10, 2.8))
    im = ax.imshow(t["dow_hour"], aspect="auto", cmap="viridis")
    ax.set_yticks(range(7)); ax.set_yticklabels(["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"])
    ax.set_xticks(range(0, 24, 2)); ax.set_xticklabels([f"{h}:00" for h in range(0, 24, 2)], fontsize=8)
    ax.set_xlabel("hour (UTC)")
    fig.colorbar(im, ax=ax, label="indicators")
    fig.tight_layout()
    fig.savefig(OUT / "fig_dow_hour.png", dpi=170)
    plt.close(fig)


if __name__ == "__main__":
    for f in (architecture, hub_experiment, timeline, geo_ranks, dow_hour):
        f()
        print("wrote", f.__name__)
