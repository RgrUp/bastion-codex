from __future__ import annotations

import re
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List

from fetchers.http import write_json, utc_now_iso
from fetchers.kev import fetch_kev
from fetchers.nvd import fetch_nvd_modified

import json
from datetime import datetime, timezone
from pathlib import Path

import os
import shutil


def run_fetch(root: Path) -> Dict:
    raw_dir = root / "data" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    artifacts: List[Dict] = []
    artifacts.append(fetch_kev(raw_dir))
    artifacts.append(fetch_nvd_modified(raw_dir))

    meta = {
        "project": "bastion-codex",
        "run_type": "fetch",
        "generated_at": utc_now_iso(),
        "raw_dir": str(raw_dir),
        "artifacts": artifacts,
    }

    write_json(raw_dir / "meta.json", meta)
    return meta


def run_rust(root: Path, args: List[str]) -> None:
    """
    Run the Rust truth engine via cargo.
    """
    cmd = ["cargo", "run", "--quiet", "--manifest-path", str(root / "core" / "Cargo.toml"), "--"] + args
    subprocess.run(cmd, cwd=str(root), check=True)


def run_weekly(root: Path) -> None:
    # 1) Fetch
    meta = run_fetch(root)
    print(f"[OK] Wrote: {root / 'data' / 'raw' / 'meta.json'}")
    for a in meta["artifacts"]:
        if a["name"] == "kev":
            print(f"  - KEV: {a['path']} ({a['bytes']} bytes)")
        else:
            print(f"  - NVD: {a['path_json']} ({a['bytes_json']} bytes)")

    # 2) Normalize
    (root / "data" / "normalized").mkdir(parents=True, exist_ok=True)
    run_rust(
        root,
        [
            "normalize",
            "--kev", "data/raw/kev.json",
            "--nvd", "data/raw/nvd_modified.json",
            "--out", "data/normalized/items.json",
        ],
    )

    # 3) Derive
    (root / "data" / "derived").mkdir(parents=True, exist_ok=True)
    run_rust(
        root,
        [
            "derive",
            "--input", "data/normalized/items.json",
            "--outdir", "data/derived",
        ],
    )

    print("[OK] Weekly pipeline complete.")
    print("  - data/normalized/items.json")
    print("  - data/derived/priority_items.json")
    print("  - data/derived/trends_7d.json")
    print("  - data/derived/trends_30d.json")
    
    ## 4) Generate weekly brief
    brief_path = generate_weekly_markdown(root)
    print(f"  - {brief_path.relative_to(root)}")

    ## Optional: export to Obsidian vault if env var set
    export_to_obsidian(root, brief_path)
    export_to_astro_blog(root, brief_path)

def generate_weekly_markdown(root: Path) -> Path:
    derived_dir = root / "data" / "derived"
    briefs_dir = root / "data" / "briefs"
    briefs_dir.mkdir(parents=True, exist_ok=True)

    trends_7 = json.load(open(derived_dir / "trends_7d.json", "r", encoding="utf-8"))
    trends_30 = json.load(open(derived_dir / "trends_30d.json", "r", encoding="utf-8"))
    priority = json.load(open(derived_dir / "priority_items.json", "r", encoding="utf-8"))

    now = datetime.now(timezone.utc)
    filename = f"weekly-{now.date()}.md"
    out_path = briefs_dir / filename

    # Top 10 priority (sorted by CVSS descending)
    priority_sorted = sorted(
        priority,
        key=lambda x: (x.get("kev", False), x.get("cvss") or 0),
        reverse=True,
    )[:10]

    # Helper to get severity counts with default of 0
    def sev_count(sev):
        return trends_7["by_severity"].get(sev, 0)

    lines = []

    lines.append("# Bastion Codex – Weekly Defender Brief")
    lines.append(f"Week of {now.date()}")
    lines.append("")
    lines.append("## Executive Snapshot")
    lines.append(f"- {trends_7['total_items']} CVEs observed in the last 7 days")
    lines.append(f"- {sev_count('critical')} Critical")
    lines.append(f"- {sev_count('high')} High")
    lines.append(f"- {trends_30['kev_items']} KEV-listed vulnerabilities in last 30 days")
    lines.append("")

    lines.append("## Defender Takeaways")

    if sev_count("critical") > 50:
        lines.append("- Elevated volume of Critical vulnerabilities this week. Prioritize external-facing asset review.")
    elif sev_count("critical") > 10:
        lines.append("- Moderate Critical vulnerability volume. Validate patch cadence and exposure management.")
    else:
        lines.append("- Critical vulnerability volume is lower than typical baseline.")

    if trends_30["kev_items"] > 0:
        lines.append("- Recently added KEV vulnerabilities detected. Review CISA remediation timelines.")
    else:
        lines.append("- No new KEV movement in the last 30 days.")

    if sev_count("high") > 300:
        lines.append("- High severity volume suggests increased patch workload. Focus on internet-exposed services first.")

    lines.append("")

    lines.append("## Severity Breakdown (7 Days)")
    for sev in ["critical", "high", "medium", "low", "unknown"]:
        lines.append(f"- {sev.title()}: {sev_count(sev)}")
    lines.append("")

    lines.append("## Top Vendors (30 Days)")
    for vendor, count in trends_30.get("top_vendors", [])[:10]:
        lines.append(f"- {vendor}: {count}")
    lines.append("")

    lines.append("## Top Products (30 Days)")
    for product, count in trends_30.get("top_products", [])[:10]:
        lines.append(f"- {product}: {count}")
    lines.append("")

    lines.append("## Priority Watchlist (Top 10)")
    for item in priority_sorted:
        lines.append(
            f"- {item['id']} | CVSS: {item.get('cvss')} | KEV: {item['kev']} | {item['short_desc'][:140]}"
        )

    lines.append("")
    lines.append("---")
    lines.append(f"Generated by Bastion Codex at {now.isoformat()}")

    #clean_body = body.replace("Generated by Bastion Codex", "Generated via Bastion Codex pipeline")
    out_path.write_text("\n".join(lines), encoding="utf-8")
    
    return out_path

# Optional: export to Obsidian vault if env var set
def export_to_obsidian(root: Path, brief_path: Path) -> None:
    """
    Export the weekly brief into an Obsidian vault if BASTION_OBSIDIAN_VAULT is set.

    Env var:
      BASTION_OBSIDIAN_VAULT = absolute path to vault root
    """
    vault = os.environ.get("BASTION_OBSIDIAN_VAULT", "").strip()
    if not vault:
        print("[INFO] Obsidian export skipped (BASTION_OBSIDIAN_VAULT not set).")
        return

    vault_root = Path(vault).expanduser()
    if not vault_root.exists():
        print(f"[WARN] Obsidian export skipped (vault not found): {vault_root}")
        return

    dest_dir = vault_root / "Threat-Brain" / "Bastion Codex" / "Briefs"
    dest_dir.mkdir(parents=True, exist_ok=True)

    dest_brief = dest_dir / brief_path.name
    shutil.copyfile(brief_path, dest_brief)

    # Update hub link (simple evergreen pointer)
    hub_path = vault_root / "Threat-Brain" / "Bastion Codex" / "Hub.md"
    hub_lines = []
    hub_lines.append("# Bastion Codex – Hub")
    hub_lines.append("")
    hub_lines.append("## Latest Weekly Brief")
    hub_lines.append(f"- [[Threat-Brain/Bastion Codex/Briefs/{brief_path.name}|{brief_path.stem}]]")
    hub_lines.append("")
    hub_lines.append("## Notes")
    hub_lines.append("- This hub is updated automatically by Bastion Codex.")
    hub_lines.append("")
    hub_lines.append("---")
    hub_lines.append(f"Updated: {datetime.now(timezone.utc).isoformat()}")

    hub_path.write_text("\n".join(hub_lines), encoding="utf-8")

    print(f"[OK] Exported to Obsidian: {dest_brief}")
    print(f"[OK] Updated Obsidian hub: {hub_path}")

# Optional: export to Astro blog if env var set
def slugify(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"[^a-z0-9\s-]", "", s)
    s = re.sub(r"[\s-]+", "-", s)
    return s


def export_to_astro_blog(root: Path, brief_path: Path) -> None:
    """
    Export a blog-ready Markdown post into an Astro site.

    Env vars:
      BASTION_ASTRO_SITE_ROOT   = absolute path to astro site root
      BASTION_ASTRO_BLOG_SUBDIR = blog folder within astro site (default: src/content/blog)
    """
    site_root = os.environ.get("BASTION_ASTRO_SITE_ROOT", "").strip()
    if not site_root:
        print("[INFO] Astro export skipped (BASTION_ASTRO_SITE_ROOT not set).")
        return

    blog_subdir = os.environ.get("BASTION_ASTRO_BLOG_SUBDIR", "src/content/blog").strip()

    site_root = str(Path(site_root).expanduser())
    out_dir = Path(site_root) / blog_subdir
    out_dir.mkdir(parents=True, exist_ok=True)

    # Read the generated brief content
    raw_body = brief_path.read_text(encoding="utf-8")

    intro = "\n".join([
    "This weekly defender brief summarizes vulnerability movement observed over the past 7 and 30 days.",
    "",
    "The goal is simple: highlight signal that matters to frontline defenders — patch workload pressure, severity shifts, and KEV movement.",
    "",
    "---",
    "",
    ])

    body = intro + raw_body

    clean_body = body.replace(
    "Generated by Bastion Codex",
    "Generated via Bastion Codex pipeline"
    )

    now = datetime.now(timezone.utc)
    date_str = str(now.date())

    title = f"Bastion Codex – Weekly Defender Brief ({date_str})"
    slug = slugify(f"bastion-codex-weekly-{date_str}")

    # Astro-friendly frontmatter (safe default for both pages + collections)
    frontmatter = "\n".join([
    "---",
    f'title: "{title}"',
    f"pubDate: {date_str}",
    'description: "Frontline defender-focused weekly vulnerability signal: severity breakdown, trends, and priority watchlist."',
    'heroImage: "/BastionBlog.png"',
    'tags: ["threat-intel", "vulnerability-management", "defender-brief", "bastion-codex"]',
    "---",
    "",
    ])

    # Output filename style that works well with content collections
    out_path = out_dir / f"{slug}.md"
    out_path.write_text(frontmatter + clean_body, encoding="utf-8")

    print(f"[OK] Exported to Astro blog: {out_path}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Bastion Codex orchestrator")
    parser.add_argument("--root", default=".", help="Repo root (default: current directory)")
    parser.add_argument("--fetch", action="store_true", help="Fetch and cache raw feeds (KEV + NVD modified)")
    parser.add_argument("--weekly", action="store_true", help="Run full weekly pipeline (fetch + normalize + derive)")

    args = parser.parse_args()
    root = Path(args.root).resolve()

    if args.weekly:
        run_weekly(root)
        return

    if args.fetch:
        meta = run_fetch(root)
        print(f"[OK] Wrote: {root / 'data' / 'raw' / 'meta.json'}")
        for a in meta["artifacts"]:
            if a["name"] == "kev":
                print(f"  - KEV: {a['path']} ({a['bytes']} bytes)")
            else:
                print(f"  - NVD: {a['path_json']} ({a['bytes_json']} bytes)")
        return

    print("Nothing to do. Try:")
    print("  python orchestrator\\ti_run.py --weekly")
    print("  python orchestrator\\ti_run.py --fetch")


if __name__ == "__main__":
    main()