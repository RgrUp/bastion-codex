from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from typing import Dict, List

from fetchers.http import write_json, utc_now_iso
from fetchers.kev import fetch_kev
from fetchers.nvd import fetch_nvd_modified


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