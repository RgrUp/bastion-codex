from __future__ import annotations

import argparse
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
        "run_type": "fetch_only",
        "generated_at": utc_now_iso(),
        "raw_dir": str(raw_dir),
        "artifacts": artifacts,
    }

    write_json(raw_dir / "meta.json", meta)
    return meta


def main() -> None:
    parser = argparse.ArgumentParser(description="Bastion Codex orchestrator (Phase 1: fetch only).")
    parser.add_argument(
        "--root",
        default=".",
        help="Repo root (default: current directory)",
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Fetch and cache raw feeds (KEV + NVD modified)",
    )

    args = parser.parse_args()
    root = Path(args.root).resolve()

    if args.fetch:
        meta = run_fetch(root)
        print(f"[OK] Wrote: {root / 'data' / 'raw' / 'meta.json'}")
        for a in meta["artifacts"]:
            if a["name"] == "kev":
                print(f"  - KEV: {a['path']} ({a['bytes']} bytes)")
            else:
                print(f"  - NVD: {a['path_json']} ({a['bytes_json']} bytes)")
    else:
        print("Nothing to do. Try: python orchestrator/ti_run.py --fetch")


if __name__ == "__main__":
    main()