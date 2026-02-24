from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import requests


@dataclass
class DownloadResult:
    url: str
    path: Path
    sha256: str
    bytes_written: int
    fetched_at_iso: str


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_to_path(
    url: str,
    dest_path: Path,
    timeout_s: int = 60,
    user_agent: str = "BastionCodex/0.1 (+local ingestion)",
) -> DownloadResult:
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    headers = {"User-Agent": user_agent}
    with requests.get(url, headers=headers, stream=True, timeout=timeout_s) as r:
        r.raise_for_status()
        bytes_written = 0
        with dest_path.open("wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
                    bytes_written += len(chunk)

    return DownloadResult(
        url=url,
        path=dest_path,
        sha256=sha256_file(dest_path),
        bytes_written=bytes_written,
        fetched_at_iso=utc_now_iso(),
    )


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")