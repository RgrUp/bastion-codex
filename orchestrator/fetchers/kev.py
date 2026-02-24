from __future__ import annotations

import os
from pathlib import Path
from typing import Dict

from .http import DownloadResult, download_to_path


# Primary: CISA feed endpoint (commonly used)
DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Fallback: official CISA GitHub mirror of the data files
DEFAULT_KEV_GITHUB_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"


def fetch_kev(raw_dir: Path) -> Dict:
    """
    Fetch CISA KEV catalog JSON.

    Writes:
      - data/raw/kev.json
    """
    kev_url = os.environ.get("BASTION_KEV_URL", DEFAULT_KEV_URL).strip()
    dest = raw_dir / "kev.json"

    try:
        res = download_to_path(kev_url, dest)
        return _meta(res, source="cisa")
    except Exception:
        # Fallback to GitHub mirror if CISA endpoint is blocked by network controls
        fallback_url = os.environ.get("BASTION_KEV_GITHUB_URL", DEFAULT_KEV_GITHUB_URL).strip()
        res = download_to_path(fallback_url, dest)
        return _meta(res, source="github_mirror")


def _meta(res: DownloadResult, source: str) -> Dict:
    return {
        "name": "kev",
        "source": source,
        "url": res.url,
        "path": str(res.path),
        "sha256": res.sha256,
        "bytes": res.bytes_written,
        "fetched_at": res.fetched_at_iso,
    }