from __future__ import annotations

import gzip
import os
import shutil
from pathlib import Path
from typing import Dict

from .http import DownloadResult, download_to_path, sha256_file


# NVD JSON 2.0 Modified feed (gz)
DEFAULT_NVD_MODIFIED_GZ_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"


def fetch_nvd_modified(raw_dir: Path) -> Dict:
    """
    Fetch NVD CVE JSON 2.0 "modified" feed (.json.gz), then decompress to .json.

    Writes:
      - data/raw/nvd_modified.json.gz
      - data/raw/nvd_modified.json
    """
    url = os.environ.get("BASTION_NVD_MODIFIED_URL", DEFAULT_NVD_MODIFIED_GZ_URL).strip()

    gz_path = raw_dir / "nvd_modified.json.gz"
    json_path = raw_dir / "nvd_modified.json"

    res_gz: DownloadResult = download_to_path(url, gz_path)

    # Decompress deterministically
    with gzip.open(gz_path, "rb") as f_in, json_path.open("wb") as f_out:
        shutil.copyfileobj(f_in, f_out)

    return {
        "name": "nvd_modified",
        "source": "nvd",
        "url": res_gz.url,
        "path_gz": str(gz_path),
        "sha256_gz": res_gz.sha256,
        "bytes_gz": res_gz.bytes_written,
        "path_json": str(json_path),
        "sha256_json": sha256_file(json_path),
        "bytes_json": json_path.stat().st_size,
        "fetched_at": res_gz.fetched_at_iso,
    }