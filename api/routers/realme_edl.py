import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()


# --- Request / Response Models ---


class RealmeEDLRequest(BaseModel):
    version_name: str = Field(
        ...,
        description="Full version string including model (e.g. RMX3888_16.0.3.500(CN01))",
    )
    region: str = Field(
        ...,
        description="Region code: CN, EU, EUEX, EEA, TR, or export regions",
    )
    date: str = Field(
        ...,
        description="12-character date prefix in YYYYMMDDHHmm format (e.g. 202601241320)",
        min_length=12,
        max_length=12,
    )


class RealmeEDLResponse(BaseModel):
    success: bool
    url: Optional[str] = None
    error: Optional[str] = None


# --- Endpoint ---


@router.post(
    "/edl",
    response_model=RealmeEDLResponse,
    summary="Query Realme EDL (Emergency Download) ROM URL",
)
def realme_edl_query(request: RealmeEDLRequest):
    """
    Probe for a Realme EDL ROM package by trying up to 10,000 numbered URLs in parallel.

    Server selection:
    - `CN` / `CH` → `rms11.realme.net` (domestic)
    - `EU` / `EUEX` / `EEA` / `TR` → `rms01.realme.net` (GDPR)
    - All other regions → `rms01.realme.net` (export)
    """
    region = request.region.upper()

    if region in ("EU", "EUEX", "EEA", "TR"):
        bucket, server = "GDPR", "rms01.realme.net"
    elif region in ("CN", "CH"):
        bucket, server = "domestic", "rms11.realme.net"
    else:
        bucket, server = "export", "rms01.realme.net"

    version_clean = (
        re.sub(r"^RMX\d+_", "", request.version_name)
        .replace("(", "")
        .replace(")", "")
    )
    model = request.version_name.split("_")[0]
    base_url = (
        f"https://{server}/sw/{model}{bucket}_11_{version_clean}_{request.date}"
    )

    found_url: Optional[str] = None

    def _check(url: str) -> Optional[str]:
        try:
            resp = requests.head(url, timeout=5, allow_redirects=True)
            if resp.status_code == 200:
                return url
        except Exception:
            pass
        return None

    batch_size = 200  # submit in batches to limit memory usage
    with ThreadPoolExecutor(max_workers=50) as executor:
        for batch_start in range(0, 10000, batch_size):
            batch_end = min(batch_start + batch_size, 10000)
            futures = {
                executor.submit(_check, f"{base_url}{i:04d}.zip"): i
                for i in range(batch_start, batch_end)
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_url = result
                    break
            if found_url:
                break

    if found_url:
        return RealmeEDLResponse(success=True, url=found_url)
    return RealmeEDLResponse(success=False, error="EDL ROM not found")
