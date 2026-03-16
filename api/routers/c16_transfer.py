import sys
import os
import base64
from typing import Optional
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from C16_transer import parse_expires_time

router = APIRouter()

# Allowed HTTPS domains for C16 URL resolution (ColorOS/OPlus CDN and OTA servers)
_ALLOWED_DOMAINS = {
    "allawnfs.com",
    "allawntech.com",
    "allawnos.com",
    "coloros.com",
    "oppo.com",
    "oneplus.com",
    "realme.com",
}

_ANDROID_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Cache-Control": "max-age=0",
    "sec-ch-ua": '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": '"Android"',
    "userId": "oplus-ota|00000001",
    "Range": "bytes=0-",
}


def _validate_url(url: str) -> None:
    """Raise HTTPException if the URL is not an allowed HTTPS OPlus/ColorOS domain."""
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise HTTPException(status_code=422, detail="Invalid URL") from exc

    if parsed.scheme != "https":
        raise HTTPException(status_code=422, detail="Only HTTPS URLs are supported")

    hostname = parsed.hostname or ""
    # Accept exact match or subdomain of an allowed domain
    if not any(
        hostname == domain or hostname.endswith("." + domain)
        for domain in _ALLOWED_DOMAINS
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                f"URL hostname '{hostname}' is not an allowed OPlus/ColorOS domain. "
                f"Allowed: {sorted(_ALLOWED_DOMAINS)}"
            ),
        )


# --- Request / Response Models ---


class C16TransferRequest(BaseModel):
    url: str = Field(
        ...,
        description="Dynamic ColorOS 16+ download URL that redirects via HTTP 302",
    )
    market_name: Optional[str] = Field(
        None,
        description="Optional market name (plain text; will be Base64-encoded before sending)",
    )


class C16TransferResponse(BaseModel):
    success: bool
    url: Optional[str] = None
    expires_timestamp: Optional[int] = None
    expires_time: Optional[str] = None
    error: Optional[str] = None


# --- Endpoint ---


@router.post(
    "/resolve",
    response_model=C16TransferResponse,
    summary="Resolve a dynamic ColorOS 16+ download URL (follow HTTP 302)",
)
def c16_resolve(request: C16TransferRequest):
    """
    Follow a single HTTP 302 redirect for ColorOS 16+ dynamic download links and
    return the final URL along with its expiration time.

    Dynamic links expire within 10–30 minutes – resolve immediately after obtaining them.
    """
    headers = dict(_ANDROID_HEADERS)
    _validate_url(request.url)
    if request.market_name:
        headers["marketName"] = base64.b64encode(
            request.market_name.encode("utf-8")
        ).decode("ascii")

    last_exc: Optional[Exception] = None
    for attempt in range(3):
        try:
            response = requests.get(
                request.url,
                headers=headers,
                timeout=10,
                allow_redirects=False,
            )
            break
        except requests.RequestException as exc:
            last_exc = exc
    else:
        raise HTTPException(
            status_code=502,
            detail=f"Network error after 3 attempts: {last_exc}",
        )

    if response.status_code != 302:
        raise HTTPException(
            status_code=502,
            detail=f"Expected HTTP 302 redirect, got {response.status_code}",
        )

    redirect_url = response.headers.get("Location", "")
    if not redirect_url:
        raise HTTPException(status_code=502, detail="302 response contained no Location header")

    time_info = parse_expires_time(redirect_url)
    return C16TransferResponse(
        success=True,
        url=redirect_url,
        expires_timestamp=time_info["timestamp"] if time_info else None,
        expires_time=(
            time_info["expires_time"].strftime("%Y-%m-%d %H:%M:%S") if time_info else None
        ),
    )
