import sys
import os
import re
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from iot_query import query_iot_server, replace_gauss_url

router = APIRouter()


# --- Request / Response Models ---


class IoTQueryRequest(BaseModel):
    ota_prefix: str = Field(
        ...,
        description="OTA version prefix or model name (e.g. OWW221 or OWW221_11.A). "
        "If a simple model name is given, all standard suffixes are tried automatically.",
    )
    model: Optional[str] = Field(None, description="Override device model extracted from prefix")


class IoTResultItem(BaseModel):
    ota_prefix: str
    link: Optional[str] = None
    changelog: Optional[str] = None
    security_patch: Optional[str] = None
    version: Optional[str] = None
    found: bool


class IoTResponse(BaseModel):
    success: bool
    results: List[IoTResultItem]
    error: Optional[str] = None


# --- Endpoint ---


@router.post(
    "/query",
    response_model=IoTResponse,
    summary="Query legacy IoT OTA server (iota.coloros.com)",
)
def iot_query(request: IoTQueryRequest):
    """
    Query the legacy ColorOS IoT OTA server (`iota.coloros.com`).

    - If the prefix looks like a bare model name (e.g. `OWW221`), the API tries all
      standard suffixes (`_11.A`, `_11.C`, `_11.F`, `_11.H`).
    - If the prefix already contains a version component (e.g. `OWW221_11.A`), a single
      query is performed.

    Supported region: **CN only**.
    """
    ota_input = request.ota_prefix.upper()
    is_simple = not bool(
        re.search(r"_\d{2}\.[A-Z]", ota_input) or ota_input.count("_") >= 3
    )

    results: List[IoTResultItem] = []

    if is_simple:
        suffixes = ["_11.A", "_11.C", "_11.F", "_11.H"]
        model = request.model if request.model else ota_input

        for suffix in suffixes:
            current_prefix = ota_input + suffix
            full_version = f"{current_prefix}.01_0001_197001010000"

            raw = query_iot_server(full_version, model)
            if raw:
                results.append(
                    IoTResultItem(
                        ota_prefix=current_prefix,
                        link=replace_gauss_url(raw.get("down_url", "")),
                        changelog=replace_gauss_url(str(raw.get("description", ""))),
                        security_patch=str(raw.get("googlePatchLevel", "")).replace("0", ""),
                        version=raw.get("new_version", ""),
                        found=True,
                    )
                )
            else:
                results.append(IoTResultItem(ota_prefix=current_prefix, found=False))
    else:
        parts = ota_input.split("_")
        model = request.model if request.model else parts[0]
        full_version = (
            f"{ota_input}.01_0001_197001010000" if len(parts) < 3 else ota_input
        )

        raw = query_iot_server(full_version, model)
        if raw:
            results.append(
                IoTResultItem(
                    ota_prefix=ota_input,
                    link=replace_gauss_url(raw.get("down_url", "")),
                    changelog=replace_gauss_url(str(raw.get("description", ""))),
                    security_patch=str(raw.get("googlePatchLevel", "")).replace("0", ""),
                    version=raw.get("new_version", ""),
                    found=True,
                )
            )
        else:
            results.append(IoTResultItem(ota_prefix=ota_input, found=False))

    return IoTResponse(success=True, results=results)
