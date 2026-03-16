import sys
import os
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from sota_query import (
    execute_query_request,
    execute_update_request,
    extract_and_format_apk_info,
)

router = APIRouter()


# --- Request / Response Models ---


class SOTAQueryRequest(BaseModel):
    model: str = Field(..., description="Device model (e.g. PJX110)")
    brand: str = Field(..., description="Device brand (e.g. OnePlus, OPPO)")
    ota_version: str = Field(
        ..., description="OTA version string (e.g. PJX110_11.F.13_2130_202512181912)"
    )
    current_sota: str = Field(
        ..., description='Current SOTA version on device (e.g. V80P02(BRB1CN01))'
    )
    coloros: str = Field(..., description="ColorOS version string (e.g. ColorOS16.0.0)")


class APKModuleResponse(BaseModel):
    name: str
    version: int
    md5: str
    url: str


class SOTAResponse(BaseModel):
    success: bool
    sota_version: Optional[str] = None
    apk_modules: Optional[List[APKModuleResponse]] = None
    error: Optional[str] = None


# --- Endpoint ---


@router.post(
    "/query",
    response_model=SOTAResponse,
    summary="Query SOTA (Software OTA / modular APK) updates",
)
def sota_query(request: SOTAQueryRequest):
    """
    Query SOTA APK module updates for a ColorOS device (CN region only).

    The endpoint first checks update availability, then triggers an update request
    to obtain per-module download links.
    """
    config = {
        "model": request.model,
        "brand": request.brand,
        "ota_version": request.ota_version,
        "current_sota": request.current_sota,
        "coloros": request.coloros,
        "rom_version": "unknown",
    }

    try:
        query_result, _aes_key, _iv = execute_query_request(config)
    except SystemExit:
        raise HTTPException(status_code=502, detail="SOTA query request failed")

    if query_result is None:
        raise HTTPException(status_code=502, detail="SOTA query returned no data")

    try:
        update_result = execute_update_request(query_result, config)
    except SystemExit:
        raise HTTPException(status_code=502, detail="SOTA update request failed")

    if update_result is None:
        raise HTTPException(status_code=502, detail="SOTA update request returned no data")

    sota_version, _formatted_lines = extract_and_format_apk_info(update_result)

    apk_modules: List[APKModuleResponse] = []
    module_map = update_result.get("moduleMap", {})
    for apk in module_map.get("apk", []):
        apk_modules.append(
            APKModuleResponse(
                name=apk.get("moduleName", ""),
                version=apk.get("moduleVersion", 0),
                md5=apk.get("md5", ""),
                url=apk.get("manualUrl", ""),
            )
        )

    return SOTAResponse(
        success=True,
        sota_version=sota_version,
        apk_modules=apk_modules if apk_modules else None,
    )
