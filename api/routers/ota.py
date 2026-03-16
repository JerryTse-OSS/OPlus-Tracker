import sys
import os
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from tomboy_pro import (
    query_update,
    process_ota_version,
    QueryConfig,
    QueryResult as TomboyQueryResult,
    REGION_CONFIG,
    SUPPORTED_MODES,
)

router = APIRouter()

# "sg_host" is a partial config merged with other regions; "cn_gray" is an internal
# alias set automatically when gray=1. Neither is a valid user-facing region code.
VALID_REGIONS = [r for r in REGION_CONFIG.keys() if r not in ("sg_host", "cn_gray")]


# --- Request / Response Models ---


class OTAQueryRequest(BaseModel):
    ota_version: str = Field(
        ...,
        description="Full OTA version string (e.g. PJX110_11.C.36_1360_20250814) "
        "or simple prefix (e.g. PJX110_11.C)",
    )
    region: str = Field(..., description=f"Region code. One of: {VALID_REGIONS}")
    model: Optional[str] = Field(None, description="Override device model")
    mode: str = Field("manual", description=f"Query mode. One of: {SUPPORTED_MODES}")
    gray: int = Field(0, ge=0, le=1, description="Gray update channel (0 or 1)")
    guid: Optional[str] = Field(
        None, description="Device GUID (64 hex chars). Defaults to all-zeros."
    )
    components: Optional[str] = Field(
        None, description="Delta OTA components in 'Name:Version,...' format"
    )
    anti: int = Field(0, ge=0, le=1, description="Anti-bypass mode for ColorOS 16 (0 or 1)")
    genshin: str = Field("0", description="Genshin edition suffix (0=none, 1=YS, 2=Ovt)")
    pre: str = Field("0", description="Preview build suffix (0 or 1)")
    nvid: Optional[str] = Field(None, description="Custom NV carrier ID (exactly 8 digits)")
    custom_language: Optional[str] = Field(None, description="Language override (e.g. zh-CN)")


class OTAAutoQueryRequest(BaseModel):
    ota_prefix: str = Field(
        ...,
        description="OTA prefix WITHOUT version suffix (e.g. PJX110). "
        "The API will try _11.A, _11.C, _11.F, _11.H, _11.J automatically.",
    )
    region: str = Field(..., description=f"Region code. One of: {VALID_REGIONS}")
    model: Optional[str] = Field(None)
    mode: str = Field("manual")
    gray: int = Field(0, ge=0, le=1)
    guid: Optional[str] = Field(None)
    components: Optional[str] = Field(None)
    anti: int = Field(0, ge=0, le=1)
    genshin: str = Field("0")
    pre: str = Field("0")
    nvid: Optional[str] = Field(None)
    custom_language: Optional[str] = Field(None)


class ComponentInfoResponse(BaseModel):
    name: str
    version: str
    link: str
    original_link: str
    size: str
    md5: str
    auto_url: str
    expires_time: Optional[str] = None


class OpexInfoResponse(BaseModel):
    index: int
    version_name: str
    business_code: str
    zip_hash: str
    auto_url: str


class OTAResponse(BaseModel):
    success: bool
    ota_prefix: Optional[str] = None
    components: Optional[List[ComponentInfoResponse]] = None
    opex_list: Optional[List[OpexInfoResponse]] = None
    changelog: Optional[str] = None
    security_patch: Optional[str] = None
    version: Optional[str] = None
    ota_version: Optional[str] = None
    published_time: Optional[str] = None
    response_code: Optional[int] = None
    error: Optional[str] = None


# --- Helpers ---


def _build_response(result: TomboyQueryResult, ota_prefix: str = None) -> OTAResponse:
    if result.success:
        components = None
        if result.components:
            components = [
                ComponentInfoResponse(
                    name=c.name,
                    version=c.version,
                    link=c.link,
                    original_link=c.original_link,
                    size=c.size,
                    md5=c.md5,
                    auto_url=c.auto_url,
                    expires_time=str(c.expires_time) if c.expires_time else None,
                )
                for c in result.components
            ]
        opex_list = None
        if result.opex_list:
            opex_list = [
                OpexInfoResponse(
                    index=o.index,
                    version_name=o.version_name,
                    business_code=o.business_code,
                    zip_hash=o.zip_hash,
                    auto_url=o.auto_url,
                )
                for o in result.opex_list
            ]
        return OTAResponse(
            success=True,
            ota_prefix=ota_prefix,
            components=components,
            opex_list=opex_list,
            changelog=result.data.get("changelog"),
            security_patch=result.data.get("security_patch"),
            version=result.data.get("version"),
            ota_version=result.data.get("ota_version"),
            published_time=result.published_time,
            response_code=result.response_code,
        )
    return OTAResponse(
        success=False,
        ota_prefix=ota_prefix,
        response_code=result.response_code,
        error=result.error or f"Query returned code {result.response_code}",
    )


def _validate_request(region: str, mode: str, guid: Optional[str], pre: str, nvid: Optional[str]):
    if region.lower() not in VALID_REGIONS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid region '{region}'. Valid values: {VALID_REGIONS}",
        )
    if mode not in SUPPORTED_MODES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid mode '{mode}'. Valid values: {SUPPORTED_MODES}",
        )
    if pre == "1" and (guid is None or guid == "0" * 64):
        raise HTTPException(
            status_code=422,
            detail="A valid GUID is required when pre=1",
        )
    if nvid is not None and (not nvid.isdigit() or len(nvid) != 8):
        raise HTTPException(
            status_code=422,
            detail="nvid must be exactly 8 digits",
        )


# --- Endpoints ---


@router.post(
    "/query",
    response_model=OTAResponse,
    summary="Query OTA update for a specific version",
)
def ota_query(request: OTAQueryRequest):
    """
    Query OTA update information for a specific OTA version string.

    - Pass the full version (e.g. `PJX110_11.C.36_1360_20250814`) or a short prefix
      (e.g. `PJX110_11.C`) together with the target `region`.
    - For delta OTA queries, supply `components` as `Name:Version,...`.
    - For ColorOS 16 anti-bypass, set `anti=1` (switches mode to `taste`).
    """
    _validate_request(request.region, request.mode, request.guid, request.pre, request.nvid)

    ota_upper = request.ota_version.upper().replace("OVT", "Ovt")
    guid = request.guid or "0" * 64

    processed_ota, processed_model = process_ota_version(
        ota_upper, request.region, request.genshin, request.pre, request.model
    )

    config = QueryConfig(
        ota_version=processed_ota,
        model=processed_model,
        region=request.region.lower(),
        gray=request.gray,
        mode=request.mode,
        guid=guid,
        components_input=request.components,
        anti=request.anti,
        has_custom_model=bool(request.model),
        genshin=request.genshin,
        pre=request.pre,
        custom_language=request.custom_language,
        nvid=request.nvid,
    )

    result = query_update(config)

    # IN region fallback: retry with model+IN suffix
    if (
        not result.success
        and result.response_code == 2004
        and request.region.lower() == "in"
        and not request.model
    ):
        config.model = f"{processed_model}IN"
        result = query_update(config)

    return _build_response(result, ota_upper)


@router.post(
    "/auto",
    response_model=List[OTAResponse],
    summary="Auto-complete OTA query (tries all version suffixes)",
)
def ota_auto_query(request: OTAAutoQueryRequest):
    """
    Auto-complete query: iterates over all standard version suffixes
    (`_11.A`, `_11.C`, `_11.F`, `_11.H`, `_11.J`) and returns one result per suffix.

    Useful for discovering which channel has an available update without knowing the exact suffix.
    """
    _validate_request(request.region, request.mode, request.guid, request.pre, request.nvid)

    suffixes = ["_11.A", "_11.C", "_11.F", "_11.H", "_11.J"]
    results: List[OTAResponse] = []
    guid = request.guid or "0" * 64
    last_success_fake: Optional[str] = None
    mode = "taste" if request.anti == 1 else request.mode

    ota_upper = request.ota_prefix.upper().replace("OVT", "Ovt")

    for suffix in suffixes:
        display_ota = ota_upper + suffix
        processed_ota, processed_model = process_ota_version(
            display_ota,
            request.region,
            request.genshin,
            request.pre,
            request.model if request.model else None,
        )

        current_config = QueryConfig(
            ota_version=processed_ota,
            model=processed_model,
            region=request.region.lower(),
            gray=request.gray,
            mode=mode,
            guid=guid,
            components_input=request.components,
            anti=request.anti,
            has_custom_model=bool(request.model),
            genshin=request.genshin,
            pre=request.pre,
            custom_language=request.custom_language,
            nvid=request.nvid,
        )

        result = query_update(current_config)

        # IN region fallback
        if (
            not result.success
            and result.response_code == 2004
            and request.region.lower() == "in"
            and not request.model
        ):
            current_config.model = f"{processed_model}IN"
            result = query_update(current_config)

        # Anti-bypass retry using last successful fake OTA version
        if (
            request.anti == 1
            and not result.success
            and result.response_code == 2004
            and last_success_fake
        ):
            retry_ota, retry_model = process_ota_version(
                last_success_fake,
                request.region,
                request.genshin,
                request.pre,
                request.model if request.model else None,
            )
            retry_config = QueryConfig(
                ota_version=retry_ota,
                model=retry_model,
                region=request.region.lower(),
                gray=request.gray,
                mode=mode,
                guid=guid,
                components_input=request.components,
                anti=0,
                has_custom_model=bool(request.model),
                genshin=request.genshin,
                pre=request.pre,
                custom_language=request.custom_language,
                nvid=request.nvid,
            )
            result = query_update(retry_config)
            if (
                not result.success
                and result.response_code == 2004
                and request.region.lower() == "in"
                and not request.model
            ):
                retry_config.model = f"{retry_model}IN"
                result = query_update(retry_config)

        if result.success and request.anti == 1:
            fake = result.data.get("fake_ota_version")
            if fake and fake != "N/A":
                last_success_fake = fake

        results.append(_build_response(result, display_ota))

    return results
