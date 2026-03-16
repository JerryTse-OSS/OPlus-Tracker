from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routers import ota, sota, opex, iot, downgrade, realme_edl, c16_transfer

app = FastAPI(
    title="OPlus Tracker API",
    description=(
        "RESTful API for querying OTA/firmware updates for OPPO, OnePlus, and Realme devices. "
        "Covers full OTA, SOTA (APK), OPEX (carrier patch), downgrade packages, "
        "Realme EDL ROMs, legacy IoT queries, and dynamic link resolution."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ota.router, prefix="/ota", tags=["OTA"])
app.include_router(sota.router, prefix="/sota", tags=["SOTA"])
app.include_router(opex.router, prefix="/opex", tags=["OPEX"])
app.include_router(iot.router, prefix="/iot", tags=["IoT"])
app.include_router(downgrade.router, prefix="/downgrade", tags=["Downgrade"])
app.include_router(realme_edl.router, prefix="/realme", tags=["Realme EDL"])
app.include_router(c16_transfer.router, prefix="/c16", tags=["C16 Transfer"])


@app.get("/", tags=["Root"])
def root():
    return {"message": "OPlus Tracker API", "docs": "/docs", "redoc": "/redoc"}
