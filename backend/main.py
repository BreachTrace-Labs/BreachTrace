import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

logging.basicConfig(level=logging.INFO, format="%(levelname)s:\t  %(name)s - %(message)s")

import config

config.validate_config()

from routers import incidents, research, simulate, webhook  # noqa: E402 — must come after validate_config

app = FastAPI(
    title="BreachTrace",
    description="Universal Credential Forensics Platform",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(webhook.router)
app.include_router(incidents.router)
app.include_router(incidents.legacy_router)
app.include_router(research.router)
app.include_router(simulate.router)


# ---------------------------------------------------------------------------
# Root + Health
# ---------------------------------------------------------------------------

@app.get("/")
def health_check():
    return {"status": "ok", "message": "BreachTrace running"}


@app.get("/health")
def health():
    return {"status": "ok"}
