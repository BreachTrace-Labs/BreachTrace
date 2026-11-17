import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO, format="%(levelname)s:\t  %(name)s - %(message)s")

import config

config.validate_config()

from routers import assistant, auth, incidents, repositories, research, settings, simulate, webhook  # noqa: E402 — must come after validate_config

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
app.include_router(auth.router)
app.include_router(incidents.router)
app.include_router(incidents.legacy_router)
app.include_router(research.router)
app.include_router(simulate.router)
app.include_router(assistant.router)
app.include_router(settings.router)
app.include_router(repositories.router)


@app.exception_handler(RequestValidationError)
async def validation_error(request, error):
    # Validation errors must not echo submitted provider keys or source files.
    return JSONResponse(status_code=422, content={"detail": [
        {"loc": list(item["loc"]), "msg": item["msg"], "type": item["type"]}
        for item in error.errors()
    ]})


@app.on_event("startup")
def _warm_search_index() -> None:
    assistant.warm_index_in_background()


# ---------------------------------------------------------------------------
# Root + Health
# ---------------------------------------------------------------------------

@app.get("/")
def health_check():
    return {"status": "ok", "message": "BreachTrace running"}


@app.get("/health")
def health():
    return {"status": "ok"}
