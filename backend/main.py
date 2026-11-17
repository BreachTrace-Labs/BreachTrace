import logging
import os
from urllib.parse import urlsplit
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

logging.basicConfig(level=logging.INFO, format="%(levelname)s:\t  %(name)s - %(message)s")

import config

config.validate_config()

from auth import get_active_user, require_admin_or_lead, require_single_organisation  # noqa: E402
from routers import assistant, auth, incidents, org, projects, repositories, research, settings, simulate, wallet, webhook  # noqa: E402 — must come after validate_config
from rate_limit import limiter

app = FastAPI(
    title="BreachTrace",
    description="Universal Credential Forensics Platform",
    version="0.1.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def frontend_origins() -> list[str]:
    value = os.environ.get("FRONTEND_ORIGIN", "http://localhost:5173,http://127.0.0.1:5173")
    origins = [part.strip().rstrip("/") for part in value.split(",") if part.strip()]
    if not origins:
        raise RuntimeError("FRONTEND_ORIGIN must contain at least one HTTP(S) origin")
    for origin in origins:
        try:
            parsed = urlsplit(origin)
            valid = (parsed.scheme in ("http", "https") and parsed.hostname and
                     not parsed.username and not parsed.password and not parsed.path and
                     not parsed.query and not parsed.fragment and
                     (parsed.port is None or 1 <= parsed.port <= 65535))
        except ValueError:
            valid = False
        if not valid:
            raise RuntimeError("FRONTEND_ORIGIN must contain only HTTP(S) origins")
    return origins


app.add_middleware(
    CORSMiddleware,
    allow_origins=frontend_origins(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(webhook.router)
app.include_router(auth.router)
app.include_router(org.router)
app.include_router(projects.router)
app.include_router(wallet.router)
# The CLI stream has its own ingest-token authentication. Existing routes are
# admin/lead-only until their data is scoped to project memberships.
if hasattr(incidents, "stream_router"):
    app.include_router(incidents.stream_router)
app.include_router(incidents.router, dependencies=[Depends(get_active_user)])
app.include_router(incidents.legacy_router, dependencies=[Depends(require_admin_or_lead)])
app.include_router(research.router, dependencies=[Depends(require_admin_or_lead), Depends(require_single_organisation)])
app.include_router(simulate.router, dependencies=[Depends(require_admin_or_lead), Depends(require_single_organisation)])
app.include_router(assistant.router, dependencies=[Depends(require_admin_or_lead), Depends(require_single_organisation)])
app.include_router(settings.router, dependencies=[Depends(require_admin_or_lead), Depends(require_single_organisation)])
app.include_router(repositories.router, dependencies=[Depends(require_admin_or_lead), Depends(require_single_organisation)])


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
