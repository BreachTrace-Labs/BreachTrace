"""
POST /assistant/search — natural-language search over incidents and the knowledge base
GET  /assistant/status — what is installed and indexed

Retrieval only: answers are matching incidents and verbatim passages with their
sources. No text is generated, so nothing can be invented.
"""
from __future__ import annotations

import logging
import threading
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

import config
from db.database import SessionLocal, get_db
from rag import embedder
from rag.index import ensure_kb, stats
from rag.search import answer
from reporter.local_model import LocalReportModel, get_local_model

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/assistant", tags=["assistant"])


class SearchRequest(BaseModel):
    question: str = Field(..., min_length=2, max_length=500)
    incident_id: Optional[str] = None
    limit: int = Field(5, ge=1, le=20)


@router.post("/search")
def assistant_search(body: SearchRequest, db: Session = Depends(get_db)):
    return answer(db, body.question, incident_id=body.incident_id, k=body.limit)


@router.get("/status")
def assistant_status(db: Session = Depends(get_db)):
    model = get_local_model()
    return {
        "index": stats(db),
        "semantic_search": embedder.get_embedder() is not None,
        "embedding_model": config.EMBED_MODEL if embedder.enabled() else None,
        "report_model": {
            "enabled": config.REPORT_MODEL_ENABLED,
            "installed": model is not None,
            "runtime_installed": LocalReportModel.runtime_installed(),
            "path": config.REPORT_MODEL_PATH,
            "provider": config.REPORT_PROVIDER,
        },
    }


def warm_index_in_background() -> None:
    """Build the knowledge-base index at startup so the first search is instant."""

    def _warm() -> None:
        db = SessionLocal()
        try:
            ensure_kb(db)
        except Exception:
            db.rollback()
            logger.exception("[SEARCH] Knowledge-base warm-up failed; it will retry on first search")
        finally:
            db.close()

    threading.Thread(target=_warm, name="kb-warmup", daemon=True).start()
