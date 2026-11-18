"""
Local sentence embeddings for semantic search (optional).

`BAAI/bge-small-en-v1.5` through fastembed: ~70 MB quantised ONNX, CPU only,
about 10 ms per query. Loaded once on first use and cached under
MODEL_CACHE_DIR. If fastembed is missing, or EMBED_ENABLED is false, search
degrades to keyword-only rather than failing.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any

import config

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_model: Any = None
_failed = False


def enabled() -> bool:
    return os.getenv("EMBED_ENABLED", "true").lower() in ("1", "true", "yes")


def get_embedder() -> Any | None:
    """The fastembed model, or None when embeddings are unavailable."""
    global _model, _failed
    if not enabled() or _failed:
        return None
    with _lock:
        if _model is None:
            try:
                from fastembed import TextEmbedding

                import model_settings
                offline = model_settings.current().offline_models_only or os.getenv("BREACHTRACE_MODELS_OFFLINE", "false").lower() in ("1", "true", "yes")
                _model = TextEmbedding(config.EMBED_MODEL, cache_dir=config.MODEL_CACHE_DIR,
                                       local_files_only=offline)
                logger.info("[SEARCH] Embedding model %s ready", config.EMBED_MODEL)
            except Exception:
                logger.exception("[SEARCH] Embedding model unavailable; keyword search only")
                _failed = True
                return None
    return _model


def embed(texts: list[str]) -> list[Any] | None:
    """Unit-normalised float32 vectors, or None when embeddings are unavailable."""
    model = get_embedder()
    if model is None or not texts:
        return None
    import numpy as np

    vectors = np.asarray(list(model.embed(texts)), dtype=np.float32)
    vectors /= np.linalg.norm(vectors, axis=1, keepdims=True) + 1e-12
    return list(vectors)


def embed_query(text: str) -> Any | None:
    """Query vector. bge models expect this instruction prefix for retrieval queries."""
    vectors = embed(["Represent this sentence for searching relevant passages: " + text])
    return vectors[0] if vectors else None
