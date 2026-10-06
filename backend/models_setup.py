"""
Fetch the model files BreachTrace runs locally, once, into MODEL_CACHE_DIR.

    python -m models_setup            # from backend/

After this, reports and search work fully offline. A native installer can run
this at build time and ship the folder instead.

  * Embedding model (search): BAAI/bge-small-en-v1.5, ~64 MB.
  * Report model: the distilled GGUF, downloaded from REPORT_MODEL_URL and
    verified against REPORT_MODEL_SHA256. Skipped until a model has passed the
    quality gate (research/report_eval.py) and been published.
"""
from __future__ import annotations

import hashlib
import os
import sys
import urllib.request

import config


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def setup_embeddings() -> None:
    from rag import embedder

    if embedder.get_embedder() is None:
        sys.exit("Embedding model could not be loaded — is fastembed installed?")
    print(f"embedding model ready: {config.EMBED_MODEL} in {config.MODEL_CACHE_DIR}")


def setup_report_model() -> None:
    path = config.REPORT_MODEL_PATH
    if os.path.isfile(path):
        print(f"report model present: {path}")
    elif not config.REPORT_MODEL_URL:
        print("report model: no REPORT_MODEL_URL set — reports use the template writer")
        return
    else:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        print(f"downloading report model from {config.REPORT_MODEL_URL} ...")
        partial = path + ".part"
        urllib.request.urlretrieve(config.REPORT_MODEL_URL, partial)
        os.replace(partial, path)

    if config.REPORT_MODEL_SHA256 and _sha256(path) != config.REPORT_MODEL_SHA256.lower():
        os.remove(path)
        sys.exit("report model checksum mismatch — file removed")
    manifest_url = config.REPORT_MODEL_URL and config.REPORT_MODEL_URL + ".gate.json"
    manifest = path + ".gate.json"
    if manifest_url and not os.path.isfile(manifest):
        urllib.request.urlretrieve(manifest_url, manifest)
    print(f"report model ready: {path} ({os.path.getsize(path) / 1e6:.0f} MB)")


if __name__ == "__main__":
    os.makedirs(config.MODEL_CACHE_DIR, exist_ok=True)
    setup_embeddings()
    setup_report_model()
