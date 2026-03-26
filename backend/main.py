from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import config

config.validate_config()

app = FastAPI(
    title="BreachTrace",
    description="Universal Credential Forensics Platform",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def health_check():
    return {"status": "ok", "message": "BreachTrace running"}


@app.get("/health")
def health():
    return {"status": "ok"}
