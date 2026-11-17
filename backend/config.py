import os
import sys
from dotenv import load_dotenv

load_dotenv()

REQUIRED_KEYS = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_REGION",
    "EXPERIMENT_AWS_ACCESS_KEY_ID",
    "EXPERIMENT_AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "GITHUB_WEBHOOK_SECRET",
    "GITHUB_TEST_REPO",
    "DATABASE_URL",
    "ENVIRONMENT",
]


def validate_config() -> None:
    keys = ["DATABASE_URL"] if os.getenv("BREACHTRACE_LOCAL_TEST_MODE", "").lower() == "true" else REQUIRED_KEYS
    missing = [key for key in keys if not os.getenv(key)]
    if missing:
        for key in missing:
            print(f"[config] MISSING required env var: {key}")
        print(f"\n[config] {len(missing)} required variable(s) not set. Exiting.")
        sys.exit(1)


# Resolved settings — available once validate_config() passes
AWS_ACCESS_KEY_ID: str = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")
AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")

EXPERIMENT_AWS_ACCESS_KEY_ID: str = os.getenv("EXPERIMENT_AWS_ACCESS_KEY_ID", "")
EXPERIMENT_AWS_SECRET_ACCESS_KEY: str = os.getenv("EXPERIMENT_AWS_SECRET_ACCESS_KEY", "")

GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
GITHUB_WEBHOOK_SECRET: str = os.getenv("GITHUB_WEBHOOK_SECRET", "")
GITHUB_TEST_REPO: str = os.getenv("GITHUB_TEST_REPO", "")

# Optional. Reports are written on this machine; Gemini is only an interim
# upgrade provider and the teacher for building the distillation dataset.
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")

# ---------------------------------------------------------------------------
# Local report model + knowledge base (see reporter/local_model.py, rag/)
#
# Everything runs in-process on the CPU. Model files live under MODEL_CACHE_DIR
# (a Docker volume, or the app-data folder of a native install).
# ---------------------------------------------------------------------------
MODEL_CACHE_DIR: str = os.path.expanduser(
    os.getenv("MODEL_CACHE_DIR", os.path.join("~", ".breachtrace", "models"))
)
# Explicit legacy opt-in: local | gemini | none. The Settings UI takes precedence.
# No automatic selection or bundled generative model.
REPORT_PROVIDER: str = os.getenv("REPORT_PROVIDER", "none").lower()
REPORT_MODEL_ENABLED: bool = os.getenv("REPORT_MODEL_ENABLED", "true").lower() in ("1", "true", "yes")
REPORT_MODEL_PATH: str = os.path.expanduser(
    os.getenv("REPORT_MODEL_PATH", os.path.join(MODEL_CACHE_DIR, "breachtrace-reporter-q4_k_m.gguf"))
)
REPORT_MODEL_URL: str = os.getenv("REPORT_MODEL_URL", "")
REPORT_MODEL_SHA256: str = os.getenv("REPORT_MODEL_SHA256", "")
REPORT_MODEL_THREADS: int = int(os.getenv("REPORT_MODEL_THREADS", "0"))  # 0 = cores - 1
# The model runs only with a passing `<model>.gate.json` (research/report_eval.py).
REPORT_MODEL_REQUIRE_GATE: bool = os.getenv("REPORT_MODEL_REQUIRE_GATE", "true").lower() in ("1", "true", "yes")
REPORT_MODEL_IDLE_S: int = int(os.getenv("REPORT_MODEL_IDLE_S", "300"))
GEMINI_REPORT_MODEL: str = os.getenv("GEMINI_REPORT_MODEL", "gemini-2.5-flash")
EMBED_MODEL: str = os.getenv("EMBED_MODEL", "BAAI/bge-small-en-v1.5")

DATABASE_URL: str = os.getenv("DATABASE_URL", "")

ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

# ---------------------------------------------------------------------------
# GCP (optional — system operates AWS-only when absent)
# ---------------------------------------------------------------------------
GCP_PROJECT_ID: str = os.getenv("GCP_PROJECT_ID", "")
GCP_SERVICE_ACCOUNT_JSON: str = os.getenv("GCP_SERVICE_ACCOUNT_JSON", "")
GCP_EXPERIMENT_CLIENT_EMAIL: str = os.getenv("GCP_EXPERIMENT_CLIENT_EMAIL", "")
GCP_EXPERIMENT_PRIVATE_KEY_ID: str = os.getenv("GCP_EXPERIMENT_PRIVATE_KEY_ID", "")
# .env files commonly store PEM newlines as the two characters "\n"
GCP_EXPERIMENT_PRIVATE_KEY: str = os.getenv("GCP_EXPERIMENT_PRIVATE_KEY", "").replace("\\n", "\n")

# ---------------------------------------------------------------------------
# Azure (optional — system operates AWS-only when absent)
# ---------------------------------------------------------------------------
AZURE_TENANT_ID: str = os.getenv("AZURE_TENANT_ID", "")
AZURE_CLIENT_ID: str = os.getenv("AZURE_CLIENT_ID", "")
AZURE_CLIENT_SECRET: str = os.getenv("AZURE_CLIENT_SECRET", "")
AZURE_SUBSCRIPTION_ID: str = os.getenv("AZURE_SUBSCRIPTION_ID", "")
AZURE_EXPERIMENT_CLIENT_ID: str = os.getenv("AZURE_EXPERIMENT_CLIENT_ID", "")
AZURE_EXPERIMENT_CLIENT_SECRET: str = os.getenv("AZURE_EXPERIMENT_CLIENT_SECRET", "")

# ---------------------------------------------------------------------------
# Stripe (optional — SaaS forensic tier)
#
# Test mode is free and fully featured, so STRIPE_API_KEY is normally an
# sk_test_ key. The collector prefers the leaked key itself and falls back to
# this one, which matters because the leaked key is often revoked by the time
# the pipeline runs.
# ---------------------------------------------------------------------------
STRIPE_API_KEY: str = os.getenv("STRIPE_API_KEY", "")
STRIPE_EXPERIMENT_API_KEY: str = os.getenv("STRIPE_EXPERIMENT_API_KEY", "")

# ---------------------------------------------------------------------------
# Twilio (optional — SaaS forensic tier)
# ---------------------------------------------------------------------------
TWILIO_ACCOUNT_SID: str = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN: str = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_API_KEY_SID: str = os.getenv("TWILIO_API_KEY_SID", "")
TWILIO_API_KEY_SECRET: str = os.getenv("TWILIO_API_KEY_SECRET", "")
TWILIO_EXPERIMENT_ACCOUNT_SID: str = os.getenv("TWILIO_EXPERIMENT_ACCOUNT_SID", "")
TWILIO_EXPERIMENT_AUTH_TOKEN: str = os.getenv("TWILIO_EXPERIMENT_AUTH_TOKEN", "")
