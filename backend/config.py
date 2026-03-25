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
    "GEMINI_API_KEY",
    "DATABASE_URL",
    "ENVIRONMENT",
]


def validate_config() -> None:
    missing = [key for key in REQUIRED_KEYS if not os.getenv(key)]
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

GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")

DATABASE_URL: str = os.getenv("DATABASE_URL", "")

ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
