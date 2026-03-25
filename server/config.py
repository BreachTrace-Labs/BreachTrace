from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # AWS admin credentials (for CloudTrail queries)
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_REGION: str = "us-east-1"

    # AWS experiment user (read-only key that gets "leaked")
    EXPERIMENT_AWS_ACCESS_KEY_ID: str = ""
    EXPERIMENT_AWS_SECRET_ACCESS_KEY: str = ""

    # GitHub
    GITHUB_TOKEN: str = ""
    GITHUB_WEBHOOK_SECRET: str = ""
    GITHUB_TEST_REPO: str = ""

    # Gemini
    GEMINI_API_KEY: str = ""

    # Database
    DATABASE_URL: str = "postgresql://user:password@localhost:5432/breachtrace"

    # App
    ENVIRONMENT: str = "development"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
