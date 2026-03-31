from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

import boto3
from github import Github, GithubException

import config

logger = logging.getLogger(__name__)

DEFAULT_LEAK_PATH = "config.env"
DEFAULT_EXPERIMENT_USER_NAME = "breachtrace-experiment"
DEFAULT_PUSH_MESSAGE = "test: leak experiment aws key"
DEFAULT_DELETE_MESSAGE = "test: remove leaked experiment aws key"


def _experiment_group_for_run(run_number: int) -> str:
    if 1 <= run_number <= 12:
        return "A"
    if 13 <= run_number <= 25:
        return "B"
    if 26 <= run_number <= 35:
        return "C"
    return "unknown"


def _credential_file_contents(access_key_id: str, secret_key: str) -> str:
    return (
        f"AWS_ACCESS_KEY_ID={access_key_id}\n"
        f"AWS_SECRET_ACCESS_KEY={secret_key}\n"
    )


def _github_repo():
    gh = Github(config.GITHUB_TOKEN)
    return gh.get_repo(config.GITHUB_TEST_REPO)


def _admin_iam_client():
    return boto3.client(
        "iam",
        region_name=config.AWS_REGION,
        aws_access_key_id=config.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
    )


def push_fake_credential(
    access_key_id: str,
    secret_key: str,
    *,
    path: str = DEFAULT_LEAK_PATH,
    commit_message: str = DEFAULT_PUSH_MESSAGE,
) -> dict[str, str]:
    """
    Create or update the leaked credential file in the public GitHub test repo.

    The file is intentionally written to the *separate* public test repo so the
    webhook path can detect it like a real leak.
    """
    repo = _github_repo()
    branch = repo.default_branch
    content = _credential_file_contents(access_key_id, secret_key)

    try:
        existing = repo.get_contents(path, ref=branch)
    except GithubException as exc:
        if getattr(exc, "status", None) != 404:
            raise
        existing = None

    if existing is None:
        result = repo.create_file(path, commit_message, content, branch=branch)
        action = "created"
    else:
        result = repo.update_file(
            path,
            commit_message,
            content,
            existing.sha,
            branch=branch,
        )
        action = "updated"

    commit_sha = result["commit"].sha
    logger.info(
        "Credential file %s in %s at %s (commit=%s)",
        action,
        config.GITHUB_TEST_REPO,
        path,
        commit_sha,
    )
    return {
        "repo": config.GITHUB_TEST_REPO,
        "path": path,
        "action": action,
        "commit_sha": commit_sha,
    }


def simulate_attacker_activity(access_key_id: str, secret_key: str) -> list[str]:
    """
    Use the experiment key to generate safe CloudTrail activity.

    Returns the AWS API action names that were successfully called.
    """
    session = boto3.session.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_key,
        region_name=config.AWS_REGION,
    )

    s3 = session.client("s3")
    ec2 = session.client("ec2")
    sts = session.client("sts")

    api_calls: list[str] = []

    s3.list_buckets()
    api_calls.append("ListBuckets")

    ec2.describe_instances()
    api_calls.append("DescribeInstances")

    sts.get_caller_identity()
    api_calls.append("GetCallerIdentity")

    logger.info("Simulated attacker activity with %d AWS calls", len(api_calls))
    return api_calls


def delete_credential_from_repo(
    *,
    path: str = DEFAULT_LEAK_PATH,
    commit_message: str = DEFAULT_DELETE_MESSAGE,
) -> dict[str, str]:
    """Delete the leaked credential file from the public GitHub test repo."""
    repo = _github_repo()
    branch = repo.default_branch

    try:
        existing = repo.get_contents(path, ref=branch)
    except GithubException as exc:
        if getattr(exc, "status", None) == 404:
            raise FileNotFoundError(
                f"{path} does not exist in {config.GITHUB_TEST_REPO}"
            ) from exc
        raise

    result = repo.delete_file(
        path,
        commit_message,
        existing.sha,
        branch=branch,
    )
    commit_sha = result["commit"].sha
    logger.info("Deleted leaked credential file from %s (commit=%s)", path, commit_sha)
    return {
        "repo": config.GITHUB_TEST_REPO,
        "path": path,
        "action": "deleted",
        "commit_sha": commit_sha,
    }


def _resolve_iam_user_name(iam_client, access_key_id: str) -> str:
    lookup = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
    user_name = lookup.get("UserName")
    if user_name:
        return user_name

    return os.getenv("EXPERIMENT_AWS_IAM_USER", DEFAULT_EXPERIMENT_USER_NAME)


def revoke_iam_key(access_key_id: str) -> dict[str, str]:
    """
    Delete the leaked IAM access key using the admin credentials.

    The owning IAM user is resolved from AWS so the helper works with both the
    default experiment user and rotated per-run keys.
    """
    iam = _admin_iam_client()
    user_name = _resolve_iam_user_name(iam, access_key_id)
    iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
    logger.info("Revoked IAM key %s for user %s", access_key_id, user_name)
    return {
        "access_key_id": access_key_id,
        "user_name": user_name,
        "status": "revoked",
    }


def run_experiment(
    run_number: int,
    *,
    access_key_id: str | None = None,
    secret_key: str | None = None,
    leak_path: str = DEFAULT_LEAK_PATH,
    sleep_before_cleanup_s: float = 0.0,
    revoke_after_run: bool = False,
) -> dict[str, Any]:
    """
    Execute one experiment run using either the provided key pair or the
    experiment key configured in local environment variables.

    The return value is a structured summary that Day 6 code can later enrich
    with incident timings and DB persistence.
    """
    key_id = access_key_id or config.EXPERIMENT_AWS_ACCESS_KEY_ID
    secret = secret_key or config.EXPERIMENT_AWS_SECRET_ACCESS_KEY

    if not key_id or not secret:
        raise ValueError("Experiment AWS credentials are required to run the harness")

    exposure_start = datetime.now(tz=timezone.utc)
    push_result = push_fake_credential(key_id, secret, path=leak_path)

    attacker_sim_start = datetime.now(tz=timezone.utc)
    api_calls_made = simulate_attacker_activity(key_id, secret)

    if sleep_before_cleanup_s > 0:
        time.sleep(sleep_before_cleanup_s)

    cleanup_result = delete_credential_from_repo(path=leak_path)

    revoke_result: dict[str, str] | None = None
    if revoke_after_run:
        revoke_result = revoke_iam_key(key_id)

    result: dict[str, Any] = {
        "run_number": run_number,
        "experiment_group": _experiment_group_for_run(run_number),
        "access_key_id": key_id,
        "repo": config.GITHUB_TEST_REPO,
        "leak_path": leak_path,
        "exposure_start": exposure_start,
        "attacker_sim_start": attacker_sim_start,
        "api_calls_made": api_calls_made,
        "push_result": push_result,
        "cleanup_result": cleanup_result,
        "revoked": revoke_result is not None,
        "revoke_result": revoke_result,
    }
    logger.info(
        "Experiment run %s complete: group=%s revoked=%s",
        run_number,
        result["experiment_group"],
        result["revoked"],
    )
    return result
