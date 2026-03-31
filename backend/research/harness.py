from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Callable
from urllib import parse, request

import json

import boto3
from github import Github, GithubException

import config

logger = logging.getLogger(__name__)

DEFAULT_LEAK_PATH = "config.env"
DEFAULT_EXPERIMENT_USER_NAME = "breachtrace-experiment"
DEFAULT_PUSH_MESSAGE = "test: leak experiment aws key"
DEFAULT_DELETE_MESSAGE = "test: remove leaked experiment aws key"
DEFAULT_WAIT_BEFORE_ACTIVITY_S = 60.0
DEFAULT_WAIT_AFTER_ACTIVITY_S = 120.0
DEFAULT_POLL_INTERVAL_S = 10.0
DEFAULT_POLL_TIMEOUT_S = 180.0
DEFAULT_BATCH_RUNS = 35
DEFAULT_LOCAL_API_BASE_URL = "http://localhost:8000"

KeyProvider = Callable[[int], tuple[str, str]]


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


def _credential_hint(access_key_id: str) -> str:
    return f"{access_key_id[:4]}****{access_key_id[-4:]}"


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _api_get_json(api_base_url: str, path: str, params: dict[str, Any] | None = None) -> Any:
    base_url = api_base_url.rstrip("/")
    query = f"?{parse.urlencode(params)}" if params else ""
    url = f"{base_url}{path}{query}"

    with request.urlopen(url) as response:
        return json.loads(response.read().decode("utf-8"))


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


def simulate_attacker_activity(
    access_key_id: str,
    secret_key: str,
    *,
    experiment_group: str = "A",
) -> list[str]:
    """
    Use the experiment key to generate safe CloudTrail activity.

    Returns the AWS API action names that were successfully called.
    """
    session = boto3.session.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_key,
        region_name=config.AWS_REGION,
    )

    sts = session.client("sts")
    s3 = session.client("s3")
    ec2 = session.client("ec2")

    api_calls: list[str] = []

    if experiment_group == "A":
        s3.list_buckets()
        api_calls.append("ListBuckets")

        ec2.describe_instances()
        api_calls.append("DescribeInstances")

        sts.get_caller_identity()
        api_calls.append("GetCallerIdentity")
    elif experiment_group == "B":
        # Uses the same safe calls repeatedly so the harness can be finished
        # without assuming bucket/object fixtures that do not exist in config.
        s3.list_buckets()
        api_calls.append("ListBuckets")
        for _ in range(5):
            sts.get_caller_identity()
            api_calls.append("GetCallerIdentity")
    elif experiment_group == "C":
        sts.get_caller_identity()
        api_calls.append("GetCallerIdentity")
    else:
        raise ValueError(f"Unknown experiment group: {experiment_group}")

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


def find_incident_for_run(
    api_base_url: str,
    *,
    repo_url: str,
    access_key_id: str,
    exposure_start: datetime,
    limit: int = 50,
) -> dict[str, Any] | None:
    """
    Find the most likely incident created by a harness run using existing
    GET /incidents data only.
    """
    incidents = _api_get_json(api_base_url, "/incidents", {"limit": limit})
    expected_hint = _credential_hint(access_key_id)

    matches: list[dict[str, Any]] = []
    for incident in incidents:
        if incident.get("repo_url") != repo_url:
            continue
        if incident.get("credential_hint") != expected_hint:
            continue

        incident_exposure_start = _parse_iso_datetime(incident.get("exposure_start"))
        if incident_exposure_start is None:
            continue
        if incident_exposure_start >= exposure_start:
            matches.append(incident)

    if not matches:
        return None

    matches.sort(key=lambda incident: incident.get("created_at", ""), reverse=True)
    return matches[0]


def wait_for_incident(
    api_base_url: str,
    *,
    repo_url: str,
    access_key_id: str,
    exposure_start: datetime,
    poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
    timeout_s: float = DEFAULT_POLL_TIMEOUT_S,
) -> dict[str, Any]:
    """Poll GET /incidents until the harness-created incident appears."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        incident = find_incident_for_run(
            api_base_url,
            repo_url=repo_url,
            access_key_id=access_key_id,
            exposure_start=exposure_start,
        )
        if incident is not None:
            return incident
        time.sleep(poll_interval_s)

    raise TimeoutError("Timed out waiting for the incident to appear in /incidents")


def poll_incident_until_complete(
    api_base_url: str,
    incident_id: str,
    *,
    poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
    timeout_s: float = DEFAULT_POLL_TIMEOUT_S,
) -> dict[str, Any]:
    """Poll GET /incidents/{id} until status='complete' or timeout."""
    deadline = time.monotonic() + timeout_s
    last_seen: dict[str, Any] | None = None

    while time.monotonic() < deadline:
        incident = _api_get_json(api_base_url, f"/incidents/{incident_id}")
        last_seen = incident
        if incident.get("status") == "complete":
            return incident
        time.sleep(poll_interval_s)

    raise TimeoutError(
        f"Timed out waiting for incident {incident_id} to reach status='complete'; "
        f"last status was {last_seen.get('status') if last_seen else 'unknown'}"
    )


def run_experiment_batch(
    *,
    total_runs: int = DEFAULT_BATCH_RUNS,
    key_provider: KeyProvider | None = None,
    api_base_url: str | None = None,
    wait_for_completion: bool = False,
    **run_kwargs: Any,
) -> list[dict[str, Any]]:
    """
    Run multiple experiments sequentially.

    If ``key_provider`` is omitted, the configured experiment key is reused for
    every run. A future key-manager can be plugged in without changing the
    harness API.
    """
    results: list[dict[str, Any]] = []

    for run_number in range(1, total_runs + 1):
        access_key_id: str | None = None
        secret_key: str | None = None
        if key_provider is not None:
            access_key_id, secret_key = key_provider(run_number)

        result = run_experiment(
            run_number,
            access_key_id=access_key_id,
            secret_key=secret_key,
            api_base_url=api_base_url,
            wait_for_completion=wait_for_completion,
            **run_kwargs,
        )
        results.append(result)

    return results


def run_experiment(
    run_number: int,
    *,
    access_key_id: str | None = None,
    secret_key: str | None = None,
    leak_path: str = DEFAULT_LEAK_PATH,
    api_base_url: str | None = None,
    wait_before_activity_s: float = DEFAULT_WAIT_BEFORE_ACTIVITY_S,
    wait_after_activity_s: float = DEFAULT_WAIT_AFTER_ACTIVITY_S,
    poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
    poll_timeout_s: float = DEFAULT_POLL_TIMEOUT_S,
    wait_for_completion: bool = False,
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

    experiment_group = _experiment_group_for_run(run_number)
    exposure_start = datetime.now(tz=timezone.utc)
    push_result = push_fake_credential(key_id, secret, path=leak_path)

    if wait_before_activity_s > 0:
        time.sleep(wait_before_activity_s)

    attacker_sim_start = datetime.now(tz=timezone.utc)
    api_calls_made = simulate_attacker_activity(
        key_id,
        secret,
        experiment_group=experiment_group,
    )

    if wait_after_activity_s > 0:
        time.sleep(wait_after_activity_s)

    incident_summary: dict[str, Any] | None = None
    incident_detail: dict[str, Any] | None = None
    detection_time_s: float | None = None
    report_time_s: float | None = None
    if wait_for_completion:
        if not api_base_url:
            raise ValueError("api_base_url is required when wait_for_completion=True")

        incident_summary = wait_for_incident(
            api_base_url,
            repo_url=push_result["repo"],
            access_key_id=key_id,
            exposure_start=exposure_start,
            poll_interval_s=poll_interval_s,
            timeout_s=poll_timeout_s,
        )
        created_at = _parse_iso_datetime(incident_summary.get("created_at"))
        if created_at is not None:
            detection_time_s = (created_at - exposure_start).total_seconds()

        incident_detail = poll_incident_until_complete(
            api_base_url,
            incident_summary["incident_id"],
            poll_interval_s=poll_interval_s,
            timeout_s=poll_timeout_s,
        )
        report_time_s = (
            datetime.now(tz=timezone.utc) - exposure_start
        ).total_seconds()

    cleanup_result = delete_credential_from_repo(path=leak_path)

    revoke_result: dict[str, str] | None = None
    if revoke_after_run:
        revoke_result = revoke_iam_key(key_id)

    result: dict[str, Any] = {
        "run_number": run_number,
        "experiment_group": experiment_group,
        "access_key_id": key_id,
        "repo": config.GITHUB_TEST_REPO,
        "leak_path": leak_path,
        "exposure_start": exposure_start,
        "attacker_sim_start": attacker_sim_start,
        "api_calls_made": api_calls_made,
        "incident_id": incident_summary.get("incident_id") if incident_summary else None,
        "incident_summary": incident_summary,
        "incident_detail": incident_detail,
        "detection_time_s": detection_time_s,
        "report_time_s": report_time_s,
        "overall_severity": incident_detail.get("overall_severity") if incident_detail else None,
        "impact_categories": sorted(
            {
                event["impact_category"]
                for event in incident_detail.get("events", [])
                if event.get("impact_category")
            }
        ) if incident_detail else [],
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
