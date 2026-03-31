from __future__ import annotations

from types import SimpleNamespace

import pytest

from research import harness


class _FakeGithubException(Exception):
    def __init__(self, status: int):
        super().__init__(f"GitHub error {status}")
        self.status = status


class _FakeRepo:
    def __init__(self, existing=None):
        self.default_branch = "main"
        self.existing = existing
        self.created = []
        self.updated = []
        self.deleted = []

    def get_contents(self, path, ref=None):
        if self.existing is None:
            raise _FakeGithubException(404)
        return self.existing

    def create_file(self, path, message, content, branch=None):
        self.created.append((path, message, content, branch))
        return {"commit": SimpleNamespace(sha="commit-create")}

    def update_file(self, path, message, content, sha, branch=None):
        self.updated.append((path, message, content, sha, branch))
        return {"commit": SimpleNamespace(sha="commit-update")}

    def delete_file(self, path, message, sha, branch=None):
        self.deleted.append((path, message, sha, branch))
        return {"commit": SimpleNamespace(sha="commit-delete")}


def test_push_fake_credential_creates_file_when_missing(monkeypatch):
    repo = _FakeRepo()
    monkeypatch.setattr(harness, "_github_repo", lambda: repo)
    monkeypatch.setattr(harness, "GithubException", _FakeGithubException)

    result = harness.push_fake_credential("AKIA1234567890ABCDEF", "secret-value")

    assert result["action"] == "created"
    assert result["commit_sha"] == "commit-create"
    assert repo.created == [
        (
            "config.env",
            harness.DEFAULT_PUSH_MESSAGE,
            "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\nAWS_SECRET_ACCESS_KEY=secret-value\n",
            "main",
        )
    ]


def test_push_fake_credential_updates_existing_file(monkeypatch):
    existing = SimpleNamespace(sha="old-sha")
    repo = _FakeRepo(existing=existing)
    monkeypatch.setattr(harness, "_github_repo", lambda: repo)
    monkeypatch.setattr(harness, "GithubException", _FakeGithubException)

    result = harness.push_fake_credential("AKIA1234567890ABCDEF", "secret-value")

    assert result["action"] == "updated"
    assert result["commit_sha"] == "commit-update"
    assert repo.updated == [
        (
            "config.env",
            harness.DEFAULT_PUSH_MESSAGE,
            "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\nAWS_SECRET_ACCESS_KEY=secret-value\n",
            "old-sha",
            "main",
        )
    ]


def test_delete_credential_from_repo_deletes_existing_file(monkeypatch):
    existing = SimpleNamespace(sha="old-sha")
    repo = _FakeRepo(existing=existing)
    monkeypatch.setattr(harness, "_github_repo", lambda: repo)
    monkeypatch.setattr(harness, "GithubException", _FakeGithubException)

    result = harness.delete_credential_from_repo()

    assert result["action"] == "deleted"
    assert result["commit_sha"] == "commit-delete"
    assert repo.deleted == [
        (
            "config.env",
            harness.DEFAULT_DELETE_MESSAGE,
            "old-sha",
            "main",
        )
    ]


def test_revoke_iam_key_resolves_username_from_access_key_lookup(monkeypatch):
    calls = {}

    class _FakeIAMClient:
        def get_access_key_last_used(self, AccessKeyId):
            calls["lookup"] = AccessKeyId
            return {"UserName": "experiment-user-1"}

        def delete_access_key(self, UserName, AccessKeyId):
            calls["delete"] = (UserName, AccessKeyId)

    monkeypatch.setattr(harness, "_admin_iam_client", lambda: _FakeIAMClient())

    result = harness.revoke_iam_key("AKIA1234567890ABCDEF")

    assert result == {
        "access_key_id": "AKIA1234567890ABCDEF",
        "user_name": "experiment-user-1",
        "status": "revoked",
    }
    assert calls == {
        "lookup": "AKIA1234567890ABCDEF",
        "delete": ("experiment-user-1", "AKIA1234567890ABCDEF"),
    }


def test_run_experiment_uses_config_defaults_and_orchestrates_steps(monkeypatch):
    monkeypatch.setattr(harness.config, "EXPERIMENT_AWS_ACCESS_KEY_ID", "AKIADEFAULT123456789")
    monkeypatch.setattr(harness.config, "EXPERIMENT_AWS_SECRET_ACCESS_KEY", "default-secret")

    recorded = {"sleep": []}

    monkeypatch.setattr(
        harness,
        "push_fake_credential",
        lambda access_key_id, secret_key, path="config.env": {
            "step": "push",
            "access_key_id": access_key_id,
            "secret_key": secret_key,
            "path": path,
        },
    )
    monkeypatch.setattr(
        harness,
        "simulate_attacker_activity",
        lambda access_key_id, secret_key, experiment_group="A": [
            "ListBuckets",
            "DescribeInstances",
            "GetCallerIdentity",
        ],
    )
    monkeypatch.setattr(
        harness,
        "delete_credential_from_repo",
        lambda path="config.env": {"step": "cleanup", "path": path},
    )
    monkeypatch.setattr(
        harness,
        "revoke_iam_key",
        lambda access_key_id: {"step": "revoke", "access_key_id": access_key_id},
    )
    monkeypatch.setattr(harness.time, "sleep", lambda seconds: recorded["sleep"].append(seconds))

    result = harness.run_experiment(
        14,
        wait_before_activity_s=0,
        wait_after_activity_s=2,
        revoke_after_run=True,
    )

    assert result["run_number"] == 14
    assert result["experiment_group"] == "B"
    assert result["access_key_id"] == "AKIADEFAULT123456789"
    assert result["api_calls_made"] == ["ListBuckets", "DescribeInstances", "GetCallerIdentity"]
    assert result["push_result"]["step"] == "push"
    assert result["cleanup_result"]["step"] == "cleanup"
    assert result["revoke_result"]["step"] == "revoke"
    assert result["revoked"] is True
    assert recorded["sleep"] == [2]


def test_run_experiment_raises_when_credentials_missing(monkeypatch):
    monkeypatch.setattr(harness.config, "EXPERIMENT_AWS_ACCESS_KEY_ID", "")
    monkeypatch.setattr(harness.config, "EXPERIMENT_AWS_SECRET_ACCESS_KEY", "")

    with pytest.raises(ValueError, match="Experiment AWS credentials are required"):
        harness.run_experiment(1)


def test_find_incident_for_run_matches_repo_hint_and_start_time(monkeypatch):
    monkeypatch.setattr(
        harness,
        "_api_get_json",
        lambda api_base_url, path, params=None: [
            {
                "incident_id": "old",
                "repo_url": "https://github.com/example/repo",
                "credential_hint": "AKIA****CDEF",
                "exposure_start": "2026-03-31T09:59:59+00:00",
                "created_at": "2026-03-31T10:00:05+00:00",
            },
            {
                "incident_id": "match",
                "repo_url": "https://github.com/example/repo",
                "credential_hint": "AKIA****CDEF",
                "exposure_start": "2026-03-31T10:00:00+00:00",
                "created_at": "2026-03-31T10:00:07+00:00",
            },
        ],
    )

    incident = harness.find_incident_for_run(
        "http://localhost:8000",
        repo_url="https://github.com/example/repo",
        access_key_id="AKIA1234567890ABCDEF",
        exposure_start=harness.datetime(2026, 3, 31, 10, 0, tzinfo=harness.timezone.utc),
    )

    assert incident["incident_id"] == "match"


def test_poll_incident_until_complete_returns_finished_incident(monkeypatch):
    calls = {"count": 0}

    def fake_get(api_base_url, path, params=None):
        calls["count"] += 1
        if calls["count"] == 1:
            return {"incident_id": "incident-1", "status": "classifying"}
        return {"incident_id": "incident-1", "status": "complete", "events": []}

    monkeypatch.setattr(harness, "_api_get_json", fake_get)
    monkeypatch.setattr(harness.time, "sleep", lambda seconds: None)

    incident = harness.poll_incident_until_complete(
        "http://localhost:8000",
        "incident-1",
        poll_interval_s=0,
        timeout_s=1,
    )

    assert incident["status"] == "complete"
    assert calls["count"] == 2


def test_run_experiment_waits_for_incident_when_requested(monkeypatch):
    monkeypatch.setattr(harness.config, "EXPERIMENT_AWS_ACCESS_KEY_ID", "AKIADEFAULT123456789")
    monkeypatch.setattr(harness.config, "EXPERIMENT_AWS_SECRET_ACCESS_KEY", "default-secret")

    monkeypatch.setattr(
        harness,
        "push_fake_credential",
        lambda access_key_id, secret_key, path="config.env": {
            "repo": "https://github.com/example/repo",
            "path": path,
            "action": "created",
            "commit_sha": "commit-1",
        },
    )
    monkeypatch.setattr(
        harness,
        "simulate_attacker_activity",
        lambda access_key_id, secret_key, experiment_group="A": ["GetCallerIdentity"],
    )
    monkeypatch.setattr(
        harness,
        "wait_for_incident",
        lambda *args, **kwargs: {
            "incident_id": "incident-1",
            "created_at": "2026-03-31T10:00:05+00:00",
        },
    )
    monkeypatch.setattr(
        harness,
        "poll_incident_until_complete",
        lambda *args, **kwargs: {
            "incident_id": "incident-1",
            "status": "complete",
            "overall_severity": 1,
            "events": [{"impact_category": "reconnaissance"}],
        },
    )
    monkeypatch.setattr(
        harness,
        "delete_credential_from_repo",
        lambda path="config.env": {"step": "cleanup", "path": path},
    )
    monkeypatch.setattr(harness.time, "sleep", lambda seconds: None)

    class _FrozenDateTime:
        moments = iter(
            [
                harness.datetime(2026, 3, 31, 10, 0, 0, tzinfo=harness.timezone.utc),
                harness.datetime(2026, 3, 31, 10, 1, 0, tzinfo=harness.timezone.utc),
                harness.datetime(2026, 3, 31, 10, 2, 0, tzinfo=harness.timezone.utc),
            ]
        )

        @classmethod
        def now(cls, tz=None):
            return next(cls.moments)

        @classmethod
        def fromisoformat(cls, value):
            from datetime import datetime as _real_datetime

            return _real_datetime.fromisoformat(value)

    monkeypatch.setattr(harness, "datetime", _FrozenDateTime)

    result = harness.run_experiment(
        1,
        api_base_url="http://localhost:8000",
        wait_before_activity_s=0,
        wait_after_activity_s=0,
        wait_for_completion=True,
    )

    assert result["incident_id"] == "incident-1"
    assert result["detection_time_s"] == 5.0
    assert result["report_time_s"] == 120.0
    assert result["impact_categories"] == ["reconnaissance"]
    assert result["overall_severity"] == 1
