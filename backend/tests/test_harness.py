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
        lambda access_key_id, secret_key: ["ListBuckets", "DescribeInstances", "GetCallerIdentity"],
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
        sleep_before_cleanup_s=2,
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
