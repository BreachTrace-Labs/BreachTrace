"""Shared Azure plumbing: ARM REST client, secret rotation, scratch RG, cleanup."""
from __future__ import annotations

import os
import random
import string
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable

import requests

import config
from research.scenarios.base import Scenario

MGMT = "https://management.azure.com"
GRAPH = "https://graph.microsoft.com/v1.0"
RG_API = "2021-04-01"
RG_WRITE = "Microsoft.Resources/subscriptions/resourceGroups/write"


class ArmError(RuntimeError):
    pass


def _sfx(n: int = 6) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


class Arm:
    """Tiny ARM REST client authenticated as the *experiment* service principal."""

    def __init__(self, tenant: str, client_id: str, secret: str, sub: str) -> None:
        from azure.identity import ClientSecretCredential

        self.sub = sub
        self.cred = ClientSecretCredential(tenant, client_id, secret)

    def _headers(self) -> dict:
        tok = self.cred.get_token("https://management.azure.com/.default").token
        return {"Authorization": f"Bearer {tok}"}

    def call(self, method: str, path: str, api: str, body: dict | None = None,
             allow: tuple[int, ...] = ()) -> requests.Response:
        """`allow` = extra status codes that are fine (used for denied-but-logged calls)."""
        r = requests.request(method, MGMT + path, params={"api-version": api},
                             json=body, headers=self._headers(), timeout=90)
        if r.status_code >= 400 and r.status_code not in allow:
            raise ArmError(f"{method} {path} -> {r.status_code}: {r.text[:400]}")
        return r

    def wait_provisioned(self, path: str, api: str, timeout: int = 900) -> None:
        t0 = time.time()
        while time.time() - t0 < timeout:
            r = self.call("GET", path, api, allow=(404,))
            if r.status_code == 200:
                state = (r.json().get("properties") or {}).get("provisioningState", "Succeeded")
                if state == "Succeeded":
                    return
                if state in ("Failed", "Canceled"):
                    raise ArmError(f"{path} provisioning {state}")
            time.sleep(8)
        raise ArmError(f"timeout waiting for {path}")

    def wait_gone(self, path: str, api: str, timeout: int = 900) -> bool:
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self.call("GET", path, api, allow=(404,)).status_code == 404:
                return True
            time.sleep(10)
        return False


class AzureScenario(Scenario):
    platform = "azure"
    location_default = "eastus"

    def __init__(self) -> None:
        super().__init__()
        self.sfx = _sfx()
        self.rg = f"breachtrace-scenario-{self.id.lower()}-{self.sfx}"
        self.location = os.getenv("AZURE_SCENARIO_LOCATION", self.location_default)
        self.sub = config.AZURE_SUBSCRIPTION_ID
        self.tenant = config.AZURE_TENANT_ID
        self.app_id = config.AZURE_EXPERIMENT_CLIENT_ID
        self.secret = ""
        self._key_id: str | None = None
        self.arm: Arm | None = None
        self._undo: list[tuple[str, Callable[[], None]]] = []
        self._rg_created = False

    # -- credentials ----------------------------------------------------------
    def credential_id(self) -> str:
        return self.app_id

    def _graph(self, method: str, path: str, body: dict) -> requests.Response:
        from azure.identity import ClientSecretCredential

        admin = ClientSecretCredential(config.AZURE_TENANT_ID, config.AZURE_CLIENT_ID,
                                       config.AZURE_CLIENT_SECRET)
        tok = admin.get_token("https://graph.microsoft.com/.default").token
        return requests.request(method, GRAPH + path, json=body,
                                headers={"Authorization": f"Bearer {tok}"}, timeout=30)

    def acquire(self) -> None:
        """Mint a fresh one-hour secret for this scenario (the 'leaked' key)."""
        if not (self.sub and self.tenant and self.app_id):
            raise RuntimeError("AZURE_TENANT_ID / SUBSCRIPTION_ID / EXPERIMENT_CLIENT_ID not set")
        end = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        r = self._graph("POST", f"/applications(appId='{self.app_id}')/addPassword",
                        {"passwordCredential": {"displayName": f"breachtrace-{self.id}", "endDateTime": end}})
        if r.status_code == 200:
            self.secret, self._key_id = r.json()["secretText"], r.json()["keyId"]
            self.note("minted a fresh per-scenario client secret via Graph")
        else:
            self.secret = config.AZURE_EXPERIMENT_CLIENT_SECRET
            self.note(f"Graph addPassword unavailable ({r.status_code}); using "
                      "AZURE_EXPERIMENT_CLIENT_SECRET - rotate it manually afterwards")
        self.arm = Arm(self.tenant, self.app_id, self.secret, self.sub)
        for _ in range(12):  # new secrets take ~30-60 s to propagate
            try:
                self.arm._headers()
                return
            except Exception:
                time.sleep(10)
        raise RuntimeError("experiment secret never became usable")

    def revoke(self) -> str:
        if not self._key_id:
            return "MANUAL: rotate AZURE_EXPERIMENT_CLIENT_SECRET in Entra ID"
        r = self._graph("POST", f"/applications(appId='{self.app_id}')/removePassword",
                        {"keyId": self._key_id})
        if r.status_code not in (200, 204):
            return f"FAILED to remove secret ({r.status_code}) - remove it manually"
        from window.azure_revocation import is_azure_key_revoked

        for _ in range(12):
            if is_azure_key_revoked(self.app_id, self.secret):
                return "secret removed; Entra confirms it is rejected"
            time.sleep(15)
        return "secret removed; Entra still accepting it (propagation lag)"

    def leak_diff_text(self) -> str:
        return (f"AZURE_CLIENT_ID={self.app_id}\nAZURE_CLIENT_SECRET={self.secret}\n"
                f"AZURE_TENANT_ID={self.tenant}")

    # -- ARM helpers ----------------------------------------------------------
    def name(self, prefix: str, maxlen: int = 24) -> str:
        return (prefix + self.sfx + _sfx(4))[:maxlen]

    def rg_path(self, suffix: str = "") -> str:
        return f"/subscriptions/{self.sub}/resourceGroups/{self.rg}{suffix}"

    def call(self, label: str, method: str, path: str, api: str, body: dict | None = None,
             allow: tuple[int, ...] = ()) -> requests.Response:
        r = self.arm.call(method, path, api, body, allow)
        self.api_calls.append(label)
        return r

    def ensure_rg(self) -> None:
        self.call("resourceGroups/write", "PUT", self.rg_path(), RG_API,
                  {"location": self.location, "tags": {"breachtrace-scenario": self.id}})
        self._rg_created = True

    def put(self, label: str, suffix: str, api: str, body: dict, wait: bool = True) -> None:
        self.call(label, "PUT", self.rg_path(suffix), api, body)
        if wait:
            self.arm.wait_provisioned(self.rg_path(suffix), api)

    def undo(self, label: str, fn: Callable[[], None]) -> None:
        self._undo.append((label, fn))

    # -- cleanup --------------------------------------------------------------
    def cleanup(self) -> None:
        if not self.arm:
            return
        for label, fn in reversed(self._undo):
            try:
                fn()
            except Exception as exc:
                self.note(f"undo '{label}' failed: {exc}")
        if self._rg_created:
            self.arm.call("DELETE", self.rg_path(), RG_API, allow=(404,))
            gone = self.arm.wait_gone(self.rg_path(), RG_API)
            self.note(f"resource group {self.rg} deleted and verified: {gone}")
            if not gone:
                raise RuntimeError(f"resource group {self.rg} still exists")

    # -- audit log visibility (via the reader/admin identity) -----------------
    def audit_visible(self, since: datetime) -> bool:
        from collectors.azure import AzureActivityLogCollector

        events = AzureActivityLogCollector().collect(self.app_id, since - timedelta(minutes=5),
                                                     datetime.now(timezone.utc))
        seen = {e.api_action for e in events}
        need = {x.api_action for x in self.expected if not x.optional}
        if self.expected_blind:
            return True  # nothing to wait for; min_wait_s enforces the observation window
        return need.issubset(seen)


def new_guid() -> str:
    return str(uuid.uuid4())
