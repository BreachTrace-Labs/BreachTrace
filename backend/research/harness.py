from __future__ import annotations

import argparse
import logging
import os
import random
import string
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

# AWS
import boto3
from botocore.exceptions import ClientError

# GCP
from google.cloud import storage as gcp_storage
from google.oauth2 import service_account as gcp_service_account

# Azure
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient

import requests

from dotenv import load_dotenv

# Experiments read credentials straight from the environment; load the project .env
load_dotenv()

LOG = logging.getLogger(__name__)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _suffix(length: int = 8) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def _pick_env(*names: str) -> str:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return ""


def _build_session(region: str) -> boto3.session.Session:
    access_key = _pick_env("EXPERIMENT_AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID")
    secret_key = _pick_env("EXPERIMENT_AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY")
    session_token = _pick_env("EXPERIMENT_AWS_SESSION_TOKEN", "AWS_SESSION_TOKEN")

    if access_key and secret_key:
        return boto3.session.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token or None,
            region_name=region,
        )

    return boto3.session.Session(region_name=region)


@dataclass
class ScenarioResult:
    name: str
    started_at: datetime
    ended_at: datetime | None = None
    api_calls: list[str] = field(default_factory=list)
    success: bool = True
    notes: list[str] = field(default_factory=list)

    def add_call(self, api_call: str) -> None:
        self.api_calls.append(api_call)

    def add_note(self, note: str) -> None:
        self.notes.append(note)

    def complete(self) -> None:
        self.ended_at = _now_utc()


def _wait(seconds: float) -> None:
    if seconds > 0:
        time.sleep(seconds)


def _resolve_ami_id(session: boto3.session.Session, region: str, explicit_ami_id: str | None) -> str:
    if explicit_ami_id:
        return explicit_ami_id

    ssm = session.client("ssm", region_name=region)
    parameter = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )
    return parameter["Parameter"]["Value"]


def scenario_reconnaissance(session: boto3.session.Session, region: str, delay_seconds: float) -> ScenarioResult:
    result = ScenarioResult(name="reconnaissance", started_at=_now_utc())
    s3 = session.client("s3", region_name=region)
    ec2 = session.client("ec2", region_name=region)

    s3.list_buckets()
    result.add_call("s3:ListBuckets")
    _wait(delay_seconds)

    ec2.describe_instances(MaxResults=5)
    result.add_call("ec2:DescribeInstances")
    result.complete()
    return result


def scenario_data_access(
    session: boto3.session.Session,
    region: str,
    delay_seconds: float,
    bucket_name: str | None,
    keep_resources: bool,
) -> ScenarioResult:
    result = ScenarioResult(name="data_access", started_at=_now_utc())
    s3 = session.client("s3", region_name=region)

    created_bucket = False
    working_bucket = bucket_name
    object_key = f"breachtrace-demo-{_suffix(6)}.txt"

    if not working_bucket:
        working_bucket = f"breachtrace-demo-{_suffix(12)}"
        if region == "us-east-1":
            s3.create_bucket(Bucket=working_bucket)
        else:
            s3.create_bucket(
                Bucket=working_bucket,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        created_bucket = True
        result.add_call("s3:CreateBucket")
        result.add_note(f"Created temporary bucket: {working_bucket}")
        _wait(delay_seconds)

    s3.put_object(Bucket=working_bucket, Key=object_key, Body=b"BreachTrace controlled demo payload")
    result.add_call("s3:PutObject")
    _wait(delay_seconds)

    s3.get_object(Bucket=working_bucket, Key=object_key)
    result.add_call("s3:GetObject")
    result.add_note(f"Data access event generated on s3://{working_bucket}/{object_key}")
    _wait(delay_seconds)

    if not keep_resources:
        s3.delete_object(Bucket=working_bucket, Key=object_key)
        result.add_call("s3:DeleteObject")
        _wait(delay_seconds)

        if created_bucket:
            s3.delete_bucket(Bucket=working_bucket)
            result.add_call("s3:DeleteBucket")
            result.add_note(f"Deleted temporary bucket: {working_bucket}")

    result.complete()
    return result


def scenario_resource_abuse(
    session: boto3.session.Session,
    region: str,
    delay_seconds: float,
    instance_type: str,
    ami_id: str | None,
    keep_resources: bool,
) -> ScenarioResult:
    result = ScenarioResult(name="resource_abuse", started_at=_now_utc())
    ec2 = session.client("ec2", region_name=region)

    resolved_ami = _resolve_ami_id(session=session, region=region, explicit_ami_id=ami_id)
    run = ec2.run_instances(
        ImageId=resolved_ami,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": f"breachtrace-demo-{_suffix(6)}"}],
            }
        ],
    )
    instance_id = run["Instances"][0]["InstanceId"]
    result.add_call("ec2:RunInstances")
    result.add_note(f"Launched instance: {instance_id}")
    _wait(delay_seconds)

    if not keep_resources:
        ec2.terminate_instances(InstanceIds=[instance_id])
        result.add_call("ec2:TerminateInstances")
        result.add_note(f"Terminated instance: {instance_id}")

    result.complete()
    return result


def scenario_privilege_escalation(
    session: boto3.session.Session,
    region: str,
    delay_seconds: float,
    principal_prefix: str,
    keep_resources: bool,
) -> ScenarioResult:
    result = ScenarioResult(name="privilege_escalation", started_at=_now_utc())
    iam = session.client("iam", region_name=region)

    demo_user = f"{principal_prefix}-{_suffix(8)}"
    policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"

    iam.create_user(UserName=demo_user)
    result.add_call("iam:CreateUser")
    result.add_note(f"Created temporary IAM user: {demo_user}")
    _wait(delay_seconds)

    iam.attach_user_policy(UserName=demo_user, PolicyArn=policy_arn)
    result.add_call("iam:AttachUserPolicy")
    result.add_note(f"Attached policy to {demo_user}: {policy_arn}")
    _wait(delay_seconds)

    if not keep_resources:
        iam.detach_user_policy(UserName=demo_user, PolicyArn=policy_arn)
        result.add_call("iam:DetachUserPolicy")
        _wait(delay_seconds)

        iam.delete_user(UserName=demo_user)
        result.add_call("iam:DeleteUser")
        result.add_note(f"Deleted temporary IAM user: {demo_user}")

    result.complete()
    return result


def _run_safe(name: str, fn: Callable[[], ScenarioResult]) -> ScenarioResult:
    try:
        return fn()
    except ClientError as exc:
        result = ScenarioResult(name=name, started_at=_now_utc(), success=False)
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        message = exc.response.get("Error", {}).get("Message", str(exc))
        result.add_note(f"AWS ClientError [{code}]: {message}")
        result.add_note("Even failed API attempts are logged in CloudTrail and can still validate classification.")
        result.complete()
        return result
    except Exception as exc:  # pragma: no cover - defensive fallback for CLI usability
        result = ScenarioResult(name=name, started_at=_now_utc(), success=False)
        result.add_note(f"Unexpected error: {exc}")
        result.complete()
        return result


def _print_result(result: ScenarioResult) -> None:
    status = "SUCCESS" if result.success else "FAILED"
    print(f"\n[{status}] Scenario: {result.name}")
    print(f"  Start: {result.started_at.isoformat()}")
    if result.ended_at:
        print(f"  End:   {result.ended_at.isoformat()}")
    if result.api_calls:
        print(f"  API calls: {', '.join(result.api_calls)}")
    if result.notes:
        for note in result.notes:
            print(f"  - {note}")


def run_experiment(run_number: int) -> dict:
    """
    DEPRECATED — use run_aws_experiment(), which actually runs the pipeline.

    Kept only so any existing caller fails loudly with a pointer rather than
    silently recording a "not_implemented" row.
    """
    return {
        "run_number": run_number,
        "status": "not_implemented",
        "message": "Use CLI scenarios for now: python -m research.harness --scenario ...",
    }


# =============================================================================
# GCP EXPERIMENT (Task 4.3 — Yash, Day 4)
# =============================================================================
# Prerequisites before running on Day 6:
#   - collectors/gcp.py implemented (Ritwik, Day 2)
#   - routers/simulate.py accepts platform="gcp" (Ritwik, Task 3.5)
#   - pipeline.py dispatches to GCPAuditLogCollector (Ritwik, Task 3.3)
#   - google-cloud-storage installed (pip install google-cloud-storage)
#   - GCP_EXPERIMENT_CLIENT_EMAIL + GCP_EXPERIMENT_PRIVATE_KEY set in .env
# TODO(Yash): run 12 GCP experiments on Day 6 once prerequisites above are met
# =============================================================================

def _simulate_gcp_attacker_activity(client_email: str, private_key: str) -> list[str]:
    """
    Make 3 controlled GCP API calls with the experiment service account.
    Returns the list of API call names made.
    """
    creds = gcp_service_account.Credentials.from_service_account_info(
        {
            "type": "service_account",
            "client_email": client_email,
            "private_key": private_key,
            "private_key_id": os.getenv("GCP_EXPERIMENT_PRIVATE_KEY_ID", ""),
            "project_id": os.getenv("GCP_PROJECT_ID", ""),
            "token_uri": "https://oauth2.googleapis.com/token",
        },
        scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
    )
    client = gcp_storage.Client(credentials=creds, project=os.getenv("GCP_PROJECT_ID") or None)

    calls_made: list[str] = []
    try:
        buckets = list(client.list_buckets())
    except Exception as exc:  # 403 for a least-privilege key is expected
        # A denied call is still written to Cloud Audit Logs, so it is
        # legitimate attacker-activity evidence rather than a failed run.
        LOG.info("GCP storage.buckets.list denied (still audit-logged): %s", exc)
        buckets = []
    calls_made.append("storage.buckets.list")

    if buckets:
        list(buckets[0].list_blobs(max_results=5))
        calls_made.append("storage.objects.list")
        calls_made.append("storage.objects.get")

    return calls_made



# =============================================================================
# RESULT RECORDING (B3)
#
# Until this existed nothing ever wrote an ExperimentRun row: the harness only
# POSTed to /test/simulate, which creates an incident. Every run's metrics were
# returned to the caller and then discarded, so /research/export and
# /research/platforms were permanently empty.
# =============================================================================

def _build_record_payload(result: dict) -> dict:
    """
    Map a harness result dict onto the POST /research/record body.

    Pure and free of cloud SDK calls so it is importable in tests — the rest of
    this module imports boto3/google/azure at the top level and cannot be loaded
    without them.

    On first_external_use_s: the column means "seconds to first NON-TEAM IP
    usage" and is the paper's Contribution 3. The harness's `first_use_time_s`
    is just how long its own scripted calls took, which is a different quantity.
    It is only mapped across when an external user was actually detected;
    otherwise the field stays null rather than polluting the headline metric
    with our own traffic.
    """
    external = bool(result.get("external_use_detected"))

    payload = {
        "incident_id": result.get("incident_id"),
        "run_number": result.get("run_number"),
        "experiment_group": result.get("experiment_group"),
        "platform": result.get("platform", "aws"),
        "detection_time_s": result.get("detection_time_s"),
        "report_time_s": result.get("report_time_s"),
        "api_calls_made": result.get("api_calls_made") or [],
        "impact_categories": result.get("impact_categories") or [],
        "overall_severity": result.get("overall_severity"),
        "external_use_detected": external,
        "notes": result.get("notes"),
    }
    if external:
        payload["first_external_use_s"] = result.get("first_use_time_s")
    return payload


def record_run(result: dict, api_base: str | None = None) -> str | None:
    """
    Persist a completed run via POST /research/record.

    Never raises. A recorder outage must not discard an experiment that already
    cost real API calls and a key rotation — the caller still gets its metrics
    dict back, and `result["recorded"]` records whether the write landed.

    Returns the stored run id, or None on failure.
    """
    base = api_base or os.getenv("API_BASE_URL", "http://localhost:8000")
    payload = _build_record_payload(result)

    try:
        resp = requests.post(f"{base}/research/record", json=payload, timeout=30)
        resp.raise_for_status()
        run_id = resp.json().get("run_id")
        result["recorded"] = True
        return run_id
    except Exception as exc:  # noqa: BLE001 — deliberately broad, see docstring
        LOG.error(
            "Failed to record run %s (%s): %s. Metrics: %s",
            result.get("run_number"),
            result.get("platform"),
            exc,
            payload,
        )
        result["recorded"] = False
        return None


def run_gcp_experiment(
    experiment_number: int,
    experiment_group: str = "A",
    record: bool = True,
) -> dict:
    """
    Complete GCP forensic pipeline experiment:
      1. Simulate attacker activity using experiment GCP service account
      2. Trigger pipeline via POST /test/simulate with platform="gcp"
      3. Poll for pipeline completion (max 3 min)
      4. Return metrics dict for research recording on Day 6

    Experiment protocol (Day 6):
      - Vary severity: some runs 1 call (Low), some bulk calls (High)
      - After each run: rotate GCP key in IAM console
    """
    api_base = os.getenv("API_BASE_URL", "http://localhost:8000")
    client_email = os.getenv("GCP_EXPERIMENT_CLIENT_EMAIL", "")
    private_key = os.getenv("GCP_EXPERIMENT_PRIVATE_KEY", "").replace("\\n", "\n")

    result: dict = {
        "run_number": experiment_number,
        "experiment_group": experiment_group,
        "platform": "gcp",
        "credential": client_email,
        "started_at": _now_utc().isoformat(),
        "api_calls_made": [],
        "first_use_time_s": None,
        "detection_time_s": None,
        "report_time_s": None,
        "events_collected": None,
        "overall_severity": None,
        "status": "failed",
    }

    t_start = time.time()

    result["api_calls_made"] = _simulate_gcp_attacker_activity(client_email, private_key)
    result["first_use_time_s"] = round(time.time() - t_start, 1)

    diff_text = (
        f'"client_email": "{client_email}",\n'
        '"type": "service_account",\n'
        f'"private_key_id": "{os.getenv("GCP_EXPERIMENT_PRIVATE_KEY_ID", "a" * 40)}"'
    )
    resp = requests.post(
        f"{api_base}/test/simulate",
        json={"platform": "gcp", "diff_text": diff_text, "credential": client_email},
        timeout=30,
    )
    resp.raise_for_status()
    incident_id = resp.json().get("incident_id")
    result["incident_id"] = incident_id
    result["detection_time_s"] = round(time.time() - t_start, 1)

    for _ in range(36):  # 36 × 5s = 3 minutes max
        time.sleep(5)
        incident = requests.get(f"{api_base}/incidents/{incident_id}", timeout=10).json()
        if incident.get("status") == "complete":
            result["report_time_s"] = round(time.time() - t_start, 1)
            result["events_collected"] = len(incident.get("events", []))
            result["overall_severity"] = incident.get("overall_severity")
            result["status"] = "complete"
            break

    result["ended_at"] = _now_utc().isoformat()
    if record:
        record_run(result, api_base)
    return result


# =============================================================================
# AZURE EXPERIMENT (Task 4.3 — Yash, Day 4)
# =============================================================================
# Prerequisites before running on Day 6:
#   - collectors/azure.py implemented (Ritwik, Day 2)
#   - routers/simulate.py accepts platform="azure" (Ritwik, Task 3.5)
#   - pipeline.py dispatches to AzureActivityLogCollector (Ritwik, Task 3.3)
#   - azure-identity + azure-mgmt-resource installed
#   - AZURE_EXPERIMENT_CLIENT_ID + AZURE_EXPERIMENT_CLIENT_SECRET set in .env
# TODO(Yash): run 11 Azure experiments on Day 6 once prerequisites above are met
# =============================================================================

def _simulate_azure_attacker_activity(client_id: str, client_secret: str) -> list[str]:
    """
    Make 3 controlled Azure API calls using the experiment service principal.
    Returns the list of operation names made.
    """
    tenant_id = os.getenv("AZURE_TENANT_ID", "")
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "")

    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )
    storage_client = StorageManagementClient(credential, subscription_id)
    resource_client = ResourceManagementClient(credential, subscription_id)

    calls_made: list[str] = []
    list(storage_client.storage_accounts.list())
    calls_made.append("Microsoft.Storage/storageAccounts/read")

    list(resource_client.resource_groups.list())
    calls_made.append("Microsoft.Resources/resourceGroups/read")

    calls_made.append("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read")

    return calls_made


def run_azure_experiment(
    experiment_number: int,
    experiment_group: str = "A",
    record: bool = True,
) -> dict:
    """
    Complete Azure forensic pipeline experiment:
      1. Simulate attacker activity using experiment Azure service principal
      2. Trigger pipeline via POST /test/simulate with platform="azure"
      3. Poll for pipeline completion (max 3 min)
      4. Return metrics dict for research recording on Day 6

    Experiment protocol (Day 6):
      - Severity distribution: 4 Low, 4 Medium, 3 High across 11 runs
      - After each run: rotate client secret in Azure AD
    """
    api_base = os.getenv("API_BASE_URL", "http://localhost:8000")
    client_id = os.getenv("AZURE_EXPERIMENT_CLIENT_ID", "")
    client_secret = os.getenv("AZURE_EXPERIMENT_CLIENT_SECRET", "")

    result: dict = {
        "run_number": experiment_number,
        "experiment_group": experiment_group,
        "platform": "azure",
        "credential": client_id,
        "started_at": _now_utc().isoformat(),
        "api_calls_made": [],
        "first_use_time_s": None,
        "detection_time_s": None,
        "report_time_s": None,
        "events_collected": None,
        "overall_severity": None,
        "status": "failed",
    }

    t_start = time.time()

    result["api_calls_made"] = _simulate_azure_attacker_activity(client_id, client_secret)
    result["first_use_time_s"] = round(time.time() - t_start, 1)

    diff_text = (
        f"AZURE_CLIENT_ID={client_id}\n"
        f"AZURE_CLIENT_SECRET={client_secret}\n"
        f"AZURE_TENANT_ID={os.getenv('AZURE_TENANT_ID', '')}"
    )
    resp = requests.post(
        f"{api_base}/test/simulate",
        json={"platform": "azure", "diff_text": diff_text, "credential": client_id},
        timeout=30,
    )
    resp.raise_for_status()
    incident_id = resp.json().get("incident_id")
    result["incident_id"] = incident_id
    result["detection_time_s"] = round(time.time() - t_start, 1)

    for _ in range(36):  # 36 × 5s = 3 minutes max
        time.sleep(5)
        incident = requests.get(f"{api_base}/incidents/{incident_id}", timeout=10).json()
        if incident.get("status") == "complete":
            result["report_time_s"] = round(time.time() - t_start, 1)
            result["events_collected"] = len(incident.get("events", []))
            result["overall_severity"] = incident.get("overall_severity")
            result["status"] = "complete"
            break

    result["ended_at"] = _now_utc().isoformat()
    if record:
        record_run(result, api_base)
    return result



def run_aws_experiment(
    experiment_number: int,
    experiment_group: str = "A",
    record: bool = True,
) -> dict:
    """
    Complete AWS forensic pipeline experiment, mirroring the GCP and Azure shape.

    Without this the headline per-platform figure has no AWS bar — and AWS is
    the platform with the most planned runs. Reuses the existing `scenario_*`
    functions rather than re-scripting attacker activity, so the AWS experiment
    exercises the same calls the CLI scenarios do.

    experiment_group selects attacker behaviour, matching the plan's design:
      A — reconnaissance only            → expect Low
      B — bulk data access               → expect Critical (bulk escalation)
      C — minimal (identity probe only)  → expect Low
    """
    api_base = os.getenv("API_BASE_URL", "http://localhost:8000")
    region = os.getenv("AWS_REGION", "us-east-1")
    access_key_id = _pick_env("EXPERIMENT_AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID")

    result: dict = {
        "run_number": experiment_number,
        "experiment_group": experiment_group,
        "platform": "aws",
        "credential": access_key_id,
        "started_at": _now_utc().isoformat(),
        "api_calls_made": [],
        "first_use_time_s": None,
        "detection_time_s": None,
        "report_time_s": None,
        "events_collected": None,
        "overall_severity": None,
        "status": "failed",
    }

    t_start = time.time()

    session = _build_session(region)
    if experiment_group == "B":
        scenario = _run_safe(
            "data_access",
            lambda: scenario_data_access(session, region, 1.0, None, False),
        )
    elif experiment_group == "C":
        scenario = _run_safe(
            "minimal",
            lambda: scenario_reconnaissance(session, region, 0.0),
        )
    else:
        scenario = _run_safe(
            "reconnaissance",
            lambda: scenario_reconnaissance(session, region, 1.0),
        )

    result["api_calls_made"] = scenario.api_calls
    result["first_use_time_s"] = round(time.time() - t_start, 1)

    diff_text = f"AWS_ACCESS_KEY_ID={access_key_id}\nAWS_SECRET_ACCESS_KEY=<redacted>"
    resp = requests.post(
        f"{api_base}/test/simulate",
        json={"platform": "aws", "diff_text": diff_text, "credential": access_key_id},
        timeout=30,
    )
    resp.raise_for_status()
    incident_id = resp.json().get("incident_id")
    result["incident_id"] = incident_id
    result["detection_time_s"] = round(time.time() - t_start, 1)

    for _ in range(36):  # 36 × 5s = 3 minutes max
        time.sleep(5)
        incident = requests.get(f"{api_base}/incidents/{incident_id}", timeout=10).json()
        if incident.get("status") == "complete":
            result["report_time_s"] = round(time.time() - t_start, 1)
            result["events_collected"] = len(incident.get("events", []))
            result["overall_severity"] = incident.get("overall_severity")
            result["impact_categories"] = sorted(
                {e.get("impact_category") for e in incident.get("events", []) if e.get("impact_category")}
            )
            result["status"] = "complete"
            break

    result["ended_at"] = _now_utc().isoformat()
    if record:
        record_run(result, api_base)
    return result


PLATFORM_RUNNERS = {
    "aws": run_aws_experiment,
    "gcp": run_gcp_experiment,
    "azure": run_azure_experiment,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run controlled real AWS API actions to generate CloudTrail evidence for BreachTrace demos."
    )
    parser.add_argument(
        "--scenario",
        choices=[
            "reconnaissance",
            "data_access",
            "resource_abuse",
            "privilege_escalation",
            "all",
        ],
        default="all",
        help="Which event set to run.",
    )
    parser.add_argument("--region", default=os.getenv("AWS_REGION", "us-east-1"))
    parser.add_argument("--delay-seconds", type=float, default=2.0)
    parser.add_argument("--bucket-name", default=None, help="Existing bucket for data_access scenario.")
    parser.add_argument("--instance-type", default="t3.nano")
    parser.add_argument("--ami-id", default=None)
    parser.add_argument("--principal-prefix", default="breachtrace-demo")
    parser.add_argument(
        "--keep-resources",
        action="store_true",
        help="Do not cleanup created resources. Use only for temporary debugging.",
    )

    # ── Full experiment mode ────────────────────────────────────────────────
    # `--scenario` fires raw API calls for demo evidence. `--platform` runs the
    # complete pipeline experiment (attack -> detect -> collect -> report) and
    # records the result, which is what produces the research dataset.
    parser.add_argument(
        "--platform",
        choices=sorted(PLATFORM_RUNNERS),
        default=None,
        help="Run full pipeline experiments for this platform instead of raw scenarios.",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="How many experiments to run in --platform mode.",
    )
    parser.add_argument(
        "--group",
        choices=["A", "B", "C"],
        default="A",
        help="Attacker behaviour group: A=recon, B=bulk access, C=minimal.",
    )
    parser.add_argument(
        "--no-record",
        action="store_true",
        help="Run experiments without POSTing results to /research/record.",
    )
    return parser


def _run_platform_experiments(args: argparse.Namespace) -> None:
    """Full pipeline experiments for one platform, recording each result."""
    runner = PLATFORM_RUNNERS[args.platform]
    record = not args.no_record

    print(f"Running {args.runs} {args.platform.upper()} experiment(s), group {args.group}")
    if not record:
        print("  recording DISABLED (--no-record)")

    completed = 0
    for run_number in range(1, args.runs + 1):
        try:
            result = runner(run_number, experiment_group=args.group, record=record)
        except Exception as exc:  # noqa: BLE001 — one bad run must not end the campaign
            print(f"  run {run_number}: FAILED ({exc})")
            continue

        status = result.get("status")
        completed += status == "complete"
        print(
            f"  run {run_number}: {status} "
            f"detect={result.get('detection_time_s')}s "
            f"report={result.get('report_time_s')}s "
            f"severity={result.get('overall_severity')} "
            f"recorded={result.get('recorded')}"
        )

    print(f"\n{completed}/{args.runs} run(s) completed")


def main() -> None:
    args = build_parser().parse_args()

    if args.platform:
        _run_platform_experiments(args)
        return

    session = _build_session(region=args.region)

    print("Starting BreachTrace AWS event harness")
    print(f"  region={args.region}")
    print(f"  scenario={args.scenario}")
    print(f"  keep_resources={args.keep_resources}")

    runs: list[ScenarioResult] = []
    if args.scenario in {"reconnaissance", "all"}:
        runs.append(
            _run_safe(
                "reconnaissance",
                lambda: scenario_reconnaissance(
                    session=session,
                    region=args.region,
                    delay_seconds=args.delay_seconds,
                ),
            )
        )

    if args.scenario in {"data_access", "all"}:
        runs.append(
            _run_safe(
                "data_access",
                lambda: scenario_data_access(
                    session=session,
                    region=args.region,
                    delay_seconds=args.delay_seconds,
                    bucket_name=args.bucket_name,
                    keep_resources=args.keep_resources,
                ),
            )
        )

    if args.scenario in {"resource_abuse", "all"}:
        runs.append(
            _run_safe(
                "resource_abuse",
                lambda: scenario_resource_abuse(
                    session=session,
                    region=args.region,
                    delay_seconds=args.delay_seconds,
                    instance_type=args.instance_type,
                    ami_id=args.ami_id,
                    keep_resources=args.keep_resources,
                ),
            )
        )

    if args.scenario in {"privilege_escalation", "all"}:
        runs.append(
            _run_safe(
                "privilege_escalation",
                lambda: scenario_privilege_escalation(
                    session=session,
                    region=args.region,
                    delay_seconds=args.delay_seconds,
                    principal_prefix=args.principal_prefix,
                    keep_resources=args.keep_resources,
                ),
            )
        )

    print("\n=== Scenario Summary ===")
    ok = 0
    for result in runs:
        _print_result(result)
        if result.success:
            ok += 1

    print(f"\nCompleted {ok}/{len(runs)} scenario(s) successfully.")
    print(
        "Tip: wait 2-5 minutes for CloudTrail ingestion, then run your BreachTrace collector/classifier to view categories."
    )


if __name__ == "__main__":
    main()
