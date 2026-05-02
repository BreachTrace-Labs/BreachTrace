from __future__ import annotations

import argparse
import os
import random
import string
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

import boto3
from botocore.exceptions import ClientError


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
    """Legacy placeholder for Day-6 loop integration."""
    return {
        "run_number": run_number,
        "status": "not_implemented",
        "message": "Use CLI scenarios for now: python -m research.harness --scenario ...",
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
    return parser


def main() -> None:
    args = build_parser().parse_args()
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
