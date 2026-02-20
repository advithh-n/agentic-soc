"""IAM Privilege Escalation Attack Simulator.

Generates realistic AWS CloudTrail webhook payloads that simulate
an IAM privilege escalation attack sequence.

Attack Pattern:
  1. Attacker (compromised low-privilege IAM user) creates a new IAM user
  2. Attaches AdministratorAccess policy to the new user
  3. Creates access keys for the new user
  4. Modifies S3 bucket policy to allow public access
  5. Opens security group to allow SSH from 0.0.0.0/0

Sends events to the SOC API's /ingest/aws endpoint.

Expected detections:
  - infra.iam_escalation (CreateUser + AttachUserPolicy + CreateAccessKey)
  - infra.s3_unauthorized (PutBucketPolicy with public access)
  - infra.security_group_change (AuthorizeSecurityGroupIngress 0.0.0.0/0)
"""

import asyncio
import time
from uuid import uuid4

import httpx

API_URL = "http://localhost:8050/api/v1/ingest/aws"

# Simulated attacker — compromised low-privilege IAM user
ATTACKER_USER = "dev-intern-jsmith"
ATTACKER_IP = "198.51.100.42"  # External IP (compromised workstation)
ATTACKER_ACCOUNT = "123456789012"

# Target resources
NEW_USER = f"backdoor-{uuid4().hex[:6]}"
TARGET_BUCKET = "heya-credentials-backup"
TARGET_SG = "sg-0a1b2c3d4e5f67890"


def _make_cloudtrail_event(event_name: str, event_source: str,
                            request_params: dict,
                            response_elements: dict | None = None) -> dict:
    """Build a realistic AWS CloudTrail event payload."""
    return {
        "eventVersion": "1.08",
        "eventID": uuid4().hex[:36],
        "eventTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "eventName": event_name,
        "eventSource": event_source,
        "awsRegion": "ap-southeast-4",
        "sourceIPAddress": ATTACKER_IP,
        "userIdentity": {
            "type": "IAMUser",
            "principalId": f"AIDA{uuid4().hex[:16].upper()}",
            "arn": f"arn:aws:iam::{ATTACKER_ACCOUNT}:user/{ATTACKER_USER}",
            "accountId": ATTACKER_ACCOUNT,
            "userName": ATTACKER_USER,
        },
        "userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0",
        "requestParameters": request_params,
        "responseElements": response_elements or {},
    }


def build_attack_sequence() -> list[dict]:
    """Build the full IAM escalation attack sequence."""
    events = []

    # Step 1: CreateUser — attacker creates a new IAM user
    events.append(_make_cloudtrail_event(
        event_name="CreateUser",
        event_source="iam.amazonaws.com",
        request_params={"userName": NEW_USER},
        response_elements={
            "user": {
                "userName": NEW_USER,
                "userId": f"AIDA{uuid4().hex[:16].upper()}",
                "arn": f"arn:aws:iam::{ATTACKER_ACCOUNT}:user/{NEW_USER}",
                "createDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        },
    ))

    # Step 2: AttachUserPolicy — attaches AdministratorAccess
    events.append(_make_cloudtrail_event(
        event_name="AttachUserPolicy",
        event_source="iam.amazonaws.com",
        request_params={
            "userName": NEW_USER,
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
    ))

    # Step 3: CreateAccessKey — generates credentials for the backdoor user
    access_key_id = f"AKIA{uuid4().hex[:16].upper()}"
    events.append(_make_cloudtrail_event(
        event_name="CreateAccessKey",
        event_source="iam.amazonaws.com",
        request_params={"userName": NEW_USER},
        response_elements={
            "accessKey": {
                "accessKeyId": access_key_id,
                "status": "Active",
                "userName": NEW_USER,
                "createDate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        },
    ))

    # Step 4: PutBucketPolicy — modifies S3 bucket policy for public access
    events.append(_make_cloudtrail_event(
        event_name="PutBucketPolicy",
        event_source="s3.amazonaws.com",
        request_params={
            "bucketName": TARGET_BUCKET,
            "bucketPolicy": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "PublicReadGetObject",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{TARGET_BUCKET}/*",
                }],
            },
        },
    ))

    # Step 5: AuthorizeSecurityGroupIngress — opens SSH to 0.0.0.0/0
    events.append(_make_cloudtrail_event(
        event_name="AuthorizeSecurityGroupIngress",
        event_source="ec2.amazonaws.com",
        request_params={
            "groupId": TARGET_SG,
            "ipPermissions": {
                "items": [{
                    "ipProtocol": "tcp",
                    "fromPort": 22,
                    "toPort": 22,
                    "ipRanges": {
                        "items": [{"cidrIp": "0.0.0.0/0"}],
                    },
                }],
            },
        },
    ))

    return events


async def run_iam_escalation(
    api_url: str = API_URL,
    delay_seconds: float = 0.5,
) -> dict:
    """Execute a simulated IAM escalation attack.

    Returns stats about the simulation.
    """
    results = {
        "total_sent": 0,
        "successful_ingests": 0,
        "failed_ingests": 0,
        "trace_ids": [],
        "attacker_user": ATTACKER_USER,
        "attacker_ip": ATTACKER_IP,
        "new_user_created": NEW_USER,
    }

    events = build_attack_sequence()
    step_names = [
        "CreateUser (backdoor account)",
        "AttachUserPolicy (AdministratorAccess)",
        "CreateAccessKey (generate credentials)",
        "PutBucketPolicy (public S3 access)",
        "AuthorizeSecurityGroupIngress (open SSH 0.0.0.0/0)",
    ]

    async with httpx.AsyncClient(timeout=10) as client:
        for i, (event, step_name) in enumerate(zip(events, step_names)):
            try:
                resp = await client.post(api_url, json=event)
                if resp.status_code == 200:
                    data = resp.json()
                    results["successful_ingests"] += 1
                    results["trace_ids"].append(data.get("trace_id"))
                    print(f"  [{i+1}/5] {step_name} -> ingested")
                else:
                    results["failed_ingests"] += 1
                    print(f"  [{i+1}/5] {step_name} -> FAILED: {resp.status_code}")
            except Exception as e:
                results["failed_ingests"] += 1
                print(f"  [{i+1}/5] {step_name} -> ERROR: {e}")

            results["total_sent"] += 1
            await asyncio.sleep(delay_seconds)

    return results


async def main():
    print("=" * 60)
    print("  IAM PRIVILEGE ESCALATION ATTACK SIMULATION")
    print("=" * 60)
    print(f"  Target: {API_URL}")
    print(f"  Attacker IAM user: {ATTACKER_USER}")
    print(f"  Attacker IP: {ATTACKER_IP}")
    print(f"  Backdoor user: {NEW_USER}")
    print("=" * 60)
    print()

    results = await run_iam_escalation(delay_seconds=0.5)

    print()
    print("=" * 60)
    print("  SIMULATION RESULTS")
    print("=" * 60)
    print(f"  Total events sent:     {results['total_sent']}")
    print(f"  Successfully ingested: {results['successful_ingests']}")
    print(f"  Failed to ingest:      {results['failed_ingests']}")
    print(f"  Attacker user:         {results['attacker_user']}")
    print(f"  Attacker IP:           {results['attacker_ip']}")
    print(f"  Backdoor user:         {results['new_user_created']}")
    print()
    print("  Expected alerts triggered:")
    print("    - infra.iam_escalation (CreateUser + AttachUserPolicy + CreateAccessKey)")
    print("    - infra.s3_unauthorized (PutBucketPolicy on credentials bucket)")
    print("    - infra.security_group_change (SSH open to 0.0.0.0/0)")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
