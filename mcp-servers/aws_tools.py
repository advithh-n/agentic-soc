"""AWS CloudTrail Tool Router — query CloudTrail events and IAM activity.

Mock implementation for development. Returns simulated data that matches
the real CloudTrail API response structure. When AWS credentials are
configured, swap mock for boto3 calls.
"""

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import structlog
from fastapi import APIRouter
from pydantic import BaseModel

logger = structlog.get_logger()

router = APIRouter(prefix="/aws", tags=["aws"])


# ─── Request/Response Schemas ────────────────────────────

class QueryCloudTrailRequest(BaseModel):
    event_name: str | None = None      # e.g., "CreateUser", "AuthorizeSecurityGroupIngress"
    user_name: str | None = None       # IAM user to filter by
    start_time: str | None = None      # ISO 8601 datetime
    end_time: str | None = None        # ISO 8601 datetime
    max_results: int = 20


class GetIAMActivityRequest(BaseModel):
    user_name: str                     # IAM user or role name
    hours_back: int = 24               # How far back to look
    max_results: int = 50


# ─── Mock Data Generator ────────────────────────────────

def _mock_cloudtrail_event(event_name: str, user_name: str,
                            source_ip: str = "203.0.113.50",
                            minutes_ago: int = 5) -> dict:
    """Generate a realistic mock CloudTrail event."""
    event_time = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)

    event_source_map = {
        "CreateUser": "iam.amazonaws.com",
        "AttachUserPolicy": "iam.amazonaws.com",
        "PutRolePolicy": "iam.amazonaws.com",
        "CreateAccessKey": "iam.amazonaws.com",
        "DeleteAccessKey": "iam.amazonaws.com",
        "GetObject": "s3.amazonaws.com",
        "PutObject": "s3.amazonaws.com",
        "PutBucketPolicy": "s3.amazonaws.com",
        "AuthorizeSecurityGroupIngress": "ec2.amazonaws.com",
        "CreateSecurityGroup": "ec2.amazonaws.com",
        "RunInstances": "ec2.amazonaws.com",
        "ConsoleLogin": "signin.amazonaws.com",
    }

    return {
        "eventVersion": "1.08",
        "eventID": uuid4().hex[:36],
        "eventTime": event_time.isoformat(),
        "eventName": event_name,
        "eventSource": event_source_map.get(event_name, "aws.amazonaws.com"),
        "awsRegion": os.getenv("AWS_REGION", "ap-southeast-4"),
        "sourceIPAddress": source_ip,
        "userIdentity": {
            "type": "IAMUser",
            "principalId": f"AIDA{uuid4().hex[:16].upper()}",
            "arn": f"arn:aws:iam::123456789012:user/{user_name}",
            "accountId": "123456789012",
            "userName": user_name,
        },
        "userAgent": "aws-cli/2.13.0 Python/3.11.4",
        "requestParameters": {},
        "responseElements": {},
    }


def _generate_mock_events(event_name: str | None, user_name: str | None,
                           max_results: int) -> list[dict]:
    """Generate a set of mock CloudTrail events for development."""
    events = []

    # If specific event_name requested, return matching mock events
    if event_name:
        for i in range(min(3, max_results)):
            evt = _mock_cloudtrail_event(
                event_name=event_name,
                user_name=user_name or "mock-user",
                source_ip=f"203.0.113.{50 + i}",
                minutes_ago=i * 5 + 1,
            )
            events.append(evt)
    else:
        # Return a mix of common events
        common_events = [
            "ConsoleLogin", "GetObject", "PutObject",
            "CreateUser", "AttachUserPolicy",
            "AuthorizeSecurityGroupIngress",
        ]
        for i, en in enumerate(common_events[:max_results]):
            evt = _mock_cloudtrail_event(
                event_name=en,
                user_name=user_name or "mock-user",
                minutes_ago=i * 10 + 1,
            )
            events.append(evt)

    return events


def _generate_mock_iam_activity(user_name: str, max_results: int) -> list[dict]:
    """Generate mock IAM-related activity for a specific user."""
    iam_events = [
        ("ConsoleLogin", 5),
        ("CreateUser", 15),
        ("AttachUserPolicy", 16),
        ("CreateAccessKey", 18),
        ("PutBucketPolicy", 25),
        ("GetObject", 30),
        ("ListBuckets", 35),
        ("AuthorizeSecurityGroupIngress", 40),
    ]

    events = []
    for event_name, minutes_ago in iam_events[:max_results]:
        evt = _mock_cloudtrail_event(
            event_name=event_name,
            user_name=user_name,
            minutes_ago=minutes_ago,
        )
        # Add relevant request parameters
        if event_name == "CreateUser":
            evt["requestParameters"] = {"userName": f"new-user-{uuid4().hex[:6]}"}
        elif event_name == "AttachUserPolicy":
            evt["requestParameters"] = {
                "userName": user_name,
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            }
        elif event_name == "CreateAccessKey":
            evt["requestParameters"] = {"userName": user_name}
            evt["responseElements"] = {
                "accessKey": {
                    "accessKeyId": f"AKIA{uuid4().hex[:16].upper()}",
                    "status": "Active",
                    "userName": user_name,
                }
            }
        events.append(evt)

    return events


# ─── Tool Endpoints ──────────────────────────────────────

@router.post("/query-cloudtrail")
async def query_cloudtrail(req: QueryCloudTrailRequest):
    """Query CloudTrail events by event name, user, and time range.

    Mock implementation — returns simulated data for development.
    In production, swap for boto3 CloudTrail lookup_events().
    """
    aws_key = os.getenv("AWS_ACCESS_KEY_ID", "")

    if aws_key:
        # TODO: Real boto3 implementation when AWS credentials are available
        logger.info("aws.cloudtrail.query", event_name=req.event_name,
                     user=req.user_name, note="real_aws_not_implemented")

    events = _generate_mock_events(
        event_name=req.event_name,
        user_name=req.user_name,
        max_results=req.max_results,
    )

    logger.debug("aws.cloudtrail.mock_query", event_name=req.event_name,
                  results=len(events))

    return {
        "mock": not bool(aws_key),
        "events": events,
        "count": len(events),
        "filters": {
            "event_name": req.event_name,
            "user_name": req.user_name,
            "start_time": req.start_time,
            "end_time": req.end_time,
        },
    }


@router.post("/get-iam-activity")
async def get_iam_activity(req: GetIAMActivityRequest):
    """Get IAM-related events for a specific user or role.

    Returns all IAM actions (Create*, Attach*, Put*, Delete* on IAM resources)
    performed by or targeting the specified user.

    Mock implementation for development.
    """
    aws_key = os.getenv("AWS_ACCESS_KEY_ID", "")

    if aws_key:
        logger.info("aws.iam_activity.query", user=req.user_name,
                     note="real_aws_not_implemented")

    events = _generate_mock_iam_activity(
        user_name=req.user_name,
        max_results=req.max_results,
    )

    logger.debug("aws.iam_activity.mock_query", user=req.user_name,
                  results=len(events))

    return {
        "mock": not bool(aws_key),
        "user_name": req.user_name,
        "hours_back": req.hours_back,
        "events": events,
        "count": len(events),
        "summary": {
            "total_events": len(events),
            "event_types": list(set(e["eventName"] for e in events)),
            "source_ips": list(set(e["sourceIPAddress"] for e in events)),
        },
    }
