"""Unit tests for CloudShield check engine, risk scoring, and read-only compliance."""
import os
import re
import json
import pytest
from app.services.risk_engine import (
    calculate_risk_score, get_band, compute_risk_score, infer_data_sensitivity
)
from app.checks import ALL_CHECKS
from app.detections import ALL_RULES, evaluate_event


def test_risk_scoring_formula():
    """Verify Risk Score = S × E × D (1..125) and bands."""
    # Test min
    score, band = compute_risk_score(1, 1, 1)
    assert score == 1
    assert band == "low"

    # Test max
    score, band = compute_risk_score(5, 5, 5)
    assert score == 125
    assert band == "critical"

    # Test middle thresholds
    assert get_band(91) == "critical"
    assert get_band(90) == "high"
    assert get_band(51) == "high"
    assert get_band(50) == "medium"
    assert get_band(21) == "medium"
    assert get_band(20) == "low"


def test_sensitivity_inference():
    """Verify data sensitivity heuristics."""
    assert infer_data_sensitivity("customer-pii-records-prod") == 4
    assert infer_data_sensitivity("dev-testing-bucket") == 1
    assert infer_data_sensitivity("unknown-generic-resource") == 3
    assert infer_data_sensitivity("my-bucket", tags={"data-classification": "restricted"}) == 5
    assert infer_data_sensitivity("my-bucket", tags={"data-classification": "public"}) == 1


def test_demo_data_scan_execution():
    """Run all 25 posture checks against demo seeded data and verify findings."""
    demo_file = os.path.join(os.path.dirname(__file__), "..", "app", "demo", "data.json")
    assert os.path.exists(demo_file)
    with open(demo_file, "r") as f:
        demo_data = json.load(f)

    findings = []
    for check in ALL_CHECKS:
        results = check.evaluate(demo_data)
        for res in results:
            if not res.passed:
                score, band = compute_risk_score(
                    res.severity,
                    res.exposure,
                    res.data_sensitivity_hint
                )
                findings.append({
                    "check_id": res.check_id,
                    "title": res.title,
                    "score": score,
                    "band": band,
                })

    assert len(findings) >= 15, f"Expected at least 15 findings, got {len(findings)}"
    criticals = [f for f in findings if f["band"] == "critical"]
    assert len(criticals) >= 2, f"Expected at least 2 critical findings, got {len(criticals)}"


def test_detection_rules():
    """Verify CloudTrail detection rules trigger appropriately."""
    root_event = {
        "eventName": "ConsoleLogin",
        "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
        "sourceIPAddress": "198.51.100.1",
        "awsRegion": "us-east-1",
    }
    matched_rules = evaluate_event(root_event)
    assert any(r.rule_id == "DET-002" for r in matched_rules), "Root login should trigger DET-002"

    sg_event = {
        "eventName": "AuthorizeSecurityGroupIngress",
        "userIdentity": {"type": "IAMUser", "userName": "developer"},
        "requestParameters": {
            "ipPermissions": {
                "items": [{"ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]
            }
        },
    }
    matched_rules = evaluate_event(sg_event)
    assert any(r.rule_id == "DET-005" for r in matched_rules), "Open SG ingress should trigger DET-005"


def test_read_only_compliance():
    """
    PRD Section 14:
    Scan backend source code to ensure no forbidden AWS mutating API prefixes are used on boto3 clients.
    """
    backend_dir = os.path.join(os.path.dirname(__file__), "..", "app")
    collectors_dir = os.path.join(backend_dir, "collectors")

    forbidden = ["create_", "delete_", "put_", "update_", "attach_", "detach_",
                 "authorize_", "revoke_", "modify_", "terminate_", "stop_"]

    for root, _, files in os.walk(collectors_dir):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                for verb in forbidden:
                    match = re.search(r'\bclient\.' + verb, content, re.I)
                    assert not match, f"Forbidden mutating API call found in {file}: {match.group(0)}"
