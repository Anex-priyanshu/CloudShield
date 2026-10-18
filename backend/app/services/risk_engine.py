"""Risk scoring engine: Risk Score = Severity × Exposure × Data Sensitivity."""
import re
from typing import Optional


SENSITIVITY_KEYWORDS_HIGH = ["prod", "customer", "pii", "backup", "finance", "hr", "db", "database", "secret", "credential"]
SENSITIVITY_KEYWORDS_MED = ["log", "audit", "monitor"]
SENSITIVITY_KEYWORDS_LOW = ["test", "dev", "tmp", "temp", "sandbox", "demo", "staging"]

SEVERITY_MAP = {"LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}


def infer_data_sensitivity(resource_id: str, tags: Optional[dict] = None, default: int = 3) -> int:
    """
    Infer data sensitivity (1-5) from resource tags or name heuristics.
    1=public, 2=internal, 3=default, 4=confidential, 5=restricted
    """
    # 1. Check tags
    if tags:
        classification = tags.get("data-classification", tags.get("DataClassification", "")).lower()
        mapping = {"public": 1, "internal": 2, "confidential": 4, "restricted": 5}
        if classification in mapping:
            return mapping[classification]

    # 2. Name heuristics
    name_lower = resource_id.lower()
    for keyword in SENSITIVITY_KEYWORDS_HIGH:
        if keyword in name_lower:
            return 4
    for keyword in SENSITIVITY_KEYWORDS_MED:
        if keyword in name_lower:
            return 3
    for keyword in SENSITIVITY_KEYWORDS_LOW:
        if keyword in name_lower:
            return 1

    return default


def calculate_risk_score(severity: int, exposure: int, data_sensitivity: int) -> int:
    """Calculate raw risk score (1-125)."""
    return max(1, min(125, severity * exposure * data_sensitivity))


def get_band(score: int, critical_min: int = 91, high_min: int = 51, medium_min: int = 21) -> str:
    """Return risk band: critical | high | medium | low."""
    if score >= critical_min:
        return "critical"
    if score >= high_min:
        return "high"
    if score >= medium_min:
        return "medium"
    return "low"


def classify_band(score: int, custom_bands: Optional[dict] = None) -> str:
    if custom_bands:
        return get_band(
            score,
            custom_bands.get("critical_min", 91),
            custom_bands.get("high_min", 51),
            custom_bands.get("medium_min", 21)
        )
    return get_band(score)


def compute_risk_score(severity: int, exposure: int, data_sensitivity: int, custom_bands: Optional[dict] = None) -> tuple[int, str]:
    """Calculate raw score (1-125) and band tuple."""
    score = calculate_risk_score(severity, exposure, data_sensitivity)
    band = classify_band(score, custom_bands)
    return score, band


def get_band_color(band: str) -> str:
    colors = {
        "critical": "#DC2626",
        "high": "#EA580C",
        "medium": "#CA8A04",
        "low": "#2563EB",
        "passed": "#16A34A",
    }
    return colors.get(band, "#93A1BC")


def build_score_explanation(severity: int, exposure: int, data_sensitivity: int, band: str, resource_id: str = "") -> str:
    score = calculate_risk_score(severity, exposure, data_sensitivity)
    return (
        f"Severity {severity} × Exposure {exposure} × Data Sensitivity {data_sensitivity} "
        f"= {score} → {band.capitalize()}"
    )


def calculate_account_risk_score(open_findings: list, total_resources: int) -> float:
    """
    Account Risk Score (0-100):
    raw = sum of risk scores of all open findings
    denominator = total_resources × 25 (avg mid risk per resource)
    clamped to [0, 100]
    """
    if not open_findings:
        return 0.0
    raw = sum(f.risk_score for f in open_findings)
    denominator = max(1, total_resources * 25)
    score = min(100.0, round((raw / denominator) * 100, 1))
    return score


def checkov_severity_to_int(sev_str: str) -> int:
    return SEVERITY_MAP.get(str(sev_str).upper(), 3)
