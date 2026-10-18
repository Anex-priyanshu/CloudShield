"""Base class for all CloudShield security checks."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CheckResult:
    check_id: str
    title: str
    category: str
    severity: int          # 1-5
    cis_control: str
    description: str
    why_it_matters: str
    remediation: str
    cli_fix: str
    passed: bool
    resource_id: str
    resource_type: str
    region: str
    evidence: Dict[str, Any]
    exposure: int          # 1-5
    data_sensitivity_hint: int  # 1-5 (from heuristic)
    tags: Dict[str, str] = field(default_factory=dict)


class BaseCheck(ABC):
    check_id: str = ""
    title: str = ""
    category: str = ""
    severity: int = 3
    cis_control: str = ""
    description: str = ""
    why_it_matters: str = ""
    remediation: str = ""
    cli_fix: str = ""

    @abstractmethod
    def evaluate(self, resource: Any) -> List[CheckResult]:
        """Evaluate the check against the given resource data. Returns list of failing CheckResults."""
        ...
