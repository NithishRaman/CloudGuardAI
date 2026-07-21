from dataclasses import dataclass
from typing import Optional


@dataclass
class SecurityFinding:
    finding_id: str
    finding_type: str
    issue: str
    resource: str
    risk: str
    description: Optional[str] = None
    remediation: Optional[str] = None
