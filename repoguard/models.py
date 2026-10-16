"""Data models and type definitions for RepoGuard."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(str, Enum):
    """Severity levels for detected code risks."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class TrustLevel(str, Enum):
    """Categorized trust levels for evaluated repositories."""
    TRUSTED = "TRUSTED"
    MODERATE = "MODERATE"
    SUSPICIOUS = "SUSPICIOUS"
    DANGEROUS = "DANGEROUS"


@dataclass
class Finding:
    """Represents a single security or code health finding."""
    filename: str
    line: Optional[int]
    rule: str
    severity: Severity
    description: str
    snippet: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "line": self.line,
            "rule": self.rule,
            "severity": self.severity.value,
            "description": self.description,
            "snippet": self.snippet,
        }


@dataclass
class ScanResult:
    """Summary of code scan findings."""
    scanned_files_count: int = 0
    findings: List[Finding] = field(default_factory=list)
    long_lines_count: int = 0
    binary_files_count: int = 0
    error: Optional[str] = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanned_files_count": self.scanned_files_count,
            "total_findings": len(self.findings),
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "long_lines_count": self.long_lines_count,
            "binary_files_count": self.binary_files_count,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class EvaluationResult:
    """Overall evaluation output combining metadata and static scanning."""
    target: str
    score: float
    trust_level: TrustLevel
    reasons: List[str] = field(default_factory=list)
    metadata: Optional[Dict[str, Any]] = None
    scan_result: Optional[ScanResult] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "score": round(self.score, 1),
            "trust_level": self.trust_level.value,
            "reasons": self.reasons,
            "metadata": self.metadata,
            "scan": self.scan_result.to_dict() if self.scan_result else None,
        }
