"""Tests for scoring engine and trust evaluation logic."""

from unittest.mock import patch
from repoguard.evaluator import (
    calculate_days_since,
    evaluate_trust,
    evaluate_directory,
    evaluate_repository,
)
from repoguard.models import ScanResult, Finding, Severity, TrustLevel


def test_calculate_days_since():
    days = calculate_days_since("2026-01-01T00:00:00Z")
    assert days is not None and days >= 0
    assert calculate_days_since(None) is None
    assert calculate_days_since("") is None
    assert calculate_days_since("invalid-date-string") is None


def test_evaluate_trust_healthy_repository():
    metadata = {
        "stars": 1500,
        "forks": 120,
        "pushed_at": "2026-10-10T00:00:00Z",
        "open_issues": 0,
        "license": "MIT",
        "is_archived": False,
        "is_fork": False,
    }
    scan = ScanResult(scanned_files_count=20, findings=[])

    result = evaluate_trust("https://github.com/owner/healthy", metadata=metadata, scan_result=scan)
    assert result.score >= 8.5
    assert result.trust_level == TrustLevel.TRUSTED
    assert any("Strong community adoption" in r for r in result.reasons)
    assert any("Clean static code scan" in r for r in result.reasons)


def test_evaluate_trust_stale_and_archived():
    metadata = {
        "stars": 5,
        "forks": 0,
        "pushed_at": "2020-01-01T00:00:00Z",
        "open_issues": 300,
        "license": None,
        "is_archived": True,
        "is_fork": True,
    }
    scan = ScanResult(scanned_files_count=5, findings=[])

    result = evaluate_trust("https://github.com/owner/dead", metadata=metadata, scan_result=scan)
    assert result.score < 4.0
    assert result.trust_level in (TrustLevel.SUSPICIOUS, TrustLevel.DANGEROUS)
    assert any("archived" in r.lower() for r in result.reasons)
    assert any("No open source license" in r for r in result.reasons)
    assert any("High unresolved issue backlog" in r for r in result.reasons)


def test_evaluate_trust_critical_backdoor_finding():
    metadata = {
        "stars": 200,
        "forks": 10,
        "pushed_at": "2026-10-14T00:00:00Z",
        "license": "Apache-2.0",
        "is_archived": False,
    }
    critical_finding = Finding(
        filename="backdoor.py",
        line=10,
        rule="PY-EXEC-EVAL",
        severity=Severity.CRITICAL,
        description="Dynamic code execution with decoded payload",
    )
    scan = ScanResult(scanned_files_count=10, findings=[critical_finding])

    result = evaluate_trust("https://github.com/bad/repo", metadata=metadata, scan_result=scan)
    assert any("CRITICAL RISK" in r for r in result.reasons)
    assert result.score <= 4.5
    assert result.trust_level in (TrustLevel.SUSPICIOUS, TrustLevel.DANGEROUS)


def test_evaluate_trust_medium_and_binary_findings():
    med_finding = Finding(
        filename="util.py",
        line=12,
        rule="PY-DYNAMIC-IMPORT",
        severity=Severity.MEDIUM,
        description="Dynamic import",
    )
    scan = ScanResult(
        scanned_files_count=15,
        findings=[med_finding],
        binary_files_count=2,
        long_lines_count=10,
    )
    result = evaluate_trust("dummy", metadata=None, scan_result=scan)
    assert any("Precompiled binary" in r for r in result.reasons)
    assert any("obfuscation" in r for r in result.reasons)


@patch("repoguard.evaluator.fetch_repo_info")
@patch("repoguard.evaluator.scan_codebase")
def test_evaluate_repository_flow(mock_scan, mock_fetch):
    mock_fetch.return_value = {
        "stars": 300,
        "license": "MIT",
        "pushed_at": "2026-10-01T00:00:00Z",
    }
    mock_scan.return_value = ScanResult(scanned_files_count=5, findings=[])

    result = evaluate_repository("https://github.com/owner/repo")
    assert result.score >= 7.0
    assert result.trust_level in (TrustLevel.TRUSTED, TrustLevel.MODERATE)
