"""Tests for CLI arguments, exit codes, and output formatting."""

import json
import os
import tempfile
from unittest.mock import patch, MagicMock
from repoguard.cli import run_cli, print_plain_report, print_rich_report
from repoguard.models import EvaluationResult, ScanResult, Finding, Severity, TrustLevel


def test_cli_version(capsys):
    try:
        run_cli(["--version"])
    except SystemExit as e:
        assert e.code == 0
    captured = capsys.readouterr()
    assert "RepoGuard" in captured.out or "RepoGuard" in captured.err


def test_cli_local_scan_pretty(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "script.py"), "w", encoding="utf-8") as f:
            f.write("print('Hello RepoGuard')\n")

        code = run_cli([tmpdir, "--local"])
        assert code == 0
        captured = capsys.readouterr()
        assert "RepoGuard" in captured.out
        assert "Final Trust Score" in captured.out


def test_cli_local_scan_json(capsys):
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "script.py"), "w", encoding="utf-8") as f:
            f.write("print('Hello RepoGuard')\n")

        code = run_cli([tmpdir, "--local", "--format", "json"])
        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "score" in data
        assert "trust_level" in data
        assert data["trust_level"] in ["TRUSTED", "MODERATE", "SUSPICIOUS", "DANGEROUS"]


def test_cli_output_to_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        script_file = os.path.join(tmpdir, "script.py")
        out_file = os.path.join(tmpdir, "report.json")
        with open(script_file, "w", encoding="utf-8") as f:
            f.write("print('Hello')\n")

        code = run_cli([tmpdir, "--local", "--output", out_file])
        assert code == 0
        assert os.path.exists(out_file)
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert "score" in data


def test_cli_fail_under_threshold():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "evil.py"), "w", encoding="utf-8") as f:
            f.write("import os\nos.system('whoami')\n")

        code = run_cli([tmpdir, "--local", "--fail-under", "9.9"])
        assert code == 1


@patch("repoguard.cli.evaluate_repository")
def test_cli_remote_repo_call(mock_eval):
    mock_eval.return_value = EvaluationResult(
        target="https://github.com/owner/repo",
        score=9.0,
        trust_level=TrustLevel.TRUSTED,
        reasons=["Clean repo"],
        metadata={"stars": 500, "full_name": "owner/repo"},
        scan_result=ScanResult(scanned_files_count=10, findings=[]),
    )
    code = run_cli(["https://github.com/owner/repo", "--token", "abc", "--skip-scan"])
    assert code == 0
    assert mock_eval.called


def test_plain_and_rich_report_rendering():
    finding = Finding(
        filename="test.py",
        line=5,
        rule="RULE-1",
        severity=Severity.HIGH,
        description="Risky call",
    )
    result = EvaluationResult(
        target="dummy/target",
        score=7.0,
        trust_level=TrustLevel.MODERATE,
        reasons=["Test reason 1", "HIGH RISK: found something"],
        metadata={"stars": 100, "forks": 10, "is_archived": False},
        scan_result=ScanResult(scanned_files_count=5, findings=[finding], binary_files_count=1),
    )
    # Ensure plain report prints without raising
    print_plain_report(result)
