"""Tests targeting edge cases and branches to achieve 100% test coverage."""

import os
import sys
import tempfile
import pytest
import requests
from unittest.mock import patch, MagicMock

from repoguard.models import Finding, ScanResult, EvaluationResult, Severity, TrustLevel
from repoguard.github_api import extract_owner_repo, fetch_repo_info
from repoguard.evaluator import evaluate_trust, evaluate_repository
from repoguard.code_scanner import (
    scan_file,
    scan_directory,
    scan_codebase,
    clone_repo,
    _remove_readonly,
    PythonSecurityVisitor,
    MAX_FILE_SIZE_BYTES,
)
from repoguard.cli import print_rich_report, print_plain_report, run_cli, main


# --- 1. MODELS COVERAGE ---

def test_finding_to_dict():
    f = Finding(
        filename="test.py",
        line=10,
        rule="TEST-RULE",
        severity=Severity.HIGH,
        description="Test finding description",
        snippet="print(1)",
    )
    d = f.to_dict()
    assert d["filename"] == "test.py"
    assert d["line"] == 10
    assert d["severity"] == "HIGH"
    assert d["rule"] == "TEST-RULE"
    assert d["snippet"] == "print(1)"


# --- 2. GITHUB API COVERAGE ---

def test_extract_owner_repo_special_characters():
    with pytest.raises(ValueError, match="Invalid characters in GitHub repository owner or name"):
        extract_owner_repo("https://github.com/owner!name/validrepo")


@patch("repoguard.github_api.requests.get")
def test_fetch_repo_info_timeout_and_network_error(mock_get):
    mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")
    with pytest.raises(RuntimeError, match="Connection timed out while querying GitHub API"):
        fetch_repo_info("https://github.com/owner/repo")

    mock_get.side_effect = requests.exceptions.RequestException("DNS lookup failed")
    with pytest.raises(RuntimeError, match="Network error querying GitHub API"):
        fetch_repo_info("https://github.com/owner/repo")


@patch("repoguard.github_api.requests.get")
def test_fetch_repo_info_unauthorized_and_forbidden_and_server_error(mock_get):
    # 401 Unauthorized
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_get.return_value = mock_resp
    with pytest.raises(PermissionError, match="GitHub API authorization failed"):
        fetch_repo_info("https://github.com/owner/repo", github_token="bad_token")

    # 403 Forbidden without rate limit remaining == 0
    mock_resp.status_code = 403
    mock_resp.headers = {"x-ratelimit-remaining": "100"}
    mock_resp.text = "Repository access blocked by policy"
    with pytest.raises(PermissionError, match="Access forbidden by GitHub API"):
        fetch_repo_info("https://github.com/owner/repo")

    # 500 Internal Server Error
    mock_resp.status_code = 500
    mock_resp.text = "Internal GitHub Server Error"
    with pytest.raises(RuntimeError, match="GitHub API returned error"):
        fetch_repo_info("https://github.com/owner/repo")


# --- 3. EVALUATOR COVERAGE ---

def test_evaluate_trust_recent_6_months_and_scan_error():
    # 1. Maintained within past 6 months (e.g. 60 days ago)
    metadata = {
        "stars": 50,
        "pushed_at": "2026-08-15T00:00:00Z",
        "license": "MIT",
    }
    # 2. ScanResult with error
    scan = ScanResult(error="Cloning timed out")
    result = evaluate_trust("https://github.com/owner/repo", metadata=metadata, scan_result=scan)
    assert any("Maintained within the past 6 months" in r for r in result.reasons)
    assert any("Code scan could not complete" in r for r in result.reasons)


@patch("repoguard.evaluator.fetch_repo_info")
@patch("repoguard.evaluator.scan_codebase")
def test_evaluate_repository_metadata_failure(mock_scan, mock_fetch):
    mock_fetch.side_effect = RuntimeError("GitHub rate limit exceeded")
    mock_scan.return_value = ScanResult(scanned_files_count=1)

    result = evaluate_repository("https://github.com/owner/repo")
    assert result.metadata is not None
    assert "error" in result.metadata
    assert "GitHub rate limit exceeded" in result.metadata["error"]


# --- 4. CODE SCANNER COVERAGE ---

def test_visitor_get_snippet_out_of_range():
    visitor = PythonSecurityVisitor("test.py", ["line 1", "line 2"])
    assert visitor._get_snippet(0) is None
    assert visitor._get_snippet(5) is None
    assert visitor._get_snippet(1) == "line 1"


def test_visitor_b64decode_imported_as_name():
    # Test line 100-101 where arg.func is ast.Name: exec(b64decode('...'))
    visitor = PythonSecurityVisitor("test.py", ["from base64 import b64decode", "exec(b64decode('x'))"])
    import ast
    tree = ast.parse("from base64 import b64decode\nexec(b64decode('x'))")
    visitor.visit(tree)
    assert any(f.rule == "PY-EXEC-EVAL" and f.severity == Severity.CRITICAL for f in visitor.findings)


def test_remove_readonly_exception_suppressed():
    def failing_func(path):
        raise OSError("Permission denied")
    # Should not raise exception
    _remove_readonly(failing_func, "non_existent_file.tmp", None)


def test_scan_file_large_and_oserror_and_read_error():
    with tempfile.TemporaryDirectory() as tmpdir:
        # 1. File > MAX_FILE_SIZE_BYTES
        big_file = os.path.join(tmpdir, "big.py")
        with open(big_file, "wb") as f:
            f.seek(MAX_FILE_SIZE_BYTES + 10)
            f.write(b"\0")
        findings, lines = scan_file(big_file, tmpdir)
        assert len(findings) == 0
        assert lines == 0

        # 2. getsize raising OSError
        with patch("os.path.getsize", side_effect=OSError("Disk error")):
            findings, lines = scan_file(big_file, tmpdir)
            assert len(findings) == 0
            assert lines == 0

        # 3. open() raising Exception
        norm_file = os.path.join(tmpdir, "norm.py")
        with open(norm_file, "w") as f:
            f.write("print('hello')")
        with patch("builtins.open", side_effect=PermissionError("Locked file")):
            findings, lines = scan_file(norm_file, tmpdir)
            assert len(findings) == 0


def test_scan_file_more_than_three_long_lines():
    with tempfile.TemporaryDirectory() as tmpdir:
        long_file = os.path.join(tmpdir, "long.py")
        # 5 lines longer than 500 chars
        with open(long_file, "w") as f:
            for _ in range(5):
                f.write("x = '" + ("A" * 550) + "'\n")

        findings, count = scan_file(long_file, tmpdir)
        assert count == 5
        long_line_findings = [f for f in findings if f.rule == "OBFUSCATION-LONG-LINE"]
        # Only first 3 are logged as findings to prevent spam
        assert len(long_line_findings) == 3


def test_scan_directory_nonexistent_and_max_files():
    # 1. Non-existent directory
    res = scan_directory("C:/non_existent_directory_123456789")
    assert res.error is not None
    assert "does not exist" in res.error

    # 2. Reaching max_files limit
    with tempfile.TemporaryDirectory() as tmpdir:
        for i in range(10):
            with open(os.path.join(tmpdir, f"file_{i}.py"), "w") as f:
                f.write("print(1)\n")
        res_limit = scan_directory(tmpdir, max_files=3)
        assert res_limit.scanned_files_count == 3


@patch("repoguard.code_scanner.subprocess.run")
def test_clone_repo_timeout_and_error(mock_run):
    import subprocess
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["git"], timeout=60)
    with pytest.raises(RuntimeError, match="Git clone operation timed out"):
        clone_repo("https://github.com/owner/repo", "dummy_dir")

    mock_run.side_effect = subprocess.CalledProcessError(returncode=128, cmd=["git"], stderr="Fatal: repo not found")
    with pytest.raises(RuntimeError, match="Failed to clone repository: Fatal: repo not found"):
        clone_repo("https://github.com/owner/repo", "dummy_dir")


@patch("repoguard.code_scanner.clone_repo")
def test_scan_codebase_success_and_error(mock_clone):
    # 1. Success
    with tempfile.TemporaryDirectory() as fake_cloned:
        with open(os.path.join(fake_cloned, "app.py"), "w") as f:
            f.write("print('clean')")

        def side_effect(url, target, timeout=60):
            with open(os.path.join(target, "main.py"), "w") as f:
                f.write("print('cloned')")

        mock_clone.side_effect = side_effect
        res = scan_codebase("https://github.com/owner/repo")
        assert res.scanned_files_count == 1

    # 2. Clone failure sets error on ScanResult
    mock_clone.side_effect = RuntimeError("Authentication failed")
    res_err = scan_codebase("https://github.com/owner/repo")
    assert res_err.error is not None
    assert "Authentication failed" in res_err.error


# --- 5. CLI COVERAGE ---

def test_cli_rich_report_all_trust_levels_and_branches():
    from rich.console import Console
    console = Console(record=True)

    # 1. SUSPICIOUS and DANGEROUS levels
    res_suspicious = EvaluationResult(
        target="suspicious/repo",
        score=4.0,
        trust_level=TrustLevel.SUSPICIOUS,
        reasons=["Medium star count (50 stars)", "No license detected"],
        metadata={"stars": 50, "is_archived": True},
        scan_result=ScanResult(scanned_files_count=1),
    )
    print_rich_report(res_suspicious, console)

    res_dangerous = EvaluationResult(
        target="dangerous/repo",
        score=1.5,
        trust_level=TrustLevel.DANGEROUS,
        reasons=["CRITICAL RISK: 1 threat", "Neutral factor notes"],
        metadata={"error": "Rate limit exceeded"},
        scan_result=ScanResult(error="Clone error"),
    )
    print_rich_report(res_dangerous, console)

    # 2. More than 25 findings
    many_findings = [
        Finding(filename=f"file_{i}.py", line=i, rule="TEST", severity=Severity.LOW, description="Low hit")
        for i in range(30)
    ]
    res_many = EvaluationResult(
        target="repo/many",
        score=7.0,
        trust_level=TrustLevel.MODERATE,
        scan_result=ScanResult(scanned_files_count=30, findings=many_findings),
    )
    print_rich_report(res_many, console)


def test_cli_json_with_output_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        src = os.path.join(tmpdir, "code.py")
        out = os.path.join(tmpdir, "out.json")
        with open(src, "w") as f:
            f.write("print('ok')")

        code = run_cli([tmpdir, "--local", "--format", "json", "--output", out])
        assert code == 0
        assert os.path.exists(out)


def test_cli_exception_handling_returns_2():
    with patch("repoguard.cli.evaluate_directory", side_effect=RuntimeError("Fatal error")):
        code = run_cli(["dummy_path", "--local"])
        assert code == 2


def test_cli_main_wrapper():
    with patch("sys.argv", ["repoguard", "--version"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0


def test_scan_directory_ignored_dotfiles_and_binaries():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a dotfile that will be skipped (line 757)
        with open(os.path.join(tmpdir, ".hidden"), "w") as f:
            f.write("ignored")
        # Ignored filename (in IGNORED_NAMES)
        with open(os.path.join(tmpdir, "coverage.xml"), "w") as f:
            f.write("<coverage></coverage>")
        # Create a binary extension file (line 767)
        with open(os.path.join(tmpdir, "sample.exe"), "wb") as f:
            f.write(b"MZ\x90\x00")
        with open(os.path.join(tmpdir, "normal.py"), "w") as f:
            f.write("print('hello')")

        res = scan_directory(tmpdir)
        assert res.scanned_files_count == 2
        assert res.binary_files_count == 1


def test_cli_rich_report_fallback_on_exception(monkeypatch):
    from unittest.mock import MagicMock
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "ok.py"), "w") as f:
            f.write("print('ok')")
        monkeypatch.setattr("repoguard.cli.print_rich_report", MagicMock(side_effect=RuntimeError("Rich crashed")))
        code = run_cli([tmpdir, "--local"])
        assert code == 0


def test_cli_has_rich_false_branch(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "ok.py"), "w") as f:
            f.write("print('ok')")
        monkeypatch.setattr("repoguard.cli.HAS_RICH", False)
        code = run_cli([tmpdir, "--local"])
        assert code == 0


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
def test_cli_runpy_main(monkeypatch):
    import runpy
    monkeypatch.setattr("sys.argv", ["repoguard", "--version"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("repoguard.cli", run_name="__main__")
    assert exc.value.code == 0

