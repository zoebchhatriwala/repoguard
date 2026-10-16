"""Static code scanner for detecting suspicious patterns, backdoors, and obfuscation."""

import ast
import os
import re
import shutil
import stat
import subprocess
import tempfile
from typing import List, Optional, Tuple, Set

from repoguard.models import Finding, ScanResult, Severity

# Language categories for static analysis
PYTHON_EXTENSIONS = {".py", ".pyw"}
JS_TS_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
GO_EXTENSIONS = {".go"}
RUST_EXTENSIONS = {".rs"}
CPP_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}
JAVA_KOT_EXTENSIONS = {".java", ".kt", ".kts"}
CSHARP_EXTENSIONS = {".cs"}
PHP_EXTENSIONS = {".php", ".phtml"}
RUBY_EXTENSIONS = {".rb"}
SHELL_EXTENSIONS = {".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}

# Backward compatibility alias
SCRIPT_EXTENSIONS = (
    JS_TS_EXTENSIONS | SHELL_EXTENSIONS | PHP_EXTENSIONS | RUBY_EXTENSIONS |
    GO_EXTENSIONS | RUST_EXTENSIONS | CPP_EXTENSIONS | JAVA_KOT_EXTENSIONS | CSHARP_EXTENSIONS
)

ALL_SOURCE_EXTENSIONS = PYTHON_EXTENSIONS | SCRIPT_EXTENSIONS

BINARY_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".elf", ".bin", ".msi", ".scr", ".com"}
AI_MODEL_EXTENSIONS = {".pkl", ".pickle", ".joblib"}

# Unicode BiDi & Zero-width characters for Trojan Source detection
BIDI_OVERRIDE_CHARS = {'\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069'}
ZERO_WIDTH_CHARS = {'\u200b', '\u200c', '\u200d', '\ufeff'}

# Files to ignore for obfuscation/line-length checks
IGNORED_LINE_LENGTH_EXTENSIONS = {
    ".min.js", ".min.css", ".map", ".svg", ".json", ".lock",
    ".csv", ".tsv", ".txt", ".md", ".rst", ".yaml", ".yml"
}
IGNORED_LINE_LENGTH_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock"
}

# Directories to skip entirely (.vscode and venv are scanned separately)
IGNORED_DIRS = {
    ".git", ".svn", ".hg", "node_modules",
    "__pycache__", ".pytest_cache", ".mypy_cache", "dist", "build",
    ".tox", "vendor", "site-packages", ".idea"
}
IGNORED_NAMES = {
    ".coverage", "coverage.xml", ".DS_Store"
}

# Max line length to flag possible obfuscation / packed payload
MAX_LINE_LENGTH = 500
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB


def _remove_readonly(func, path, exc_info):
    """Error handler for shutil.rmtree to clean read-only files (Windows git objects)."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


class PythonSecurityVisitor(ast.NodeVisitor):
    """AST visitor detecting dangerous functions, deserialization, and obfuscation in Python."""

    def __init__(self, filename: str, lines: List[str]):
        self.filename = filename
        self.lines = lines
        self.findings: List[Finding] = []

    def _get_snippet(self, lineno: int) -> Optional[str]:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return None

    def visit_Call(self, node: ast.Call):
        # 1. Direct function calls: eval, exec, compile
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ("eval", "exec"):
                # Check if it unpacks base64 or hex
                is_obfuscated = False
                for arg in node.args:
                    if isinstance(arg, ast.Call):
                        arg_call = ""
                        if isinstance(arg.func, ast.Attribute):
                            arg_call = arg.func.attr
                        elif isinstance(arg.func, ast.Name):
                            arg_call = arg.func.id
                        if arg_call in ("b64decode", "fromhex", "decompress"):
                            is_obfuscated = True

                self.findings.append(Finding(
                    filename=self.filename,
                    line=node.lineno,
                    rule="PY-EXEC-EVAL",
                    severity=Severity.CRITICAL if is_obfuscated else Severity.HIGH,
                    description=f"Use of '{func_name}()' dynamic code execution" + (" with decoded payload" if is_obfuscated else ""),
                    snippet=self._get_snippet(node.lineno),
                ))

            elif func_name == "compile":
                self.findings.append(Finding(
                    filename=self.filename,
                    line=node.lineno,
                    rule="PY-COMPILE",
                    severity=Severity.MEDIUM,
                    description="Use of 'compile()' for dynamic code compilation",
                    snippet=self._get_snippet(node.lineno),
                ))

            elif func_name == "__import__":
                self.findings.append(Finding(
                    filename=self.filename,
                    line=node.lineno,
                    rule="PY-DYNAMIC-IMPORT",
                    severity=Severity.MEDIUM,
                    description="Dynamic module loading via '__import__()'",
                    snippet=self._get_snippet(node.lineno),
                ))

        # 2. Module attribute calls: os.system, subprocess.*, pickle.loads, ctypes.*
        elif isinstance(node.func, ast.Attribute):
            module_name = ""
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
            attr_name = node.func.attr

            # Deserialization attacks
            if module_name == "pickle" and attr_name in ("loads", "load"):
                self.findings.append(Finding(
                    filename=self.filename,
                    line=node.lineno,
                    rule="PY-UNSAFE-DESERIALIZATION",
                    severity=Severity.CRITICAL,
                    description="Insecure deserialization via 'pickle.load(s)()'",
                    snippet=self._get_snippet(node.lineno),
                ))
            elif module_name == "marshal" and attr_name in ("loads", "load"):
                self.findings.append(Finding(
                    filename=self.filename,
                    line=node.lineno,
                    rule="PY-UNSAFE-DESERIALIZATION",
                    severity=Severity.CRITICAL,
                    description="Insecure deserialization via 'marshal.load(s)()'",
                    snippet=self._get_snippet(node.lineno),
                ))
            elif module_name == "shelve" and attr_name == "open":
                self.findings.append(Finding(
                    filename=self.filename,
                    line=node.lineno,
                    rule="PY-UNSAFE-DESERIALIZATION",
                    severity=Severity.HIGH,
                    description="Insecure persistence via 'shelve.open()'",
                    snippet=self._get_snippet(node.lineno),
                ))
            elif module_name == "yaml" and attr_name == "unsafe_load":
                self.findings.append(Finding(
                    filename=self.filename,
                    line=node.lineno,
                    rule="PY-UNSAFE-DESERIALIZATION",
                    severity=Severity.CRITICAL,
                    description="Unsafe YAML deserialization via 'yaml.unsafe_load()'",
                    snippet=self._get_snippet(node.lineno),
                ))

            # Shell / Process execution
            elif module_name == "os" and attr_name in ("system", "popen", "spawnl", "spawnle", "spawnlp", "spawnv"):
                self.findings.append(Finding(
                    filename=self.filename,
                    line=node.lineno,
                    rule="PY-OS-SHELL",
                    severity=Severity.HIGH,
                    description=f"Arbitrary OS shell execution via 'os.{attr_name}()'",
                    snippet=self._get_snippet(node.lineno),
                ))
            elif module_name == "subprocess":
                # Check if shell=True is passed
                has_shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                self.findings.append(Finding(
                    filename=self.filename,
                    line=node.lineno,
                    rule="PY-SUBPROCESS-SHELL" if has_shell_true else "PY-SUBPROCESS",
                    severity=Severity.HIGH if has_shell_true else Severity.MEDIUM,
                    description=f"Subprocess execution 'subprocess.{attr_name}()'" + (" with shell=True" if has_shell_true else ""),
                    snippet=self._get_snippet(node.lineno),
                ))
            elif module_name == "pty" and attr_name == "spawn":
                self.findings.append(Finding(
                    filename=self.filename,
                    line=node.lineno,
                    rule="PY-PTY-SPAWN",
                    severity=Severity.HIGH,
                    description="Interactive pseudo-terminal spawn via 'pty.spawn()'",
                    snippet=self._get_snippet(node.lineno),
                ))

            # Low-level native bindings & network sockets
            elif module_name == "ctypes":
                self.findings.append(Finding(
                    filename=self.filename,
                    line=node.lineno,
                    rule="PY-CTYPES",
                    severity=Severity.MEDIUM,
                    description=f"Native memory/C library interaction via 'ctypes.{attr_name}'",
                    snippet=self._get_snippet(node.lineno),
                ))
            elif module_name == "socket" and attr_name == "socket":
                self.findings.append(Finding(
                    filename=self.filename,
                    line=node.lineno,
                    rule="PY-RAW-SOCKET",
                    severity=Severity.LOW,
                    description="Raw network socket creation via 'socket.socket()'",
                    snippet=self._get_snippet(node.lineno),
                ))

        self.generic_visit(node)


SECRET_PATTERNS = [
    (
        re.compile(r"^\s*-----BEGIN\s+(?:[A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----"),
        "SECRET-PRIVATE-KEY",
        Severity.CRITICAL,
        "Exposed private cryptographic key detected"
    ),
]

# --- LANGUAGE-SPECIFIC THREAT CATALOGS ---

UNIVERSAL_PATTERNS = [
    (
        re.compile(r"(?:curl|wget)\s+[^|\n]+\|\s*(?:bash|sh|zsh)"),
        "SHELL-CURL-PIPE",
        Severity.CRITICAL,
        "Remote script downloaded and directly piped to shell interpreter"
    ),
    (
        re.compile(r"(?:nc(?:\.traditional)?\s+-[e|c]|bash\s+-i\s+>&|/dev/tcp/\d+)"),
        "SHELL-REVERSE-SHELL",
        Severity.CRITICAL,
        "Possible interactive reverse shell connection string"
    ),
    (
        re.compile(r"powershell(?:\.exe)?\s+.*(?:-enc|-encodedcommand|-ExecutionPolicy\s+Bypass)", re.IGNORECASE),
        "PS-SUSPICIOUS-EXEC",
        Severity.HIGH,
        "PowerShell executed with encoded command or execution policy bypass"
    ),
    (
        re.compile(r"certutil(?:\.exe)?\s+.*-(?:urlcache|decode)", re.IGNORECASE),
        "CERTUTIL-SUSPICIOUS-DOWNLOAD",
        Severity.HIGH,
        "Certutil living-off-the-land utility invoked to download or decode files"
    ),
]

JS_TS_PATTERNS = [
    (
        re.compile(r"\beval\s*\("),
        "JS-EVAL",
        Severity.HIGH,
        "Dynamic JavaScript code evaluation via 'eval()'"
    ),
    (
        re.compile(r"\bFunction\s*\([^)]*\)\s*\("),
        "JS-DYNAMIC-FUNCTION",
        Severity.MEDIUM,
        "Dynamic code construction via Function constructor"
    ),
    (
        re.compile(r"(?:child_process|\bcp)\.(?:exec|execSync|spawn|spawnSync)\s*\(|require\s*\(\s*['\"]child_process['\"]"),
        "JS-CHILD-PROCESS",
        Severity.HIGH,
        "Subprocess execution or child_process module import"
    ),
    (
        re.compile(r"\bvm\.(?:runInThisContext|runInNewContext|runInContext)\s*\("),
        "JS-VM-EXEC",
        Severity.HIGH,
        "Dynamic code execution via Node.js vm module"
    ),
]

GO_PATTERNS = [
    (
        re.compile(r"//\s*#cgo\s+"),
        "GO-CGO-DIRECTIVE",
        Severity.MEDIUM,
        "Cgo compiler directive present; potential native build injection vector"
    ),
    (
        re.compile(r"\bexec\.Command(?:Context)?\s*\("),
        "GO-EXEC-COMMAND",
        Severity.HIGH,
        "External command execution via os/exec Command"
    ),
    (
        re.compile(r"\bsyscall\.(?:Syscall|RawSyscall)\s*\("),
        "GO-RAW-SYSCALL",
        Severity.HIGH,
        "Direct kernel syscall invocation in Go"
    ),
]

RUST_PATTERNS = [
    (
        re.compile(r"\b(?:std::process::)?Command::new\s*\("),
        "RUST-COMMAND-EXEC",
        Severity.HIGH,
        "External process execution via Command::new"
    ),
    (
        re.compile(r"(?:VirtualAlloc|VirtualProtect|CreateThread)\b"),
        "RUST-WIN-MEM-INJECTION",
        Severity.CRITICAL,
        "Low-level Windows memory/thread API invoked; potential shellcode execution"
    ),
]

CPP_PATTERNS = [
    (
        re.compile(r"\b(?:system|popen|execl|execle|execlp|execv|execvp|execvpe)\s*\("),
        "CPP-SYSTEM-EXEC",
        Severity.HIGH,
        "Arbitrary shell command execution via C system/exec API"
    ),
    (
        re.compile(r"(?:VirtualAlloc|VirtualProtect)\s*\(.*?(?:0x40|PAGE_EXECUTE_READWRITE)"),
        "CPP-RWX-MEMORY-ALLOC",
        Severity.CRITICAL,
        "Executable RWX memory allocation (classic shellcode injection pattern)"
    ),
    (
        re.compile(r"\b(?:WinExec|ShellExecute[AW]?)\s*\("),
        "CPP-WINEXEC",
        Severity.HIGH,
        "Process execution via Windows API"
    ),
]

JAVA_KOT_PATTERNS = [
    (
        re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\("),
        "JAVA-PROCESS-EXEC",
        Severity.HIGH,
        "Process execution via Runtime.exec or ProcessBuilder"
    ),
    (
        re.compile(r"ObjectInputStream\s*\([^)]*\)\.readObject\s*\("),
        "JAVA-UNSAFE-DESERIALIZATION",
        Severity.CRITICAL,
        "Insecure Java object deserialization via readObject()"
    ),
    (
        re.compile(r"InitialContext\s*\(.*?\)\.lookup\s*\("),
        "JAVA-JNDI-LOOKUP",
        Severity.HIGH,
        "JNDI lookup invocation (potential Log4Shell / remote class loading vector)"
    ),
]

CSHARP_PATTERNS = [
    (
        re.compile(r"\bProcess\.Start\s*\("),
        "CS-PROCESS-START",
        Severity.HIGH,
        "Subprocess execution via System.Diagnostics.Process.Start"
    ),
    (
        re.compile(r"Assembly\.Load\s*\([^)]*(?:byte\[\]|rawAssembly)"),
        "CS-IN-MEMORY-ASSEMBLY",
        Severity.CRITICAL,
        "In-memory assembly/DLL reflection loading"
    ),
    (
        re.compile(r"BinaryFormatter\s*\(\)\.Deserialize\s*\("),
        "CS-BINARY-FORMATTER",
        Severity.CRITICAL,
        "Insecure .NET deserialization via BinaryFormatter"
    ),
]

PHP_PATTERNS = [
    (
        re.compile(r"\b(?:shell_exec|exec|passthru|system|popen|proc_open)\s*\("),
        "PHP-SHELL-EXEC",
        Severity.HIGH,
        "OS command execution via PHP shell function"
    ),
    (
        re.compile(r"\bassert\s*\("),
        "PHP-ASSERT-EVAL",
        Severity.HIGH,
        "Dynamic code evaluation via assert()"
    ),
]

RUBY_PATTERNS = [
    (
        re.compile(r"\b(?:Kernel\.)?(?:system|exec)\s*\("),
        "RUBY-COMMAND-EXEC",
        Severity.HIGH,
        "Process execution via system or exec"
    ),
    (
        re.compile(r"\bIO\.popen\s*\(|open\s*\(\s*[\"']\|"),
        "RUBY-PIPE-EXEC",
        Severity.HIGH,
        "Piped command execution in Ruby"
    ),
]

# Combined script patterns for generic scanners
SCRIPT_PATTERNS = (
    UNIVERSAL_PATTERNS + JS_TS_PATTERNS + GO_PATTERNS + RUST_PATTERNS +
    CPP_PATTERNS + JAVA_KOT_PATTERNS + CSHARP_PATTERNS + PHP_PATTERNS + RUBY_PATTERNS
)

# Backward compatibility alias
REGEX_PATTERNS = SECRET_PATTERNS + SCRIPT_PATTERNS


def scan_python_file(filepath: str, relpath: str, lines: List[str]) -> List[Finding]:
    """Scans a Python file using AST analysis, falling back to regex on syntax errors."""
    code_text = "\n".join(lines)
    findings: List[Finding] = []

    try:
        tree = ast.parse(code_text, filename=relpath)
        visitor = PythonSecurityVisitor(relpath, lines)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    except SyntaxError:
        # Fallback to regex pattern scan if AST parse fails
        findings.extend(scan_regex_file(filepath, relpath, lines, patterns=UNIVERSAL_PATTERNS))

    return findings


def scan_regex_file(
    filepath: str,
    relpath: str,
    lines: List[str],
    patterns: Optional[List] = None
) -> List[Finding]:
    """Scans source files with compiled security regexes."""
    active_patterns = patterns if patterns is not None else REGEX_PATTERNS
    findings: List[Finding] = []

    for lineno, line in enumerate(lines, start=1):
        for pattern, rule, severity, desc in active_patterns:
            if pattern.search(line):
                findings.append(Finding(
                    filename=relpath,
                    line=lineno,
                    rule=rule,
                    severity=severity,
                    description=desc,
                    snippet=line.strip()[:150],
                ))

    return findings


def scan_file(filepath: str, base_dir: str) -> Tuple[List[Finding], int]:
    """
    Scans a single file for security risks and obfuscation.

    Returns:
        (findings_list, long_lines_count)
    """
    relpath = os.path.relpath(filepath, base_dir).replace("\\", "/")
    findings: List[Finding] = []
    long_lines = 0

    _, ext = os.path.splitext(filepath)
    ext_lower = ext.lower()
    filename = os.path.basename(filepath)

    # 1. Binary files
    if ext_lower in BINARY_EXTENSIONS:
        findings.append(Finding(
            filename=relpath,
            line=None,
            rule="BINARY-EXECUTABLE",
            severity=Severity.HIGH,
            description=f"Compiled binary or executable file present in repository ({ext_lower})"
        ))
        return findings, 0

    # 2. AI / ML Insecure Pickle Model Checkpoint
    if ext_lower in AI_MODEL_EXTENSIONS:
        findings.append(Finding(
            filename=relpath,
            line=None,
            rule="AI-UNSAFE-PICKLE-MODEL",
            severity=Severity.HIGH,
            description=f"Raw serialized Python pickle model present ({ext_lower}); vulnerable to __reduce__ RCE. Prefer 'safetensors'.",
        ))
        return findings, 0

    # Check file size before reading
    try:
        if os.path.getsize(filepath) > MAX_FILE_SIZE_BYTES:
            return findings, 0
    except OSError:
        return findings, 0

    # 3. Text / Source file scanning
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.rstrip("\r\n") for line in f]
    except Exception:
        return findings, 0

    # A. Python .pth path file execution
    if ext_lower == ".pth":
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("import ") or stripped.startswith("import\t"):
                findings.append(Finding(
                    filename=relpath,
                    line=lineno,
                    rule="PY-PTH-EXECUTION",
                    severity=Severity.CRITICAL,
                    description="Python .pth path file executes arbitrary code on interpreter startup",
                    snippet=stripped[:80],
                ))

    # B. VS Code Workspace Tasks & Settings Auditor
    if relpath.endswith(".vscode/tasks.json") or filename == "tasks.json":
        content_text = "\n".join(lines)
        if re.search(r'"runOn"\s*:\s*"folderOpen"', content_text, re.IGNORECASE):
            findings.append(Finding(
                filename=relpath,
                line=None,
                rule="IDE-TASKS-AUTORUN",
                severity=Severity.CRITICAL,
                description="VS Code tasks.json configured with 'folderOpen' auto-execution (Lazarus Contagious Interview vector)",
                snippet='"runOn": "folderOpen"',
            ))
    if relpath.endswith(".vscode/settings.json") or filename == "settings.json":
        content_text = "\n".join(lines)
        if re.search(r'"(?:python\.defaultInterpreterPath|go\.alternateTools)"\s*:\s*"[.\\]+', content_text):
            findings.append(Finding(
                filename=relpath,
                line=None,
                rule="IDE-INTERPRETER-HIJACK",
                severity=Severity.HIGH,
                description="VS Code settings.json points interpreter or tool path to a local relative file",
                snippet="Custom interpreter/tool path configuration",
            ))

    # C. NPM package.json Lifecycle Hooks Auditor
    if filename == "package.json":
        content_text = "\n".join(lines)
        for hook in ("preinstall", "install", "postinstall", "prepare"):
            pattern = rf'"{hook}"\s*:\s*"([^"]+)"'
            match = re.search(pattern, content_text)
            if match:
                script_cmd = match.group(1)
                if any(s in script_cmd.lower() for s in ("curl", "wget", "node -e", "powershell", "bash", "sh", "eval", "base64")):
                    findings.append(Finding(
                        filename=relpath,
                        line=None,
                        rule="NPM-LIFECYCLE-HOOK",
                        severity=Severity.CRITICAL,
                        description=f"Dangerous command in npm '{hook}' lifecycle script: {script_cmd[:60]}",
                        snippet=script_cmd[:80],
                    ))

    # D. Python requirements.txt Dependency Confusion Auditor
    if filename in ("requirements.txt", "requirements.in"):
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("--extra-index-url") or stripped.startswith("--index-url"):
                if not ("pypi.org" in stripped or "python.org" in stripped):
                    findings.append(Finding(
                        filename=relpath,
                        line=lineno,
                        rule="PIP-DEPENDENCY-CONFUSION",
                        severity=Severity.HIGH,
                        description="Custom pip package index URL specified; potential dependency confusion risk",
                        snippet=stripped[:80],
                    ))

    # E. Python setup.py Custom cmdclass Hook Auditor
    if filename == "setup.py":
        content_text = "\n".join(lines)
        if "cmdclass" in content_text and any(h in content_text for h in ("install", "develop", "build_py")):
            findings.append(Finding(
                filename=relpath,
                line=None,
                rule="PY-SETUP-CMDCLASS-HOOK",
                severity=Severity.HIGH,
                description="Custom cmdclass install/develop hook detected in setup.py (executes during pip install)",
                snippet="cmdclass override present in setup.py",
            ))

    # F. Docker Compose Host Mount Escape Auditor
    if filename in ("docker-compose.yml", "docker-compose.yaml"):
        content_text = "\n".join(lines)
        if re.search(r'volumes:\s*.*?(?:-\s*["\']?(?:/:|/var/run/docker\.sock))', content_text, re.DOTALL):
            findings.append(Finding(
                filename=relpath,
                line=None,
                rule="DOCKER-HOST-MOUNT-ESCAPE",
                severity=Severity.CRITICAL,
                description="Docker Compose file mounts host root '/' or Docker socket '/var/run/docker.sock'",
                snippet="Host filesystem/socket mount detected in docker-compose.yml",
            ))

    # G. Direnv Committed .envrc Auditor
    if filename == ".envrc":
        findings.append(Finding(
            filename=relpath,
            line=None,
            rule="DIRENV-COMMITTED-ENVRC",
            severity=Severity.MEDIUM,
            description="Committed .envrc file detected; automatically evaluated by direnv upon directory navigation",
        ))

    # H. Trojan Source (BiDi Override Characters & Zero-Width Steganography)
    for lineno, line in enumerate(lines, start=1):
        if any(c in line for c in BIDI_OVERRIDE_CHARS):
            findings.append(Finding(
                filename=relpath,
                line=lineno,
                rule="TROJAN-SOURCE-BIDI",
                severity=Severity.CRITICAL,
                description="Trojan Source Unicode bidirectional override character detected (CVE-2021-42574)",
                snippet="[BiDi override control character in line]",
            ))
        elif any(c in line for c in ZERO_WIDTH_CHARS):
            findings.append(Finding(
                filename=relpath,
                line=lineno,
                rule="TROJAN-ZERO-WIDTH",
                severity=Severity.HIGH,
                description="Invisible zero-width character detected; potential payload steganography",
                snippet="[Zero-width character in line]",
            ))

    # Check for long lines / obfuscation
    check_line_length = (
        ext_lower not in IGNORED_LINE_LENGTH_EXTENSIONS
        and filename not in IGNORED_LINE_LENGTH_NAMES
        and not filename.endswith(".min.js")
        and not filename.endswith(".min.css")
    )
    if check_line_length:
        for lineno, line in enumerate(lines, start=1):
            if len(line) > MAX_LINE_LENGTH:
                long_lines += 1
                if long_lines <= 3:  # Only report the first few as findings to avoid spam
                    findings.append(Finding(
                        filename=relpath,
                        line=lineno,
                        rule="OBFUSCATION-LONG-LINE",
                        severity=Severity.MEDIUM,
                        description=f"Excessively long line ({len(line)} chars), possible minified or obfuscated payload",
                        snippet=line[:80] + "...",
                    ))

    # Check for exposed secrets across all text files
    for lineno, line in enumerate(lines, start=1):
        for pattern, rule, severity, desc in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    filename=relpath,
                    line=lineno,
                    rule=rule,
                    severity=severity,
                    description=desc,
                    snippet=line.strip()[:80],
                ))

    # Run AST and language-specific threat catalog checks
    if ext_lower in PYTHON_EXTENSIONS:
        findings.extend(scan_python_file(filepath, relpath, lines))
        findings.extend(scan_regex_file(filepath, relpath, lines, patterns=UNIVERSAL_PATTERNS))
    elif ext_lower in JS_TS_EXTENSIONS:
        findings.extend(scan_regex_file(filepath, relpath, lines, patterns=JS_TS_PATTERNS + UNIVERSAL_PATTERNS))
    elif ext_lower in GO_EXTENSIONS:
        findings.extend(scan_regex_file(filepath, relpath, lines, patterns=GO_PATTERNS + UNIVERSAL_PATTERNS))
    elif ext_lower in RUST_EXTENSIONS:
        findings.extend(scan_regex_file(filepath, relpath, lines, patterns=RUST_PATTERNS + UNIVERSAL_PATTERNS))
    elif ext_lower in CPP_EXTENSIONS:
        findings.extend(scan_regex_file(filepath, relpath, lines, patterns=CPP_PATTERNS + UNIVERSAL_PATTERNS))
    elif ext_lower in JAVA_KOT_EXTENSIONS:
        findings.extend(scan_regex_file(filepath, relpath, lines, patterns=JAVA_KOT_PATTERNS + UNIVERSAL_PATTERNS))
    elif ext_lower in CSHARP_EXTENSIONS:
        findings.extend(scan_regex_file(filepath, relpath, lines, patterns=CSHARP_PATTERNS + UNIVERSAL_PATTERNS))
    elif ext_lower in PHP_EXTENSIONS:
        findings.extend(scan_regex_file(filepath, relpath, lines, patterns=PHP_PATTERNS + UNIVERSAL_PATTERNS))
    elif ext_lower in RUBY_EXTENSIONS:
        findings.extend(scan_regex_file(filepath, relpath, lines, patterns=RUBY_PATTERNS + UNIVERSAL_PATTERNS))
    elif ext_lower in SHELL_EXTENSIONS or ext_lower in ALL_SOURCE_EXTENSIONS:
        findings.extend(scan_regex_file(filepath, relpath, lines, patterns=UNIVERSAL_PATTERNS))

    return findings, long_lines


def scan_directory(directory_path: str, max_files: int = 5000) -> ScanResult:
    """
    Scans a local directory for security risks, backdoors, and obfuscation.

    Args:
        directory_path: Absolute or relative directory path.
        max_files: Maximum number of files to process before truncating.
    """
    if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
        return ScanResult(error=f"Directory '{directory_path}' does not exist or is not a directory.")

    all_findings: List[Finding] = []
    total_scanned = 0
    total_long_lines = 0
    total_binaries = 0

    for root, dirs, files in os.walk(directory_path):
        # Detect committed virtual environments
        for d in dirs:
            if d in ("venv", ".venv", "env"):
                all_findings.append(Finding(
                    filename=os.path.relpath(os.path.join(root, d), directory_path).replace("\\", "/"),
                    line=None,
                    rule="ENV-COMMITTED-VENV",
                    severity=Severity.HIGH,
                    description="Committed Python virtual environment directory detected; potential activation script or .pth backdoor",
                ))

        # Filter ignored directories in-place to avoid descending, but permit .vscode
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and (d == ".vscode" or not d.startswith("."))]

        for file in files:
            # Audit .envrc even though it starts with a dot
            if file == ".envrc":
                pass
            elif file.startswith(".") or file in IGNORED_NAMES:
                continue

            if total_scanned >= max_files:
                break

            filepath = os.path.join(root, file)
            _, ext = os.path.splitext(file)
            ext_lower = ext.lower()

            if ext_lower in BINARY_EXTENSIONS:
                total_binaries += 1

            findings, long_lines = scan_file(filepath, directory_path)
            all_findings.extend(findings)
            total_long_lines += long_lines
            total_scanned += 1

    return ScanResult(
        scanned_files_count=total_scanned,
        findings=all_findings,
        long_lines_count=total_long_lines,
        binary_files_count=total_binaries,
    )


def clone_repo(repo_url: str, target_dir: str, timeout: int = 60) -> None:
    """
    Safely clones a GitHub repository into the target directory with strict timeouts,
    disabled hooks, disabled symlinks, and no recursive submodules (defeats CVE-2024-32002).
    """
    if not repo_url.startswith(("https://", "http://", "git@")):
        raise ValueError("Invalid repository URL protocol. Only https, http, and git SSH are permitted.")

    # Mitigate git hook execution, symlink traversal, and submodule exploits
    cmd = [
        "git",
        "clone",
        "--depth=1",
        "--single-branch",
        "--no-recurse-submodules",
        "--config", "core.hooksPath=/dev/null",
        "--config", "core.symlinks=false",
        repo_url,
        target_dir
    ]
    try:
        subprocess.run(
            cmd,
            check=True,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"Git clone operation timed out after {timeout} seconds.") from e
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.strip() if e.stderr else "Unknown git error"
        raise RuntimeError(f"Failed to clone repository: {err_msg}") from e


def scan_codebase(repo_url: str, timeout: int = 60) -> ScanResult:
    """
    Clones and scans a remote GitHub repository. Safely cleans up temporary directories.
    """
    tmp_dir = tempfile.mkdtemp(prefix="repoguard_")
    try:
        clone_repo(repo_url, tmp_dir, timeout=timeout)
        result = scan_directory(tmp_dir)
        return result
    except Exception as e:
        return ScanResult(error=str(e))
    finally:
        # On Windows, git objects can be read-only, so handle permission errors safely
        shutil.rmtree(tmp_dir, onerror=_remove_readonly)
