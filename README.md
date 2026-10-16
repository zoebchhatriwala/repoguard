<div align="center">

# 🛡️ RepoGuard

**Automated Trust, Safety, and Security Intelligence for GitHub Repositories**

[![CI](https://github.com/zoebchhatriwala/repoguard/actions/workflows/ci.yml/badge.svg)](https://github.com/zoebchhatriwala/repoguard/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Clean](https://img.shields.io/badge/code%20quality-A+-brightgreen.svg)](#)

*Before you clone, run, or integrate an unfamiliar repository onto your machine or into your production pipeline, inspect it with RepoGuard.*

</div>

---

## 💡 Why RepoGuard?

> *"I once received a link to an unfamiliar repository as part of a technical assignment. While reviewing it, I felt suspicious: the repository could contain backdoors, reverse shells, or malicious payloads. Finding no quick, reliable tool to inspect both GitHub reputation signals and deep code safety, I built **RepoGuard**."*

RepoGuard combines **GitHub reputation telemetry** with **deep AST static code analysis** to calculate a calibrated **Trust Score (1.0 to 10.0)** and explainable risk breakdown.

---

## ✨ Features

- 🔍 **Dual-Layer Evaluation**: Aggregates community telemetry (stars, maintainer activity, open issues ratio, license, forks) with deep static code security analysis.
- ⚡ **Abstract Syntax Tree (AST) Inspection**: Python code is parsed into abstract syntax trees to detect dangerous primitives (`eval`, `exec`, `pickle.loads`, `os.system`, `subprocess(shell=True)`, `pty.spawn`, `ctypes`) without executing code.
- 🛑 **Zero-Execution Clone Sandbox**: Hardened git cloning with `--no-recurse-submodules`, `--config core.symlinks=false`, and `--config core.hooksPath=/dev/null` (defeats clone-time RCE exploits like **CVE-2024-32002**).
- 👁️ **Trojan Source & Steganography Detection**: Detects invisible Unicode Bidirectional override characters (**CVE-2021-42574**) and zero-width spaces hiding payloads inside innocent-looking code.
- 🖥️ **IDE Workspace Auto-Run Detection**: Identifies `.vscode/tasks.json` `"runOn": "folderOpen"` directives and interpreter hijacking in `.vscode/settings.json` (the exact vector used in the **Lazarus Group "Contagious Interview"** campaign).
- 🐍 **Pre-Import `.pth` Execution Detection**: Detects Python `.pth` path configuration files that run arbitrary code via `import ` upon interpreter startup.
- 📦 **Package Lifecycle Hook Auditing**: Flags malicious `preinstall`/`postinstall` scripts in `package.json`, custom `cmdclass` hooks in `setup.py`, and `--extra-index-url` dependency confusion in `requirements.txt`.
- 🐳 **Container Escape Detection**: Detects `docker-compose.yml` configurations mounting the host root filesystem (`/:`) or Docker socket (`/var/run/docker.sock`).
- 🤖 **AI/ML Model Weight Scanning**: Flags untrusted pickled model files (`.pkl`, `.joblib`) vulnerable to `__reduce__` RCE exploits.
- 🔑 **Secret & Key Leak Prevention**: Detects committed private keys and sensitive credentials.
- 🎨 **Rich Terminal Interface**: Beautiful, color-coded interactive summaries, scoring factor breakdowns, and finding tables.
- 🤖 **CI/CD Native**: Supports `--format json` for automated pipelines and `--fail-under <score>` to gate pull requests.
- 💻 **Local & Remote Auditing**: Scan remote GitHub repositories or audit local working directories before pushing.

---

## 🌐 Supported Programming Languages & Threat Coverage

RepoGuard performs multi-language static analysis across all major modern programming ecosystems:

| Language | Extensions | Audited Threat Vectors |
| :--- | :--- | :--- |
| **Python** | `.py`, `.pyw`, `.pth` | AST analysis for `eval`, `exec`, `pickle`/`marshal` deserialization, `os.system`, `subprocess(shell=True)`, `ctypes`, `.pth` auto-execution, and `setup.py` hooks. |
| **JavaScript / TypeScript** | `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.jsx` | `eval()`, `Function()`, `child_process.exec/spawn`, `vm.runInContext`, and `package.json` lifecycle scripts (`preinstall`/`postinstall`). |
| **Go** | `.go` | Malicious `// #cgo` compiler directives, `os/exec.Command`, and raw `syscall.Syscall` invocation. |
| **Rust** | `.rs` | Arbitrary host command execution in `build.rs` or runtime (`std::process::Command`), memory-only shellcode injection via `VirtualAlloc`/`CreateThread`. |
| **C / C++** | `.c`, `.cpp`, `.cc`, `.cxx`, `.h`, `.hpp` | Shell execution (`system`, `popen`, `exec*`), RWX shellcode memory allocations (`VirtualAlloc` with `0x40`), `WinExec`, and `ShellExecute`. |
| **Java / Kotlin** | `.java`, `.kt`, `.kts` | `Runtime.exec`, `ProcessBuilder`, insecure Java deserialization (`ObjectInputStream.readObject`), and JNDI lookup injection (Log4Shell). |
| **C# / .NET** | `.cs` | `Process.Start`, in-memory dynamic assembly reflection (`Assembly.Load`), and insecure `BinaryFormatter.Deserialize`. |
| **PHP** | `.php`, `.phtml` | OS execution (`shell_exec`, `passthru`, `system`, `popen`, `proc_open`) and dynamic `assert()`. |
| **Ruby** | `.rb` | `Kernel.system`, `Kernel.exec`, piped command execution (`IO.popen`, `open("|...")`). |
| **Shell & PowerShell** | `.sh`, `.bash`, `.zsh`, `.ps1`, `.bat`, `.cmd` | Interactive reverse shells (`nc -e`, `/dev/tcp`), piped downloads (`curl \| bash`), and obfuscated PowerShell execution policy bypasses. |
| **All Files (Universal)** | *Any file* | **Trojan Source** BiDi overrides (**CVE-2021-42574**), zero-width character steganography, committed private keys, IDE auto-run (`tasks.json`), and container escapes. |

---

## 🚀 Installation

### Option 1: Editable / Development Installation
```bash
git clone https://github.com/zoebchhatriwala/repoguard.git
cd repoguard
pip install -e .
```

### Option 2: Requirements
```bash
pip install -r requirements.txt
```

---

## 🛠️ Usage

### CLI Quick Start

#### 1. Evaluate a Remote GitHub Repository
```bash
repoguard https://github.com/psf/requests
```

#### 2. Audit a Local Folder Before Pushing
```bash
repoguard ./my-project --local
```

#### 3. Use in CI/CD (Fail Pull Request if Trust Score < 7.0)
```bash
repoguard https://github.com/owner/repo --fail-under 7.0
```

#### 4. Output Machine-Readable JSON
```bash
repoguard https://github.com/owner/repo --format json --output report.json
```

#### 5. Using Authenticated GitHub Token (Higher Rate Limits)
```bash
# Pass explicitly or export GITHUB_TOKEN in your environment
export GITHUB_TOKEN="ghp_yourPersonalAccessToken"
repoguard https://github.com/owner/repo
```

---

## 📊 Trust Score Matrix

Repositories receive an explainable **Trust Score between 1.0 and 10.0**:

| Trust Level | Score Range | Classification & Recommendation |
| :--- | :--- | :--- |
| **TRUSTED** | `8.0 – 10.0` | 🟢 Healthy open source repository with strong maintenance, clear license, and clean static scan. |
| **MODERATE** | `5.0 – 7.9` | 🟡 Normal code health. Exercise standard peer review; inspect non-critical warnings. |
| **SUSPICIOUS** | `3.0 – 4.9` | 🟠 Multiple red flags (e.g. stale/archived, no license, dangerous functions, or long obfuscated lines). |
| **DANGEROUS** | `1.0 – 2.9` | 🔴 **Critical risk detected** (reverse shells, obfuscated payloads, exposed private keys, backdoors). |

---

## 🧠 Python API

You can embed RepoGuard directly into your Python scripts, security bots, or CI tools:

```python
from repoguard import evaluate_repository, scan_directory

# Evaluate a remote repository
result = evaluate_repository("https://github.com/pallets/flask")
print(f"Trust Score: {result.score}/10 ({result.trust_level.value})")

for reason in result.reasons:
    print(f" • {reason}")

# Scan a local folder directly
local_scan = scan_directory("./src")
print(f"Scanned {local_scan.scanned_files_count} files, found {len(local_scan.findings)} findings.")
```

---

## 🧪 Running Tests

RepoGuard comes with a comprehensive test suite covering API integrations, AST analysis, scoring edge cases, and CLI workflows:

```bash
# Run pytest with coverage report
pytest --cov=repoguard --cov-report=term
```

---

## 🛡️ Security Architecture

- **Hardened Git Clone Sandbox**: Remote cloning enforces `--no-recurse-submodules`, `--config core.symlinks=false`, and `--config core.hooksPath=/dev/null` alongside shallow single-branch cloning. This completely mitigates clone-time RCE vectors including **CVE-2024-32002** (submodule symlink traversal) and case-sensitivity overwrites.
- **Inert AST Parsing**: Python source analysis is performed purely via Python's native `ast` module without compiling, executing, or importing the target code.
- **Supply-Chain Threat Defenses**: Pre-execution inspection actively blocks IDE folder-open hooks (`tasks.json`), Python `.pth` startup execution, `package.json` install scripts, Docker root filesystem mounts, and Trojan Source BiDi control characters (**CVE-2021-42574**).
- **Strict Input Validation**: Repositories must match strict URL schemas and character allowlists to prevent option and command injection.
- **Safe Directory Cleanup**: Cross-platform file cleanup handles read-only git packfile permissions gracefully on Windows and POSIX.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
