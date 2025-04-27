# repoguard/code_scanner.py

import os
import re
import tempfile
import shutil
import subprocess

# Suspicious function patterns
SUSPICIOUS_PATTERNS = [
    r'\beval\(',
    r'\bexec\(',
    r'\bpickle\.load\(',
    r'\bos\.system\(',
    r'\bsubprocess\.',
    r'\bmarshal\.',
    r'\bctypes\.',
    r'\binput\(',
]

# Max line length to detect obfuscation
MAX_LINE_LENGTH = 500

def clone_repo(repo_url, target_dir):
    """
    Clones the given GitHub repository into the target directory.
    """
    subprocess.run(["git", "clone", "--depth=1", repo_url, target_dir], check=True)

def scan_file(filepath):
    """
    Scans a single file for suspicious patterns.
    """
    suspicious_hits = 0
    long_lines = 0

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()

                # Check suspicious patterns
                for pattern in SUSPICIOUS_PATTERNS:
                    if re.search(pattern, line):
                        suspicious_hits += 1

                # Check very long lines (possible obfuscation)
                if len(line) > MAX_LINE_LENGTH:
                    long_lines += 1

    except Exception as e:
        print(f"Failed to read {filepath}: {e}")

    return suspicious_hits, long_lines

def scan_codebase(repo_url):
    """
    Clones and scans a GitHub repository for suspicious code patterns.
    Returns a summary dict.
    """
    tmp_dir = tempfile.mkdtemp()
    suspicious_files = 0
    total_suspicious_hits = 0
    total_long_lines = 0

    try:
        clone_repo(repo_url, tmp_dir)

        for root, dirs, files in os.walk(tmp_dir):
            for file in files:
                if file.endswith(('.py', '.js', '.sh')):  # Scan common script files
                    filepath = os.path.join(root, file)
                    suspicious_hits, long_lines = scan_file(filepath)

                    if suspicious_hits > 0 or long_lines > 0:
                        suspicious_files += 1
                        total_suspicious_hits += suspicious_hits
                        total_long_lines += long_lines

    except subprocess.CalledProcessError:
        print(f"Failed to clone {repo_url}")
    finally:
        shutil.rmtree(tmp_dir)  # Clean up

    return {
        "suspicious_files": suspicious_files,
        "suspicious_hits": total_suspicious_hits,
        "long_lines": total_long_lines
    }
