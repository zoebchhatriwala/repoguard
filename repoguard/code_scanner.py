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
    r'\bopen\(',
    r'\bexecfile\(',
    r'\bcompile\(',
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
    suspicious_files = []

    try:
        # Clone the repository
        clone_repo(repo_url, tmp_dir)

        # Walk through the cloned directory
        for root, dirs, files in os.walk(tmp_dir):
            for file in files:
                if file.endswith(('.py', '.js', '.sh', '.ts', '.tsx', '.jsx')):  # Scan common script files
                    # Construct the full file path
                    filepath = os.path.join(root, file)

                    # Scan the file for suspicious patterns
                    suspicious_hits, long_lines = scan_file(filepath)

                    # If there are suspicious hits or long lines, add to the list
                    if suspicious_hits > 0 or long_lines > 0:
                        suspicious_files.append({
                            "filename": str.replace(filepath, tmp_dir + os.sep, '', 1),
                            "suspicious_hits": suspicious_hits,
                            "long_lines": long_lines,
                        })

                elif file.endswith(('.exe', '.dll', '.so')):  # Binary files are suspicious by default
                    suspicious_files.append({
                        "filename": str.replace(filepath, tmp_dir + os.sep, '', 1),
                        "suspicious_hits": 1,
                        "long_lines": 0,
                    })


    except subprocess.CalledProcessError:
        # If the clone fails, we can assume the repo is not accessible or doesn't exist
        print(f"Failed to clone {repo_url}")
    finally:
        shutil.rmtree(tmp_dir)  # Clean up

    return {
        "suspicious_files": suspicious_files,
    }
