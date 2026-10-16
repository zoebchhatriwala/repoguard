"""RepoGuard - Evaluate GitHub repositories for trust, safety, and code health."""

__version__ = "1.0.0"

from repoguard.evaluator import evaluate_repository
from repoguard.code_scanner import scan_codebase, scan_directory
from repoguard.github_api import fetch_repo_info, extract_owner_repo

__all__ = [
    "__version__",
    "evaluate_repository",
    "scan_codebase",
    "scan_directory",
    "fetch_repo_info",
    "extract_owner_repo",
]
