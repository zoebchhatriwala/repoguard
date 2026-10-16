"""GitHub API integration for metadata retrieval and repository verification."""

import os
import re
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse
import requests

GITHUB_API_URL = "https://api.github.com"
SAFE_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]+$")


def extract_owner_repo(repo_url: str) -> Tuple[str, str]:
    """
    Extracts and validates the owner and repository name from a GitHub URL.

    Supports:
    - https://github.com/owner/repo
    - https://github.com/owner/repo.git
    - http://github.com/owner/repo
    - git@github.com:owner/repo.git
    - github.com/owner/repo

    Raises:
        ValueError: If the URL is invalid or does not point to a GitHub repository.
    """
    if not repo_url or not isinstance(repo_url, str):
        raise ValueError("Repository URL must be a non-empty string.")

    repo_url = repo_url.strip()

    # Handle SSH format: git@github.com:owner/repo.git
    if repo_url.startswith("git@github.com:"):
        path = repo_url.split("git@github.com:", 1)[1]
    else:
        # Prepend scheme if missing (e.g. github.com/owner/repo)
        if not repo_url.startswith(("http://", "https://")):
            repo_url = f"https://{repo_url}"

        parsed = urlparse(repo_url)
        host = (parsed.hostname or "").lower()
        if host not in ("github.com", "www.github.com"):
            raise ValueError(f"Invalid host '{host}'. Only github.com repositories are supported.")

        if parsed.params or parsed.query:
            raise ValueError("Invalid characters or parameters in GitHub repository URL.")

        path = parsed.path

    # Strip leading/trailing slashes and trailing .git
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]

    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        raise ValueError("Invalid GitHub repository URL. Must be in the format 'owner/repo'.")

    owner, repo = parts[0], parts[1]

    if not SAFE_IDENTIFIER_PATTERN.match(owner) or not SAFE_IDENTIFIER_PATTERN.match(repo):
        raise ValueError("Invalid characters in GitHub repository owner or name.")

    return owner, repo


def fetch_repo_info(
    repo_url: str,
    github_token: Optional[str] = None,
    timeout: int = 15
) -> Dict[str, Any]:
    """
    Fetches repository metadata from the GitHub REST API.

    Args:
        repo_url: The URL of the GitHub repository.
        github_token: Optional personal access token (falls back to GITHUB_TOKEN env var).
        timeout: HTTP request timeout in seconds.

    Returns:
        Dict containing repository metadata.

    Raises:
        ValueError: If repository does not exist or URL is invalid.
        PermissionError: If API rate limit is exceeded or auth is rejected.
        RuntimeError: On communication or server errors.
    """
    owner, repo = extract_owner_repo(repo_url)
    token = github_token or os.environ.get("GITHUB_TOKEN")

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "RepoGuard/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    api_url = f"{GITHUB_API_URL}/repos/{owner}/{repo}"

    try:
        response = requests.get(api_url, headers=headers, timeout=timeout)
    except requests.exceptions.Timeout as e:
        raise RuntimeError(f"Connection timed out while querying GitHub API: {e}") from e
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Network error querying GitHub API: {e}") from e

    if response.status_code == 404:
        raise ValueError(
            f"Repository '{owner}/{repo}' not found on GitHub. "
            "Please check the spelling or verify that the repository is public."
        )

    if response.status_code == 401:
        raise PermissionError("GitHub API authorization failed. Please check your personal access token.")

    if response.status_code == 403:
        remaining = response.headers.get("x-ratelimit-remaining")
        if remaining == "0":
            raise PermissionError(
                "GitHub API rate limit exceeded. Set a GitHub token via --token or GITHUB_TOKEN environment variable."
            )
        raise PermissionError(f"Access forbidden by GitHub API: {response.text}")

    if response.status_code != 200:
        raise RuntimeError(f"GitHub API returned error ({response.status_code}): {response.text}")

    data = response.json()
    license_info = data.get("license") or {}
    license_name = license_info.get("spdx_id") or license_info.get("name")

    return {
        "name": data.get("name"),
        "full_name": data.get("full_name") or f"{owner}/{repo}",
        "owner": data.get("owner", {}).get("login", owner),
        "description": data.get("description") or "",
        "stars": data.get("stargazers_count", 0),
        "forks": data.get("forks_count", 0),
        "watchers": data.get("watchers_count", 0),
        "open_issues": data.get("open_issues_count", 0),
        "license": license_name,
        "size_kb": data.get("size", 0),
        "last_updated": data.get("updated_at"),
        "pushed_at": data.get("pushed_at"),
        "created_at": data.get("created_at"),
        "is_archived": data.get("archived", False),
        "is_fork": data.get("fork", False),
        "has_wiki": data.get("has_wiki", False),
        "default_branch": data.get("default_branch", "main"),
    }
