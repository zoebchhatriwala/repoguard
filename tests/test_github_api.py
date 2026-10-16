"""Tests for GitHub API integration and URL extraction."""

import pytest
from unittest.mock import patch, MagicMock
from repoguard.github_api import extract_owner_repo, fetch_repo_info


def test_extract_owner_repo_standard_https():
    owner, repo = extract_owner_repo("https://github.com/torvalds/linux")
    assert owner == "torvalds"
    assert repo == "linux"


def test_extract_owner_repo_with_git_suffix():
    owner, repo = extract_owner_repo("https://github.com/psf/requests.git")
    assert owner == "psf"
    assert repo == "requests"


def test_extract_owner_repo_with_trailing_slash():
    owner, repo = extract_owner_repo("https://github.com/python/cpython/")
    assert owner == "python"
    assert repo == "cpython"


def test_extract_owner_repo_ssh_format():
    owner, repo = extract_owner_repo("git@github.com:facebook/react.git")
    assert owner == "facebook"
    assert repo == "react"


def test_extract_owner_repo_without_scheme():
    owner, repo = extract_owner_repo("github.com/pallets/flask")
    assert owner == "pallets"
    assert repo == "flask"


def test_extract_owner_repo_invalid_host():
    with pytest.raises(ValueError, match="Invalid host"):
        extract_owner_repo("https://gitlab.com/user/project")


def test_extract_owner_repo_invalid_format():
    with pytest.raises(ValueError, match="Invalid GitHub repository URL"):
        extract_owner_repo("https://github.com/singlepart")


def test_extract_owner_repo_empty():
    with pytest.raises(ValueError):
        extract_owner_repo("")


def test_extract_owner_repo_injection_characters():
    with pytest.raises(ValueError, match="Invalid characters"):
        extract_owner_repo("https://github.com/owner/repo;rm -rf")


@patch("repoguard.github_api.requests.get")
def test_fetch_repo_info_success(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "name": "repoguard",
        "full_name": "zoebchhatriwala/repoguard",
        "owner": {"login": "zoebchhatriwala"},
        "description": "Security evaluator",
        "stargazers_count": 150,
        "forks_count": 25,
        "watchers_count": 150,
        "open_issues_count": 2,
        "license": {"spdx_id": "MIT"},
        "size": 1024,
        "updated_at": "2026-10-15T12:00:00Z",
        "pushed_at": "2026-10-15T12:30:00Z",
        "archived": False,
        "fork": False,
        "has_wiki": True,
        "default_branch": "main",
    }
    mock_get.return_value = mock_resp

    data = fetch_repo_info("https://github.com/zoebchhatriwala/repoguard", github_token="test_token")

    assert data["name"] == "repoguard"
    assert data["stars"] == 150
    assert data["license"] == "MIT"
    assert data["is_archived"] is False
    assert mock_get.call_args[1]["headers"]["Authorization"] == "Bearer test_token"


@patch("repoguard.github_api.requests.get")
def test_fetch_repo_info_not_found(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_get.return_value = mock_resp

    with pytest.raises(ValueError, match="not found on GitHub"):
        fetch_repo_info("https://github.com/unknown/nonexistent-repo-12345")


@patch("repoguard.github_api.requests.get")
def test_fetch_repo_info_rate_limit(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.headers = {"x-ratelimit-remaining": "0"}
    mock_resp.text = "API rate limit exceeded"
    mock_get.return_value = mock_resp

    with pytest.raises(PermissionError, match="rate limit exceeded"):
        fetch_repo_info("https://github.com/owner/repo")
