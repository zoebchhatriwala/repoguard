import requests
from urllib.parse import urlparse

GITHUB_API_URL = "https://api.github.com"

def extract_owner_repo(repo_url):
    """
    Extracts the owner and repository name from a GitHub URL.
    Example: https://github.com/owner/repo -> ('owner', 'repo')
    """
    parsed = urlparse(repo_url)
    parts = parsed.path.strip("/").split("/")
    if len(parts) >= 2:
        return parts[0], parts[1]
    else:
        raise ValueError("Invalid GitHub repository URL.")

def fetch_repo_info(repo_url, github_token=None):
    """
    Fetches repository metadata from GitHub API.
    Optionally accepts a GitHub token for authenticated requests.
    """
    owner, repo = extract_owner_repo(repo_url)
    headers = {}
    
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    
    response = requests.get(f"{GITHUB_API_URL}/repos/{owner}/{repo}", headers=headers)

    if response.status_code != 200:
        raise Exception(f"Failed to fetch repo info: {response.status_code} {response.text}")

    data = response.json()

    repo_info = {
        "name": data.get("name"),
        "owner": data.get("owner", {}).get("login"),
        "stars": data.get("stargazers_count", 0),
        "forks": data.get("forks_count", 0),
        "watchers": data.get("watchers_count", 0),
        "open_issues": data.get("open_issues_count", 0),
        "license": data.get("license", {}).get("name") if data.get("license") else None,
        "size": data.get("size", 0),
        "last_updated": data.get("updated_at"),
    }

    return repo_info
