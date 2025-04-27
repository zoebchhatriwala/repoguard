from .github_api import fetch_repo_info
from datetime import datetime, timezone

def calculate_days_since(date_str):
    """
    Calculates the number of days since the given ISO formatted date string.
    """
    last_update = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    return (now - last_update).days

def evaluate_repository(repo_url, github_token=None):
    """
    Evaluates a GitHub repository and returns a score between 1 and 10,
    along with detailed reasoning.
    """
    repo_info = fetch_repo_info(repo_url, github_token)
    score = 5  # Neutral starting score
    reasons = []

    # Popularity
    if repo_info['stars'] > 500:
        score += 2
        reasons.append("High star count (>500)")
    elif repo_info['stars'] > 100:
        score += 1
        reasons.append("Moderate star count (>100)")
    else:
        score -= 1
        reasons.append("Low star count (<100)")

    # Recent activity
    days_since_update = calculate_days_since(repo_info['last_updated'])
    if days_since_update < 30:
        score += 1
        reasons.append("Recently updated (<30 days)")
    elif days_since_update > 365:
        score -= 2
        reasons.append("Stale repository (>1 year since last update)")

    # License
    if repo_info['license'] is None:
        score -= 2
        reasons.append("No license detected")

    # Open issues
    if repo_info['open_issues'] > 100:
        score -= 1
        reasons.append("High number of open issues (>100)")
    elif repo_info['open_issues'] == 0:
        score += 1
        reasons.append("No open issues")

    # Normalize the score between 1 and 10
    final_score = max(1, min(10, score))

    return {
        "repo_url": repo_url,
        "score": final_score,
        "reasons": reasons,
        "repo_info": repo_info
    }
