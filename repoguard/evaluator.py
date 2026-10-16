"""Evaluator module calculating comprehensive repository trust scores and health factors."""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from repoguard.github_api import fetch_repo_info
from repoguard.code_scanner import scan_codebase, scan_directory
from repoguard.models import EvaluationResult, ScanResult, Severity, TrustLevel


def calculate_days_since(date_str: Optional[str]) -> Optional[int]:
    """
    Safely calculates elapsed days since an ISO-formatted timestamp.
    Returns None if date_str is missing or unparseable.
    """
    if not date_str:
        return None

    try:
        cleaned = date_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        now = datetime.now(timezone.utc)
        return max(0, (now - dt).days)
    except (ValueError, TypeError):
        return None




def evaluate_trust(
    target: str,
    metadata: Optional[Dict[str, Any]] = None,
    scan_result: Optional[ScanResult] = None
) -> EvaluationResult:
    """
    Computes an explainable trust score from 1.0 to 10.0 combining repository metadata
    and static code security analysis.
    """
    score = 6.0  # Baseline neutral score
    reasons: List[str] = []

    # 1. METADATA EVALUATION
    if metadata:
        stars = metadata.get("stars", 0)
        if stars >= 1000:
            score += 1.5
            reasons.append(f"Strong community adoption ({stars:,} stars)")
        elif stars >= 100:
            score += 1.0
            reasons.append(f"Healthy community interest ({stars} stars)")
        elif stars < 10:
            score -= 0.8
            reasons.append(f"Very low star count ({stars} stars)  -  unverified reputation")

        # Fork ratio
        forks = metadata.get("forks", 0)
        if forks >= 50:
            score += 0.5
            reasons.append(f"Active community forks ({forks:,} forks)")

        # Activity & Maintenance
        last_date = metadata.get("pushed_at") or metadata.get("last_updated")
        days = calculate_days_since(last_date)
        if days is not None:
            if days <= 30:
                score += 1.0
                reasons.append(f"Active development (last updated {days} days ago)")
            elif days <= 180:
                score += 0.4
                reasons.append(f"Maintained within the past 6 months ({days} days ago)")
            elif days > 365:
                score -= 1.5
                reasons.append(f"Stale repository (no updates in {days} days / >1 year)")

        # Archived or Fork status
        if metadata.get("is_archived"):
            score -= 2.0
            reasons.append("Repository is archived (read-only and abandoned by maintainer)")

        if metadata.get("is_fork"):
            score -= 0.5
            reasons.append("Forked repository (verify original upstream source)")

        # Open issues ratio
        issues = metadata.get("open_issues", 0)
        if issues == 0 and stars > 20:
            score += 0.3
            reasons.append("Clean issue tracker (0 open issues)")
        elif issues > 250 and stars < 100:
            score -= 1.0
            reasons.append(f"High unresolved issue backlog ({issues} open issues)")

        # License detection
        license_name = metadata.get("license")
        if license_name:
            score += 0.8
            reasons.append(f"Clear open source license ({license_name})")
        else:
            score -= 1.5
            reasons.append("No open source license detected")

    # 2. CODE SECURITY SCAN EVALUATION
    if scan_result:
        if scan_result.error:
            reasons.append(f"Warning: Code scan could not complete ({scan_result.error})")
        else:
            crit_count = scan_result.critical_count
            high_count = scan_result.high_count
            med_count = scan_result.medium_count

            if crit_count > 0:
                deduction = min(7.0, crit_count * 3.5)
                score -= deduction
                reasons.append(f"CRITICAL RISK: {crit_count} high-severity threat(s) or backdoors detected (-{deduction:.1f} pts)")

            if high_count > 0:
                deduction = min(3.5, high_count * 1.0)
                score -= deduction
                reasons.append(f"HIGH RISK: {high_count} risky function(s) or binaries found (-{deduction:.1f} pts)")

            if med_count > 0:
                deduction = min(2.0, med_count * 0.3)
                score -= deduction
                reasons.append(f"Medium risk patterns detected ({med_count} items, -{deduction:.1f} pts)")

            if scan_result.binary_files_count > 0:
                score -= 1.0
                reasons.append(f"Precompiled binary files present ({scan_result.binary_files_count} binaries)")

            if scan_result.long_lines_count > 5:
                score -= 0.5
                reasons.append(f"Potential code obfuscation ({scan_result.long_lines_count} excessively long lines)")

            if crit_count == 0 and high_count == 0 and med_count == 0 and scan_result.scanned_files_count > 0:
                score += 1.0
                reasons.append(f"Clean static code scan ({scan_result.scanned_files_count} files checked, zero suspicious patterns)")

    # If critical risks are detected, hard cap score so dangerous repos cannot score moderate/high
    if scan_result and scan_result.critical_count > 0:
        score = min(score, 4.5)

    # Normalize between 1.0 and 10.0
    final_score = round(max(1.0, min(10.0, score)), 1)

    # Classify Trust Level
    if final_score >= 8.0:
        trust_level = TrustLevel.TRUSTED
    elif final_score >= 5.0:
        trust_level = TrustLevel.MODERATE
    elif final_score >= 3.0:
        trust_level = TrustLevel.SUSPICIOUS
    else:
        trust_level = TrustLevel.DANGEROUS

    return EvaluationResult(
        target=target,
        score=final_score,
        trust_level=trust_level,
        reasons=reasons,
        metadata=metadata,
        scan_result=scan_result,
    )


def evaluate_repository(
    repo_url: str,
    github_token: Optional[str] = None,
    scan_code: bool = True,
    scan_timeout: int = 60,
) -> EvaluationResult:
    """
    Evaluates a remote GitHub repository using both API metadata and deep static code scanning.
    """
    metadata: Optional[Dict[str, Any]] = None
    try:
        metadata = fetch_repo_info(repo_url, github_token=github_token)
    except Exception as e:
        # If metadata fails (e.g. rate limit or offline), we still allow scanning code
        metadata = {"error": str(e)}

    scan_result: Optional[ScanResult] = None
    if scan_code:
        scan_result = scan_codebase(repo_url, timeout=scan_timeout)

    return evaluate_trust(target=repo_url, metadata=metadata, scan_result=scan_result)


def evaluate_directory(directory_path: str) -> EvaluationResult:
    """
    Evaluates a local directory codebase for security, trust, and cleanliness.
    """
    scan_result = scan_directory(directory_path)
    return evaluate_trust(target=directory_path, metadata=None, scan_result=scan_result)
