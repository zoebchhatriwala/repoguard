import argparse
from .evaluator import evaluate_repository
from .code_scanner import scan_codebase

def main():
    parser = argparse.ArgumentParser(description="RepoGuard - Evaluate a GitHub repository for trust and safety.")
    parser.add_argument('repo_url', type=str, help="GitHub repository URL to evaluate")
    parser.add_argument('--token', type=str, help="GitHub API token (optional)", default=None)

    args = parser.parse_args()

    print(f"\nEvaluating repository: {args.repo_url}\n")

    evaluation = evaluate_repository(args.repo_url, github_token=args.token)
    scan = scan_codebase(args.repo_url)

    print(f"Final Trust Score: {evaluation['score']}/10")
    print("\nReasons:")
    for reason in evaluation['reasons']:
        print(f" - {reason}")

    print("\nCode Scan Results:")
    print(f" - Suspicious Files: {scan['suspicious_files']}")
    print(f" - Suspicious Hits: {scan['suspicious_hits']}")
    print(f" - Long Lines (possible obfuscation): {scan['long_lines']}")
    
    # Optionally: Deduct points if code scan finds too much suspicious stuff
    if scan['suspicious_files'] > 5:
        print("\nWarning: High number of suspicious files detected!")

if __name__ == "__main__":
    main()
