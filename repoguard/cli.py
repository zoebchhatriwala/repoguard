import argparse
from repoguard.evaluator import evaluate_repository
from repoguard.code_scanner import scan_codebase

def run_cli():
    parser = argparse.ArgumentParser(description="RepoGuard - Evaluate a GitHub repository for trust and safety.")
    parser.add_argument('repo_url', type=str, help="GitHub repository URL to evaluate")
    parser.add_argument('--token', type=str, help="GitHub API token (optional)", default=None)

    args = parser.parse_args()

    print(f"\nEvaluating repository: {args.repo_url}\n")

    # Evaluate the repository using the provided URL and token
    evaluation = evaluate_repository(args.repo_url, github_token=args.token)

    # Scan the codebase for suspicious files and long lines
    scan = scan_codebase(args.repo_url)

    # Print the evaluation score and reasons
    print(f"\nFinal Trust Score: {evaluation['score']}/10")

    # Print the reasons for the score
    print("\nReasons:")

    # Print each reason for the score
    for reason in evaluation['reasons']:
        print(f" - {reason}")

    # Print the evaluation details
    print("\nCode Scan Results:")

    # Get the number of suspicious files and long lines files
    len_suspicious_files = len(scan['suspicious_files'])

    # Print the number of suspicious files and hits
    print(f" - Suspicious Files: {len_suspicious_files}")

    # Print suspicious files
    for file in scan['suspicious_files']:
        print(f"   - {file['filename']} (Suspicious Hits: {file['suspicious_hits']}, Long Lines: {file['long_lines']})")

    # Optionally: Deduct points if code scan finds too much suspicious stuff
    if len_suspicious_files > 5:
        print("\nWarning: High number of suspicious files detected!")

# Main function to run the CLI
def main():
    run_cli()

# Entry point for the CLI
if __name__ == "__main__":
    main()
