# Security Policy

The RepoGuard project takes software safety and defensive engineering seriously. We appreciate responsible disclosure of any security vulnerabilities found in this repository.

## Reporting a Vulnerability

Please **DO NOT** open a public GitHub issue for security vulnerabilities, zero-days, or exploit disclosures.

Instead, report security vulnerabilities by creating a [Private Vulnerability Advisory](https://github.com/zoebchhatriwala/repoguard/security/advisories/new) on GitHub or emailing the maintainer with:
- Summary of the vulnerability and attack vector
- Steps or proof-of-concept to reproduce
- Affected components and versions

### Response & Remediation SLA

| Severity | Initial Acknowledgement | Triage & Fix SLA |
| :--- | :--- | :--- |
| **Critical** | Within 24 hours | Within 7 days |
| **High** | Within 48 hours | Within 14 days |
| **Medium / Low** | Within 7 days | Next release cycle |

## Security Architecture & Defenses

RepoGuard itself enforces the following security controls:
- **Zero Shell Injection**: Remote clones execute via safe argument vectors (`subprocess.run` list form) with disabled git hooks (`core.hooksPath=/dev/null`).
- **AST-Based Parsing**: Code analysis utilizes Python's native `ast` module rather than naïve string evaluation, preventing code execution during scanning.
- **Strict Canonicalization**: All remote and local target inputs are sanitized against command and parameter injection.
