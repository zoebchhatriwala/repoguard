# RepoGuard

**RepoGuard** is a Python tool that evaluates GitHub repositories for **trustworthiness**, **safety**, and **code health**.

It combines:

- **Metadata analysis** (stars, last update, license, open issues)
- **Static code scanning** (for risky functions like `eval()`, `exec()`, `pickle.load()` etc.)

Result: a **Trust Score from 1 to 10** 📊

---

## Why RepoGuard?

> "I once received a link to a GitHub repository as part of a coding test.  
> While reviewing it, I felt suspicious — the repo could potentially contain malicious code — but I couldn't find an easy tool to evaluate it quickly and reliably.
>
> That's why I built **RepoGuard** — a simple way to analyze and rate a repository’s trustworthiness before you run anything on your machine."

Stay safe, trust wisely!

---

## Installation

Clone the project:

```bash
git clone https://github.com/zoebchhatriwala/repoguard.git
cd repoguard
```
