# PatchForge 🛠️⚡
> Autonomous Security Patching & Code Refactoring Agent

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)]()

PatchForge is an autonomous developer agent that scans repositories for critical security vulnerabilities (SQL injection, shell execution, leaked secrets), generates AST-compliant remediations, and validates them in an isolated sandbox before exporting git-ready PR diffs.

---

## 🚀 Key Capabilities
- **AST Security Scanner:** Static inspection of Python Abstract Syntax Trees detecting OWASP Top 10 vectors without sending code to third-party APIs.
- **Semantic Code Rewriter:** Automatically transforms insecure patterns (e.g., string concatenation in DB queries, unescaped `os.system` calls) into secure, production-grade idioms.
- **Sandbox Validation:** Re-runs AST linting and security scanners in an isolated sandbox to ensure the patch introduces zero regressions.
- **Git PR Diff Generator:** Emits standard unified diff format (`.patch`) ready for direct inclusion in GitHub Pull Requests.

---

## ⚡ Quickstart

```bash
cd patchforge
python -m pip install -e .

# 1. Scan a repository or script
python -m patchforge.cli scan examples/vulnerable_app.py

# 2. Automatically generate validated patches and export diff
python -m patchforge.cli fix examples/vulnerable_app.py --diff-out patch.diff
```
