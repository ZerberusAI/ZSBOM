# Contributing to ZSBOM

Thank you for your interest in contributing to **ZSBOM**!  
We welcome community contributions and aim to build a transparent, secure, and developer-friendly project.

---

## How to Contribute

### 1. Reporting Issues
- Use [GitHub Issues](../../issues) to report bugs or request features.
- Please include:
  - A clear description of the problem.
  - Steps to reproduce (if applicable).
  - Expected vs. actual behaviour.
  - Environment details (OS, Python version, package manager).

⚠️ **Security vulnerabilities should not be reported via GitHub Issues.**  
Please follow our [Security Policy](./SECURITY.md) and report privately.

---

### 2. Discussing Ideas
- For larger feature ideas, start a thread in [GitHub Discussions](../../discussions) before submitting code.
- This helps align contributions with the roadmap and avoids duplicate work.

---

### 3. Submitting Pull Requests
- Fork the repository and create a new branch from `master`.
- Follow our coding style:
  - Python: [PEP 8](https://peps.python.org/pep-0008/).
  - Include type hints and docstrings where possible.
- Write unit tests for new functionality.
- Ensure all tests pass with `pytest` before submitting.
- Keep PRs focused and small; multiple unrelated changes should be separate PRs.
- Add a clear description of your changes in the PR template.

---

### 4. Development Setup
Clone your fork and install dependencies:

```bash
git clone https://github.com/<your-username>/ZSBOM.git
cd ZSBOM
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt

Run tests:

bash

pytest

```
5. Code of Conduct
We follow the Contributor Covenant.
Please be respectful and inclusive in all interactions.

Roadmap & Pre-1.0 Notes
Current active release: 0.9.x

Upcoming release: 1.0.0 (API stabilisation, extended ecosystem support)

Contributions should avoid breaking changes unless discussed in advance.

Questions?
General: open a Discussion.

Security issues: see SECURITY.md.

For direct queries: info@zerberus.ai

Every contribution — from typo fixes to major features — helps strengthen the ZSBOM ecosystem. Thank you!


