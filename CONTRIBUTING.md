# Contributing to JWTBlaze

Thanks for your interest in contributing! We welcome bug reports, feature
requests, and pull requests.

How to contribute

1. Fork the repository and create a branch named `feature/your-feature` or
   `fix/your-fix`.
2. Make changes in a branch and keep commits small and focused.
3. Run tests and linters locally (see below).
4. Open a pull request against `main` with a clear description and test plan.

Coding style

- Use Python 3.10+ features where appropriate.
- Format code with `black` and check with `ruff` or `flake8` if you prefer.
- Keep functions small and add unit tests for new logic.

Testing

- We use `pytest` for unit tests. To run tests:

```bash
python -m pip install -U pytest
pytest
```

- CI will run linters and tests on each PR.

Security & responsible disclosure

If you find a security vulnerability, please follow the instructions in
SECURITY.md.
