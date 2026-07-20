# Contributing

Thank you for your interest in contributing to the Zero-Trust Lab!

## Getting Started

1. Fork the repository.
2. Create a feature branch (`git checkout -b feat/my-feature`).
3. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```
4. Make your changes.
5. Run tests: `pytest`
6. Run flake8: `flake8 .`
7. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` — new feature
   - `fix:` — bug fix
   - `chore:` — maintenance, tooling, config
   - `docs:` — documentation only
   - `refactor:` — code change with no functional impact
8. Push and open a pull request against `main`.

## Code Style

- Follow PEP 8.
- Keep functions small and focused.
- Write tests for new functionality.
- Update or add checkpoint docs if the lab topology changes.

## Pull Request Process

- Ensure CI passes (tests + lint).
- At least one approving review is required before merging.
- Squash-merge into `main` with a clean commit message.
