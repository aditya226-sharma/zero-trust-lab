# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-07-20

### Added

- Governance files: LICENSE (MIT), CONTRIBUTING.md, SECURITY.md.
- CI workflow (`.github/workflows/ci.yml`): pytest + flake8 on push/PR to `main`.
- Mock OIDC provider (`gateway/mock-oidc/app.py`) with `/.well-known/openid-configuration`, `/oauth/token`, and `/userinfo` endpoints.
- Initial CHANGELOG entry.
