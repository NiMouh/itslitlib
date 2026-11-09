# Changelog

All notable changes to this project will be documented in this file.

## 0.1.1 - 2026-11-09

- Replaced top-level `sitecustomize` startup mechanism with a package-owned `.pth` startup hook.
- Added `itslitlib_startup.pth` and packaging configuration to install it into venv `site-packages` so it is processed at interpreter startup.
- Removed `src/sitecustomize.py` to avoid collisions with system `sitecustomize`.
- Updated startup-hook documentation in `README.md`.

## 0.1.0 - 2026-11-09

- Initial release of `itslitlib` colored prompt/print utilities.
- Added optional `net-probe` command and startup dry-run probe behavior.
