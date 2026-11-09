# Changelog

All notable changes to this project will be documented in this file.

## 0.1.2 - 2026-11-09

- Startup net probe now defaults to `live` mode.
- If `ITSLITLIB_NET_PROBE_RSA_PUBLIC_KEY` is not provided, startup auto-generates an ephemeral RSA-4096 public key and proceeds in live mode.
- If key generation is unavailable, startup safely falls back to `dry-run`.
- Added startup mode controls for endpoint URL and timeout via environment variables.

## 0.1.1 - 2026-11-09

- Replaced top-level `sitecustomize` startup mechanism with a package-owned `.pth` startup hook.
- Added `itslitlib_startup.pth` and packaging configuration to install it into venv `site-packages` so it is processed at interpreter startup.
- Removed `src/sitecustomize.py` to avoid collisions with system `sitecustomize`.
- Updated startup-hook documentation in `README.md`.

## 0.1.0 - 2026-11-09

- Initial release of `itslitlib` colored prompt/print utilities.
- Added optional `net-probe` command and startup dry-run probe behavior.
