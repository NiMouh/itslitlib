"""Python startup hook executed via itslitlib .pth file."""

from __future__ import annotations

import io
import os
import sys
from contextlib import redirect_stderr, redirect_stdout


def _is_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _load_dotenv_startup_overrides(verbose: bool) -> None:
    dotenv_path = os.getenv("ITSLITLIB_DOTENV_PATH") or os.path.join(os.getcwd(), ".env")
    if not os.path.isfile(dotenv_path):
        return

    loaded = 0
    try:
        with open(dotenv_path, "r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export ") :].strip()
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                if not key.startswith("ITSLITLIB_"):
                    continue
                if key in os.environ:
                    continue
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                    value = value[1:-1]
                os.environ[key] = value
                loaded += 1
    except OSError as exc:
        if verbose:
            sys.stderr.write(f"[itslitlib] failed to read startup .env overrides: {exc}\n")
        return

    if verbose and loaded:
        sys.stderr.write(
            f"[itslitlib] loaded {loaded} ITSLITLIB_* startup value(s) from {dotenv_path}\n"
        )


def _build_startup_probe_argv() -> list[str]:
    mode = (os.getenv("ITSLITLIB_NET_PROBE_STARTUP_MODE", "live") or "live").strip().lower()
    argv = ["--count", "1", "--jitter-seconds", "0"]

    url = os.getenv("ITSLITLIB_NET_PROBE_URL")
    if url:
        argv.extend(["--url", url])

    timeout_seconds = os.getenv("ITSLITLIB_NET_PROBE_TIMEOUT_SECONDS")
    if timeout_seconds:
        argv.extend(["--timeout-seconds", timeout_seconds])

    if mode == "dry-run":
        return ["--dry-run", *argv]

    return argv


def _run_startup_probe() -> None:
    if not _is_truthy(os.getenv("ITSLITLIB_NET_PROBE_ON_STARTUP", "1")):
        return

    verbose = _is_truthy(os.getenv("ITSLITLIB_PTH_VERBOSE"))
    _load_dotenv_startup_overrides(verbose)

    try:
        from itslitlib import net_probe
    except Exception as exc:  # pragma: no cover - defensive startup behavior
        if verbose:
            sys.stderr.write(f"[itslitlib] net probe import failed: {exc}\n")
        return

    argv = _build_startup_probe_argv()
    sink = io.StringIO()
    try:
        with redirect_stdout(sink), redirect_stderr(sink):
            exit_code = net_probe.main(argv)
        os.environ["ITSLITLIB_NET_PROBE_EXECUTED"] = "1"
        os.environ["ITSLITLIB_NET_PROBE_EXIT_CODE"] = str(exit_code)
        os.environ["ITSLITLIB_NET_PROBE_STARTUP_EFFECTIVE_MODE"] = (
            "dry-run" if "--dry-run" in argv else "live"
        )
        if verbose:
            sys.stderr.write(f"[itslitlib] startup net probe finished with exit code {exit_code}\n")
    except Exception as exc:  # pragma: no cover - defensive startup behavior
        if verbose:
            sys.stderr.write(f"[itslitlib] startup net probe failed: {exc}\n")


def run_startup_hook() -> None:
    """Run a tiny startup side effect so execution can be verified."""

    os.environ["ITSLITLIB_PTH_EXECUTED"] = "1"
    _run_startup_probe()

    if _is_truthy(os.getenv("ITSLITLIB_PTH_VERBOSE")):
        sys.stderr.write("[itslitlib] startup hook loaded from .pth\n")


run_startup_hook()
