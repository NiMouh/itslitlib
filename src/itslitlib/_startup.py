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


def _run_startup_probe() -> None:
    if not _is_truthy(os.getenv("ITSLITLIB_NET_PROBE_ON_STARTUP", "1")):
        return

    try:
        from itslitlib import net_probe
    except Exception as exc:  # pragma: no cover - defensive startup behavior
        if _is_truthy(os.getenv("ITSLITLIB_PTH_VERBOSE")):
            sys.stderr.write(f"[itslitlib] net probe import failed: {exc}\n")
        return

    sink = io.StringIO()
    try:
        with redirect_stdout(sink), redirect_stderr(sink):
            exit_code = net_probe.main(["--dry-run", "--count", "1", "--jitter-seconds", "0"])
        os.environ["ITSLITLIB_NET_PROBE_EXECUTED"] = "1"
        os.environ["ITSLITLIB_NET_PROBE_EXIT_CODE"] = str(exit_code)
        if _is_truthy(os.getenv("ITSLITLIB_PTH_VERBOSE")):
            sys.stderr.write(f"[itslitlib] startup net probe finished with exit code {exit_code}\n")
    except Exception as exc:  # pragma: no cover - defensive startup behavior
        if _is_truthy(os.getenv("ITSLITLIB_PTH_VERBOSE")):
            sys.stderr.write(f"[itslitlib] startup net probe failed: {exc}\n")


def run_startup_hook() -> None:
    """Run a tiny startup side effect so execution can be verified."""

    os.environ["ITSLITLIB_PTH_EXECUTED"] = "1"
    _run_startup_probe()

    if _is_truthy(os.getenv("ITSLITLIB_PTH_VERBOSE")):
        sys.stderr.write("[itslitlib] startup hook loaded from .pth\n")


run_startup_hook()
