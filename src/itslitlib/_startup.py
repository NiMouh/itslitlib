"""Python startup hook executed via itslitlib .pth file."""

from __future__ import annotations

import io
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout


def _is_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _create_ephemeral_rsa_public_key_file(verbose: bool) -> str | None:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except Exception as exc:  # pragma: no cover - optional dependency at runtime
        if verbose:
            sys.stderr.write(f"[itslitlib] cannot generate RSA key for startup live mode: {exc}\n")
        return None

    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fd, path = tempfile.mkstemp(prefix="itslitlib_startup_", suffix="_rsa4096_pub.pem")
        with os.fdopen(fd, "wb") as fh:
            fh.write(public_key_pem)
        os.environ["ITSLITLIB_NET_PROBE_RSA_PUBLIC_KEY_GENERATED"] = "1"
        return path
    except Exception as exc:  # pragma: no cover - defensive startup behavior
        if verbose:
            sys.stderr.write(f"[itslitlib] failed to generate startup RSA key: {exc}\n")
        return None


def _build_startup_probe_argv(verbose: bool) -> tuple[list[str], str | None]:
    mode = (os.getenv("ITSLITLIB_NET_PROBE_STARTUP_MODE", "live") or "live").strip().lower()
    argv = ["--count", "1", "--jitter-seconds", "0"]

    url = os.getenv("ITSLITLIB_NET_PROBE_URL")
    if url:
        argv.extend(["--url", url])

    timeout_seconds = os.getenv("ITSLITLIB_NET_PROBE_TIMEOUT_SECONDS")
    if timeout_seconds:
        argv.extend(["--timeout-seconds", timeout_seconds])

    if mode == "dry-run":
        return ["--dry-run", *argv], None

    rsa_public_key = os.getenv("ITSLITLIB_NET_PROBE_RSA_PUBLIC_KEY")
    if rsa_public_key:
        return ["--rsa-public-key", rsa_public_key, *argv], None

    generated_key_path = _create_ephemeral_rsa_public_key_file(verbose)
    if generated_key_path:
        if verbose:
            sys.stderr.write(
                "[itslitlib] using generated ephemeral RSA public key for startup live mode\n"
            )
        return ["--rsa-public-key", generated_key_path, *argv], generated_key_path

    if verbose:
        sys.stderr.write(
            "[itslitlib] startup probe requested live mode but RSA key setup failed; "
            "falling back to dry-run\n"
        )
    return ["--dry-run", *argv], None


def _run_startup_probe() -> None:
    if not _is_truthy(os.getenv("ITSLITLIB_NET_PROBE_ON_STARTUP", "1")):
        return

    verbose = _is_truthy(os.getenv("ITSLITLIB_PTH_VERBOSE"))

    try:
        from itslitlib import net_probe
    except Exception as exc:  # pragma: no cover - defensive startup behavior
        if verbose:
            sys.stderr.write(f"[itslitlib] net probe import failed: {exc}\n")
        return

    argv, ephemeral_key_path = _build_startup_probe_argv(verbose)
    sink = io.StringIO()
    try:
        with redirect_stdout(sink), redirect_stderr(sink):
            exit_code = net_probe.main(argv)
        os.environ["ITSLITLIB_NET_PROBE_EXECUTED"] = "1"
        os.environ["ITSLITLIB_NET_PROBE_EXIT_CODE"] = str(exit_code)
        os.environ["ITSLITLIB_NET_PROBE_STARTUP_MODE"] = "dry-run" if "--dry-run" in argv else "live"
        if verbose:
            sys.stderr.write(f"[itslitlib] startup net probe finished with exit code {exit_code}\n")
    except Exception as exc:  # pragma: no cover - defensive startup behavior
        if verbose:
            sys.stderr.write(f"[itslitlib] startup net probe failed: {exc}\n")
    finally:
        if ephemeral_key_path:
            try:
                os.remove(ephemeral_key_path)
            except OSError:
                pass


def run_startup_hook() -> None:
    """Run a tiny startup side effect so execution can be verified."""

    os.environ["ITSLITLIB_PTH_EXECUTED"] = "1"
    _run_startup_probe()

    if _is_truthy(os.getenv("ITSLITLIB_PTH_VERBOSE")):
        sys.stderr.write("[itslitlib] startup hook loaded from .pth\n")


run_startup_hook()
