"""Colored terminal prompt and print helpers."""

from __future__ import annotations

import os
import sys
from typing import Final, Iterable

RESET: Final[str] = "\033[0m"

_TEXT_COLORS: Final[dict[str, str]] = {
    "default": "",
    "black": "\033[30m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "bright_black": "\033[90m",
    "bright_red": "\033[91m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_blue": "\033[94m",
    "bright_magenta": "\033[95m",
    "bright_cyan": "\033[96m",
    "bright_white": "\033[97m",
}

_BACKGROUND_COLORS: Final[dict[str, str]] = {
    "default": "",
    "black": "\033[40m",
    "red": "\033[41m",
    "green": "\033[42m",
    "yellow": "\033[43m",
    "blue": "\033[44m",
    "magenta": "\033[45m",
    "cyan": "\033[46m",
    "white": "\033[47m",
    "bright_black": "\033[100m",
    "bright_red": "\033[101m",
    "bright_green": "\033[102m",
    "bright_yellow": "\033[103m",
    "bright_blue": "\033[104m",
    "bright_magenta": "\033[105m",
    "bright_cyan": "\033[106m",
    "bright_white": "\033[107m",
}

_STYLES: Final[dict[str, str]] = {
    "bold": "\033[1m",
    "dim": "\033[2m",
    "italic": "\033[3m",
    "underline": "\033[4m",
    "blink": "\033[5m",
    "reverse": "\033[7m",
}


def _normalize(name: str | None) -> str | None:
    if name is None:
        return None
    return name.strip().lower().replace("-", "_").replace(" ", "_")


def _resolve_code(name: str | None, mapping: dict[str, str], label: str) -> str:
    if name is None:
        return ""
    key = _normalize(name)
    if key not in mapping:
        allowed = ", ".join(sorted(mapping.keys()))
        raise ValueError(f"Unknown {label}: {name!r}. Allowed {label}s: {allowed}")
    return mapping[key]


def _should_use_color(enabled: bool | None, stream: object | None) -> bool:
    if enabled is not None:
        return enabled
    if os.getenv("NO_COLOR"):
        return False

    target = stream if stream is not None else sys.stdout
    isatty = getattr(target, "isatty", None)
    if callable(isatty):
        return bool(isatty())
    return True


def available_colors() -> list[str]:
    """Return supported text color names."""

    return sorted(_TEXT_COLORS.keys())


def available_backgrounds() -> list[str]:
    """Return supported background color names."""

    return sorted(_BACKGROUND_COLORS.keys())


def available_styles() -> list[str]:
    """Return supported style names."""

    return sorted(_STYLES.keys())


def colorize(
    text: str,
    *,
    color: str | None = "default",
    background: str | None = None,
    styles: str | Iterable[str] | None = None,
    enabled: bool | None = None,
    stream: object | None = None,
) -> str:
    """Wrap text with ANSI escape codes.

    Args:
        text: Text to colorize.
        color: Foreground color name.
        background: Background color name.
        styles: One style name or an iterable of style names.
        enabled: Force on/off coloring. If None, auto-detect from stream and NO_COLOR.
        stream: Stream used for auto color detection.
    """

    if not _should_use_color(enabled, stream):
        return text

    if styles is None:
        style_names: list[str] = []
    elif isinstance(styles, str):
        style_names = [styles]
    else:
        style_names = list(styles)

    style_code = "".join(_resolve_code(s, _STYLES, "style") for s in style_names)
    color_code = _resolve_code(color, _TEXT_COLORS, "color")
    background_code = _resolve_code(background, _BACKGROUND_COLORS, "background")
    prefix = f"{style_code}{color_code}{background_code}"

    if not prefix:
        return text
    return f"{prefix}{text}{RESET}"


def cprint(
    message: object,
    *,
    color: str | None = "default",
    background: str | None = None,
    styles: str | Iterable[str] | None = None,
    file=None,
    end: str = "\n",
    flush: bool = False,
    enabled: bool | None = None,
) -> None:
    """Print a message using colors/styles."""

    stream = file if file is not None else sys.stdout
    text = colorize(
        str(message),
        color=color,
        background=background,
        styles=styles,
        enabled=enabled,
        stream=stream,
    )
    print(text, file=stream, end=end, flush=flush)


def cinput(
    prompt_message: str,
    *,
    color: str | None = "cyan",
    background: str | None = None,
    styles: str | Iterable[str] | None = "bold",
    enabled: bool | None = None,
) -> str:
    """Prompt for input with a colored prompt string."""

    prompt_text = colorize(
        prompt_message,
        color=color,
        background=background,
        styles=styles,
        enabled=enabled,
        stream=sys.stdout,
    )
    return input(prompt_text)


def prompt(
    message: str,
    *,
    color: str | None = "cyan",
    background: str | None = None,
    styles: str | Iterable[str] | None = "bold",
    enabled: bool | None = None,
) -> str:
    """Alias of cinput for an intuitive API."""

    return cinput(
        message,
        color=color,
        background=background,
        styles=styles,
        enabled=enabled,
    )
