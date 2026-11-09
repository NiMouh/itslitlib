"""itslitlib: lightweight colored terminal prompts for Python."""

from .prompts import (
    available_backgrounds,
    available_colors,
    available_styles,
    cinput,
    colorize,
    cprint,
    prompt,
)

__all__ = [
    "available_backgrounds",
    "available_colors",
    "available_styles",
    "cinput",
    "colorize",
    "cprint",
    "prompt",
]

__version__ = "0.1.2"
