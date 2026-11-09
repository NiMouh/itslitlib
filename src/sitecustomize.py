"""Interpreter startup hook for itslitlib.

This module is auto-imported by Python's site initialization when present
on sys.path. It forwards to the package startup hook.
"""

from __future__ import annotations

import itslitlib._startup
