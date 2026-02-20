from __future__ import annotations

from pathlib import Path
import os


def env_flag(name: str) -> bool:
    raw = os.getenv(name, "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def env_int(name: str, fallback: int, minimum: int = 1) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return fallback
    try:
        value = int(raw, 10)
    except ValueError:
        return fallback
    if value < minimum:
        return fallback
    return value


def find_repo_root(file_path: str) -> Path:
    start = Path(file_path).resolve()
    for candidate in (start.parent, *start.parents):
        if (candidate / "Makefile").is_file() and (candidate / "VERSION").is_file():
            return candidate
    raise RuntimeError(f"could not find repo root from {file_path}")
