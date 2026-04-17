from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class LoadedConfig:
    raw: dict[str, Any]
    path: Path


def load_yaml(path: Path | str) -> LoadedConfig:
    p = Path(path)
    with p.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict):
        raise ValueError("Config root must be a mapping")
    return LoadedConfig(raw=raw, path=p.resolve())
