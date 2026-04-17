from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Phase:
    id: str
    start_sec: float
    end_sec: float
    label: str
    mode: str
    attack_type: str | None
    intensity: float


def parse_phases(cfg: dict[str, Any]) -> list[Phase]:
    rows = cfg.get("phases")
    if not isinstance(rows, list):
        raise ValueError("config.phases must be a list")
    out: list[Phase] = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"phases[{i}] must be a mapping")
        pid = str(row["id"])
        start = float(row["start_sec"])
        end = float(row["end_sec"])
        if end <= start:
            raise ValueError(f"Phase {pid}: end_sec must be > start_sec")
        atk = row.get("attack_type")
        default_intensity = 1.0 if atk else 0.0
        out.append(
            Phase(
                id=pid,
                start_sec=start,
                end_sec=end,
                label=str(row.get("label", pid)),
                mode=str(row["mode"]),
                attack_type=atk,
                intensity=float(row.get("intensity", default_intensity)),
            )
        )
    out.sort(key=lambda p: p.start_sec)
    return out


def resolve_mode_at_time(t: float, phases: list[Phase]) -> Phase | None:
    """Return the phase active at time t (first match if overlapping)."""
    for p in phases:
        if p.start_sec <= t < p.end_sec:
            return p
    return None


def validate_full_coverage(phases: list[Phase], total_sec: float) -> None:
    """Ensure every integer second in [0, total_sec) falls inside at least one phase."""
    n = int(total_sec)
    for s in range(n):
        active = [p for p in phases if p.start_sec <= s < p.end_sec]
        if not active:
            raise ValueError(
                f"Schedule gap: no phase covers t={s}s. "
                "Adjust start_sec/end_sec so the timeline is fully covered."
            )


def resolve_effective_mode(t: float, phases: list[Phase]) -> tuple[str, Phase | None]:
    """
    If multiple phases overlap, prefer 'attack' over others, then recovery, then baseline.
    """
    active = [p for p in phases if p.start_sec <= t < p.end_sec]
    if not active:
        return "idle", None
    priority = {"attack": 0, "recovery": 1, "baseline": 2}

    def key(p: Phase) -> tuple[int, float]:
        return priority.get(p.mode, 9), p.start_sec

    best = sorted(active, key=key)[0]
    return best.mode, best
