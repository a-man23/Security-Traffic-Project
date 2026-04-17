from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

import numpy as np

from security_traffic.schedule import Phase, parse_phases, resolve_effective_mode, validate_full_coverage


@dataclass
class TimeSeriesRow:
    time_sec: float
    phase_id: str
    mode: str
    attack_type: str | None
    attack_intensity: float
    goodput_mbps: float
    latency_ms: float
    new_connections_per_sec: float
    security_events_per_sec: float
    packet_drop_rate: float
    ids_signature_hits_per_sec: float
    mitigation_cpu_percent: float


def _effects_for_mode(cfg: dict[str, Any], mode: str) -> dict[str, float]:
    e = cfg["effects"][mode]
    return {k: float(e[k]) for k in e}


def _attack_profile(cfg: dict[str, Any], attack_type: str) -> dict[str, Any]:
    profiles = cfg.get("attack_profiles", {})
    if attack_type not in profiles:
        return {}
    return profiles[attack_type]


def run_simulation(cfg: dict[str, Any], rng: np.random.Generator) -> tuple[list[TimeSeriesRow], dict[str, Any]]:
    sim = cfg["simulation"]
    dt = float(sim["time_step_seconds"])
    total = float(sim["total_duration_seconds"])
    app = cfg["application_traffic"]
    phases = parse_phases(cfg)
    validate_full_coverage(phases, total)

    jitter = float(app["jitter_fraction"])
    base_goodput = float(app["target_goodput_mbps"])
    base_lat = float(app["target_latency_ms"])
    base_cps = float(app["target_new_connections_per_sec"])

    times = np.arange(0.0, total, dt)
    rows: list[TimeSeriesRow] = []

    for t in times:
        mode_eff, phase = resolve_effective_mode(float(t), phases)
        if phase is None:
            raise RuntimeError(f"No phase defined at t={t}s; fix config coverage.")

        eff = _effects_for_mode(cfg, mode_eff)
        noise_g = 1.0 + rng.normal(0.0, jitter)
        noise_l = 1.0 + rng.normal(0.0, jitter * 1.2)
        noise_c = 1.0 + rng.normal(0.0, jitter)

        intensity = float(phase.intensity) if mode_eff == "attack" else 0.0
        blend = 1.0 - 0.15 * intensity if mode_eff == "attack" else 1.0

        goodput = max(0.0, base_goodput * eff["goodput_factor"] * noise_g * blend)
        latency = max(0.5, base_lat * eff["latency_factor"] * noise_l)
        cps = max(0.0, base_cps * eff["cps_factor"] * noise_c)

        sec_ev = max(0.0, eff["security_events_per_sec"] * (1.0 + rng.normal(0.0, 0.08)))
        if mode_eff == "attack":
            sec_ev *= 1.0 + 2.0 * intensity

        drop = max(0.0, min(0.5, eff["drop_rate"] * (1.0 + rng.normal(0.0, 0.2))))

        atk = phase.attack_type if mode_eff == "attack" else None
        prof = _attack_profile(cfg, atk or "")
        peak_hits = float(prof.get("ids_signature_hits_per_sec_peak", 0))
        sig_hits = 0.0
        mit_cpu = 12.0 + rng.normal(0.0, 1.5)
        if mode_eff == "attack" and atk:
            sig_hits = max(0.0, peak_hits * intensity * (0.85 + 0.3 * rng.random()))
            cpu_f = float(prof.get("mitigation_cpu_load_factor", 1.2))
            mit_cpu = min(98.0, 35.0 * cpu_f * (0.4 + 0.6 * intensity) + rng.normal(0.0, 4.0))

        rows.append(
            TimeSeriesRow(
                time_sec=float(t),
                phase_id=phase.id,
                mode=mode_eff,
                attack_type=atk,
                attack_intensity=intensity,
                goodput_mbps=float(goodput),
                latency_ms=float(latency),
                new_connections_per_sec=float(cps),
                security_events_per_sec=float(sec_ev),
                packet_drop_rate=float(drop),
                ids_signature_hits_per_sec=float(sig_hits),
                mitigation_cpu_percent=float(max(0.0, mit_cpu)),
            )
        )

    summary = _summarize(rows, phases, cfg)
    return rows, summary


def _summarize(rows: list[TimeSeriesRow], phases: list[Phase], cfg: dict[str, Any]) -> dict[str, Any]:
    def stats_for(pred) -> dict[str, float]:
        subset = [r for r in rows if pred(r)]
        if not subset:
            return {"count": 0}
        gps = [r.goodput_mbps for r in subset]
        lats = [r.latency_ms for r in subset]
        return {
            "count": len(subset),
            "goodput_mbps_mean": float(np.mean(gps)),
            "goodput_mbps_p95": float(np.percentile(gps, 95)),
            "latency_ms_mean": float(np.mean(lats)),
            "latency_ms_p95": float(np.percentile(lats, 95)),
            "security_events_mean": float(np.mean([r.security_events_per_sec for r in subset])),
            "ids_hits_mean": float(np.mean([r.ids_signature_hits_per_sec for r in subset])),
        }

    by_mode = {m: stats_for(lambda r, mm=m: r.mode == mm) for m in ["baseline", "attack", "recovery"]}

    attack_windows = [
        {
            "phase_id": p.id,
            "attack_type": p.attack_type,
            "start_sec": p.start_sec,
            "end_sec": p.end_sec,
            "duration_sec": p.end_sec - p.start_sec,
        }
        for p in phases
        if p.mode == "attack"
    ]

    return {
        "application_traffic": cfg["application_traffic"]["name"],
        "total_duration_sec": cfg["simulation"]["total_duration_seconds"],
        "phases": [asdict(p) for p in phases],
        "attack_windows": attack_windows,
        "stats_by_mode": by_mode,
        "overall": stats_for(lambda r: True),
    }


def write_csv(rows: list[TimeSeriesRow], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    import csv

    field_names = [f.name for f in fields(TimeSeriesRow)]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=field_names)
        w.writeheader()
        for r in rows:
            w.writerow({k: getattr(r, k) for k in field_names})


def write_summary(summary: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
