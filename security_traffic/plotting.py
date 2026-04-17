from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt

from security_traffic.metrics_engine import TimeSeriesRow


def plot_timeseries(rows: list[TimeSeriesRow], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    t = [r.time_sec for r in rows]
    paths: list[Path] = []

    def fig_line(ykey: str, title: str, ylabel: str, fname: str) -> None:
        fig, ax = plt.subplots(figsize=(11, 3.2))
        y = [getattr(r, ykey) for r in rows]
        ax.plot(t, y, color="#1f77b4", linewidth=1.2)
        ax.set_title(title)
        ax.set_xlabel("Time (s)")
        ax.set_ylabel(ylabel)
        ax.grid(True, alpha=0.3)
        p = out_dir / fname
        fig.tight_layout()
        fig.savefig(p, dpi=150)
        plt.close(fig)
        paths.append(p)

    fig_line("goodput_mbps", "Application goodput (simulated)", "Mbps", "goodput_mbps.png")
    fig_line("latency_ms", "Latency (simulated)", "ms", "latency_ms.png")
    fig_line("security_events_per_sec", "Security events / sec (simulated)", "events/s", "security_events.png")
    fig_line("ids_signature_hits_per_sec", "IDS signature hits / sec (simulated)", "hits/s", "ids_hits.png")
    fig_line("mitigation_cpu_percent", "Mitigation path CPU load (simulated)", "%", "mitigation_cpu.png")

    _plot_stacked_phase_background(rows, out_dir / "overview_goodput_phases.png")
    paths.append(out_dir / "overview_goodput_phases.png")
    return paths


def _plot_stacked_phase_background(rows: list[TimeSeriesRow], path: Path) -> None:
    t = [r.time_sec for r in rows]
    g = [r.goodput_mbps for r in rows]
    fig, ax = plt.subplots(figsize=(11, 4))
    ax.plot(t, g, color="#0b7285", linewidth=1.4, label="Goodput (Mbps)")

    # Shade attack windows
    in_attack = False
    start = 0.0
    for i, r in enumerate(rows):
        atk = r.mode == "attack"
        if atk and not in_attack:
            in_attack = True
            start = r.time_sec
        if not atk and in_attack:
            ax.axvspan(start, r.time_sec, color="#fa5252", alpha=0.12)
            in_attack = False
    if in_attack and rows:
        ax.axvspan(start, rows[-1].time_sec + 1, color="#fa5252", alpha=0.12)

    ax.set_title("Overview: goodput with attack windows shaded (simulated)")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Mbps")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="upper right")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
