#!/usr/bin/env python3
"""
Run the Security Traffic Python simulation: CSV, JSON summary, Markdown report.

  python run_simulation.py
  python run_simulation.py --config config.yaml --seed ###
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from security_traffic.load_config import load_yaml
from security_traffic.metrics_engine import run_simulation, write_csv, write_summary
from security_traffic.plotting import plot_timeseries
from security_traffic.report_builder import build_report_md


def main() -> int:
    parser = argparse.ArgumentParser(description="Security Strikes + app traffic (Python simulation).")
    parser.add_argument("--config", type=Path, default=ROOT / "config.yaml", help="Path to YAML config.")
    parser.add_argument("--seed", type=int, default=None, help="Override RNG seed (default: config simulation.seed).")
    args = parser.parse_args()

    loaded = load_yaml(args.config)
    cfg = loaded.raw
    seed = int(args.seed if args.seed is not None else cfg.get("simulation", {}).get("seed", 42))
    rng = np.random.default_rng(seed)

    out = cfg.get("output", {})
    out_dir = ROOT / str(out.get("directory", "output"))
    csv_name = str(out.get("csv_filename", "metrics_timeseries.csv"))
    summary_name = str(out.get("summary_filename", "summary.json"))
    report_name = str(out.get("report_filename", "TECHNICAL_REPORT.md"))

    rows, summary = run_simulation(cfg, rng)
    csv_path = out_dir / csv_name
    write_csv(rows, csv_path)
    summary_path = out_dir / summary_name
    write_summary(summary, summary_path)

    plots_dir = out_dir / "plots"
    plot_paths = plot_timeseries(rows, plots_dir)

    report_path = out_dir / report_name
    build_report_md(cfg, summary, rows, plot_paths, report_path)

    print(f"Wrote: {csv_path}")
    print(f"Wrote: {summary_path}")
    print(f"Wrote: {report_path}")
    for p in plot_paths:
        print(f"Wrote: {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
