# Security Traffic Project (Python simulation)

**Option:** Security Strikes and Application Simulation.

This folder contains a **reproducible Python simulator** that models:

- steady application traffic targets,
- scheduled attack windows (types, timing, duration, intensity),
- synthetic KPIs: goodput, latency, connection rate, security events, IDS signature hits, mitigation CPU.

## Quick start

```bash
cd "Security_Traffic Project"
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python run_simulation.py
```

Outputs are written to `output/`:

- `metrics_timeseries.csv` — per-second series  
- `summary.json` — rollups by mode  
- `plots/*.png` — figures for the report  
- `TECHNICAL_REPORT.md` — generated write-up (introduction, methodology, results, analysis, mitigations, reflection)

Edit `config.yaml` to change duration, phases, attack types, and effect strengths.

## Course alignment

CyPerf commercial provides application emulation and security-strike catalogs; CyPerf Community Edition is CLI-focused and does not include full attack emulation ([CyPerf CE README](https://github.com/Keysight/cyperf/tree/main/cyperf-ce#installation-steps)). This project documents that distinction inside the generated report and uses Python for end-to-end artifacts.
