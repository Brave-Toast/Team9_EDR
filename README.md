# EDR Agent

## Overview

This repository contains a modular, multi-process Endpoint Detection and Response (EDR) agent written in Python. The agent monitors system state, detects suspicious activity, and can perform configurable active responses. The codebase is intended as a prototype and educational tool; monitors are implemented as individual modules under `EDR/monitors` and run in separate processes.

## Quick summary (what's in this repo)

- `EDR/` - package containing the core agent (`edr_agent.py`), monitor base class and monitor implementations.
- `EDR/monitors/` - monitor implementations (file, process, network, ssh, juice_shop, xss_sql, etc.).
- `EDR/offensive scripts/` - small test scripts used to validate detections (Juice Shop helpers, brute force, SQLi, port scanner, etc.).
- `tests/` - unit tests for monitors.
- `requirements.txt` - pinned runtime dependencies used for development/testing.
- `config.json` - example agent configuration used by the agent at startup.

## Requirements

- Python 3.8+ recommended.
- Install runtime dependencies:

```powershell
python -m pip install -r requirements.txt
```

Notes:
- Some monitors and scripts have optional dependencies:
	- `scapy` (used by `network_monitor`) — required for packet sniffing; sniffing typically requires root/admin privileges.
	- `requests` (used by offensive scripts and some monitors) — optional for the repository itself but required to run those example scripts.
- If you only want to run the agent (not the offensive scripts), installing the main `requirements.txt` should be sufficient for most functionality.

## Running the agent

From the repository root you can start the agent module. Example (PowerShell):

```powershell
python -m EDR.edr_agent
```

This will load `config.json`, start configured monitors (each in its own process), and begin processing the central log queue and threat bus.

Important:
- `network_monitor` requires `scapy` and usually elevated privileges to sniff packets.
- IP blocking uses `ufw` on Linux or `netsh` on Windows — ensure your environment supports these if you enable blocking.

## Monitors (current list)

The repository provides several monitors out of the box. Each monitor implements `get_name()` and `run()` (and optional `start()`/`stop()` hooks):

- File monitor (`file_monitor.py`) — watches files for changes and suspicious content.
- Juice Shop monitor (`juice_shop_monitor.py`) — parses Juice Shop logs for web attack indicators.
- Network monitor (`network_monitor.py`) — passive/active network analysis (requires `scapy`).
- Process monitor (`process_monitor.py`) — watches running processes for suspicious behavior.
- SSH monitor (`ssh_monitor.py`) — inspects SSH logs for brute-force activity.
- XSS/SQL monitor (`xss_sql_monitor.py`) — looks for web attack patterns in logs.

Each monitor is configurable via the `monitoring` section of `config.json` (see the file for supported options).

## Offensive / test scripts

The `EDR/offensive scripts/` folder contains small scripts used for testing detection:

- `brute_force_script.py` — brute-force attempts against a Juice Shop login endpoint (not SSH).
- `sql_injection.py` — attempts simple SQL injection payloads against Juice Shop login.
- `port_scanner.py` — basic TCP port scanner used for testing port-scan detection.

These scripts are educational — run them only in test environments you control.

Note: the offensive scripts use `requests`. If your editor (Pylance) reports missing imports for `requests`, install it into the interpreter used by your editor or run `pip install requests` in the environment you use.

## Tests

Unit tests are located in `tests/`. Run them with pytest from the repository root:

```powershell
python -m pytest -q
```

## Development notes

- The `BaseMonitor.run_wrapper()` method uses specific exception handlers to avoid overly broad exception catches and includes a traceback in structured alerts when a monitor crashes. If you add a new monitor, follow the same pattern for error handling.
- When adding new monitors place them in `EDR/monitors/` and ensure `get_name()` returns the key used in `config.json`.
- For optional native or environment-dependent features (packet sniffing, firewall changes), the code performs runtime availability checks and will log errors rather than crash if the dependency is missing.

## Security / Legal

The offensive scripts are included for testing and educational use only. Do not run them against systems you do not own or have explicit permission to test.

## Contact / Contributing

Open issues and PRs are welcome. Please include tests for new monitors and keep changes focused and minimal.

---
