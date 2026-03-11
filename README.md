# PortScanner

![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-pytest-orange?logo=pytest)
![Code style](https://img.shields.io/badge/code%20style-PEP8-black)

A professional, multi-threaded TCP port scanner written in Python. Features service detection via banner grabbing, a live progress bar, and multiple output formats — all with a clean, colorized terminal interface powered by [Rich](https://github.com/Textualize/rich).

---

## Features

- **Fast parallel scanning** via `ThreadPoolExecutor` (configurable thread count)
- **Banner grabbing** for service fingerprinting on open ports
- **Three scan modes**: custom port range, top-100 preset, full 1–65535 range
- **Live progress bar** with per-port open-port callouts
- **Rich terminal table** with colour-coded states (open / closed / filtered)
- **Export** results to JSON or CSV
- **Graceful error handling** for timeouts, unreachable hosts, and permission errors

---

## Installation

```bash
git clone https://github.com/youruser/portscanner.git
cd portscanner
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

---

## Usage

```
portscanner [-h] [-p PORTS | --top-100 | --full]
            [-t SECONDS] [--threads N]
            [--no-banner] [--format {json,csv}] [-o FILE]
            [--show-closed] [--no-progress] [-v]
            host
```

### Examples

```bash
# Scan default range (ports 1–1024) on a host
portscanner scanme.nmap.org

# Scan specific ports and ranges
portscanner 192.168.1.1 -p 22,80,443,8000-8080

# Use the top-100 preset with a 2-second timeout
portscanner 10.0.0.1 --top-100 -t 2

# Scan with 200 threads and export to JSON
portscanner example.com --top-100 --threads 200 -o results.json

# Full port scan, export to CSV, show all ports including closed
portscanner 192.168.1.1 --full -o scan.csv --format csv --show-closed

# Faster scan without banner grabbing
portscanner 10.0.0.1 -p 1-1024 --no-banner --threads 500
```

### CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `host` | — | Target hostname or IP address |
| `-p`, `--ports` | `1-1024` | Port spec: `80`, `1-1024`, `22,80,443` |
| `--top-100` | — | Scan the top 100 most common ports |
| `--full` | — | Scan all 65535 ports |
| `-t`, `--timeout` | `1.0` | Per-port timeout in seconds |
| `--threads` | `100` | Number of concurrent threads |
| `--no-banner` | — | Skip banner grabbing |
| `--format` | `json` | Export format: `json` or `csv` |
| `-o`, `--output` | — | Save results to file |
| `--show-closed` | — | Show closed/filtered ports in the table |
| `--no-progress` | — | Suppress the progress bar |

---

## Sample Output

```
╭─────────────────────────────── PortScanner ────────────────────────────────╮
│ Target:    scanme.nmap.org (45.33.32.156)                                   │
│ Ports:     1,024 scanned                                                    │
│ Duration:  4.31s                                                            │
│ Timestamp: 2024-01-15 14:23:01 UTC                                          │
╰────────────────────────────────────────────────────────────────────────────╯

╭────────┬────────────┬──────────────────┬────────────┬────────────────────╮
│   PORT │   STATE    │ SERVICE          │    LATENCY │ BANNER             │
├────────┼────────────┼──────────────────┼────────────┼────────────────────┤
│     22 │   OPEN     │ SSH              │     12.4ms │ SSH-2.0-OpenSSH... │
│     80 │   OPEN     │ HTTP             │      8.1ms │ —                  │
│    443 │   OPEN     │ HTTPS            │      9.7ms │ —                  │
╰────────┴────────────┴──────────────────┴────────────┴────────────────────╯

╭──────────────── Summary ────────────────╮
│   Open        3                         │
│   Closed    997                         │
│   Filtered    24                        │
│   Rate      237 ports/s                 │
╰─────────────────────────────────────────╯
```

---

## Project Structure

```
portscanner/
├── src/
│   └── scanner/
│       ├── __init__.py      # Package exports
│       ├── core.py          # Scanner engine, ScanResult, ScanSummary
│       ├── cli.py           # argparse CLI entry point
│       ├── utils.py         # Port parsing, service names, banner sanitization
│       └── reporter.py      # Rich table, JSON/CSV export
├── tests/
│   ├── test_core.py         # Core scanner tests (uses local TCP server fixture)
│   ├── test_utils.py        # Utility function unit tests
│   └── test_reporter.py     # Reporter/export unit tests
├── requirements.txt
├── setup.py
└── .gitignore
```

---

## Running Tests

```bash
# Run all tests
pytest

# With coverage report
pytest --cov=scanner --cov-report=term-missing

# Run a single test file
pytest tests/test_utils.py -v
```

---

## Legal Notice

Only scan hosts and networks you own or have **explicit written permission** to test. Unauthorized port scanning may violate computer fraud laws in your jurisdiction.

---

## License

MIT — see [LICENSE](LICENSE) for details.
