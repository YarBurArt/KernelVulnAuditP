# KernelVulnAuditP

This is a lightweight, Python-based utility that analyzes Linux systems by reading uname and /proc to accurately determine the running kernel version and configuration details.

The tool automatically queries vulnerability databases, such as CISA KEV, CVE Details and cve.org, scrapes and parses CVE entries, and correlates findings to the exact kernel release.

Results are filtered to highlight kernel-related CVEs and prioritize those with known exploits or public disclosures.

The tool performs automated checks to verify the presence of public exploit code or proof-of-concept repositories, aggregates relevant links, and maps vulnerabilities to their CWE classifications.

The output includes a comprehensive, machine-readable JSON report and a user-friendly HTML report with direct links to advisories, exploit sources, CVE pages, and CWE references, making it easy for administrators to assess real risk and plan remediation.

# Installation

## Nix

The `flake.nix` bundles the app plus all recon tools and the QEMU sandbox. But the app uses the QEMU `microvm` scenario only.

```bash
nix run .#gui            # Textual TUI
nix run .#cli            # CLI minimal quick-start menu
nix run .#report         # report (web/Streamlit if available, else CLI)
nix build .#default      # installable package (kishirika-cli/-gui/-report)
```

The flake is pinned via `flake.lock` for reproducibility.

## or by uv + install_tools.sh

```bash
git clone https://github.com/YarBurArt/KernelVulnAuditP.git
```
```bash
cd ./KernelVulnAuditP
```

install temporary dependencies (only for the non-Nix path; the Nix package
already bundles lynis/LES/linpeas and the QEMU sandbox tools)
```bash
chmod u+x ./install_tools.sh
```
```bash
./install_tools.sh
```

run the terminal UI (Textual TUI; auto back to CLI if missing)

```bash
uv run python main.py
```

force CLI with quick-start menu

```bash
uv run python main.py --cli
```

generate report (Streamlit if available, else CLI + JSON)

```bash
uv sync --extra streamlit   # optional: web report (streamlit)
uv run streamlit run report.py
```

force CLI report

```bash
uv run python report.py --cli 
```

## CLI flags

Long-running operations (local recon, threat-intel feeds, CISA KEV import, PoC execution) show a live progress bar on a terminal; output stays clean when piped.

### `main.py`

| flag | description | notes |
| --- | --- | --- |
| `--cli` / `--gui` | force CLI or the Textual TUI | TUI needs no extra deps; `--cli` with no command prints a quick-start menu on a TTY |
| `--scan`, `-s` | run local recon + threat‑intel feeds in one shot | uses uname, /proc, Lynis, LinPEAS, LES, OSV, NVD, GitHub search  with KEV filters |
| `--local`, `-l` | local recon only | uname/proc, Lynis, LinPEAS, LES, SELinux/capabilities hardening |
| `--feeds`, `-f` | threat-intel feeds only | NIST / OSV / GitHub PoC search |
| `--report`, `-r` | print a condensed vulnerability summary | pulls cached DB stats and KEV counts |
| `--exec-tests` | fetch PoCs, compile/run them in the sandbox | uses virtme-ng/QEMU microvm to isolate; respects `ALLOW_HOST_EXECUTION` |
| `--sandbox-runs`, `-b` | list sandbox runs stored in the DB | grouped per CVE |
| `--list-kev` | print CISA KEV entries already in the DB | limit 50, shows ransomware flag |
| `--settings` / `--set KEY=VALUE` | show / change config values | e.g. `--set ISOLATION_TIMEOUT_SEC=30` |
| `--verbose`, `-v` | show top items from NVD/OSV/GitHub queries | helpful while tuning kernels |
| `--save` | persist scan results to the selected DB backend | honor `--db` |
| `--db orm / memory` | pick the SQLite ORM helper or in‑memory cache | defined in `config.py` |

------

### `report` package

Report logic lives in the `report/` package (`base_report.py` for data building, `cli.py`, `streamlit_rep.py`, `diff.py`); `report.py` is kept as a thin entry shim so the commands below still work.

| flag | description | notes |
| --- | --- | --- |
| `--verbose`, `-v` | include top items from each section in CLI renderer | |
| `--save`, `-s` | export report JSON (`--output` path) before rendering | works in Streamlit or CLI |
| `--output`, `-o` | set JSON output filename (default `report_data.json`) | |
| `--load`, `-l` | render a previously saved JSON instead of live DB | skips fresh scans |
| `--cli` | force CLI output | default already when streamlit isn't installed |

### Sandbox & isolation
- `config.py` exposes `ALLOW_HOST_EXECUTION` (disable to force virtme-ng / microvm isolation), `ISOLATION_TIMEOUT_SEC`, and paths to Lynis, LinPEAS, LES outputs.
- The default micro-VM uses `virtme-ng --quiet --memory 512M` on top of QEMU `microvm` machine type; adjust in `isolate.py` if you want let less or more RAM/CPU.

## install notes
- `./install_tools.sh [OUTPUT_PATH]` clones Lynis and LES into `/tmp`, then builds a kernel-focused LinPEAS script via the PEASS builder; pass a custom script path if you don’t want `/tmp/linpeas_kernel.sh`.
- After the script runs, update the paths in `config.py` (`PATH_LINPEAS`, `LES_PATH`, `LYNIS_BINARY`, report/log paths) so scans pick up the freshly built tools.
- `uv run python main.py --scan --save --db orm` gives the most complete run (DB persistence + feeds); `--exec-tests` will trigger sandboxed PoC execution, so keep `ALLOW_HOST_EXECUTION` = `False` unless you accept host risk.
- `uv run python report.py --save --output report_data.json` writes the JSON before rendering; add `--verbose` for more lines in CLI mode.

## check this in the config

Edit the file and re-run. Full reference:

| setting | default | notes |
| --- | --- | --- |
| `DB_BACKEND` | `orm` | `orm` / `memory` (SQLite / in-memory); `orm` is recommended |
| `LOG_LEVEL` | `DEBUG` | verbosity of `logs/kernel_audit.log` |
| `CISA_KEV_URL` | CISA KEV feed URL | known-exploited-vulnerabilities JSON |
| `CISA_KEV_PATH` | `known_exploited_vulnerabilities.json` | where the KEV feed is cached |
| `CVEORG_BASE_URL` | `https://cveawg.mitre.org/api/cve/` | CVE lookup API base |
| `GITHUB_URL` / `GITHUB_API_URL` | GitHub search URLs | PoC/repo search patterns |
| `NIST_API_URL` | NVD REST API (CPE query) | CPE pinned to the running kernel |
| `NIST_CVE_DETAILS_API_URL` | NVD REST API (CVE query) | per-CVE detail lookups |
| `OSV_API_URL` | `https://api.osv.dev/v1/query` | OSV query endpoint |
| `CH_API_URL` | `https://cdn.kernel.org/.../ChangeLog-{version}` | kernel changelog mirror |
| `REQUIREMENTS_RE` / `VERSIONS_RE` | regexes | PoC README parsing heuristics |
| `LYNIS_BINARY` | `lynis` | lynis executable (or absolute path) |
| `LYNIS_REPORT_FILE` | `/tmp/lynis-report.dat` | lynis output file |
| `LYNIS_LOG_FILE` | `/tmp/lynis.log` | lynis log file |
| `LINPEAS_OUT_JSON` | `/tmp/linpeas_report.json` | LinPEAS JSON output |
| `PATH_LINPEAS` | `/tmp/linpeas_kernel.sh` | kernel-focused LinPEAS script path |
| `POCS_BASE_PATH` | `/tmp/kernauditp` | where PoCs are cloned/staged |
| `LES_PATH` | `/tmp/linux-exploit-suggester/linux-exploit-suggester.sh` | Linux Exploit Suggester script |
| `LES_REPORT_PATH` | `/tmp/les_report.txt` | LES output file |
| `ISOLATION_TIMEOUT_SEC` | `20` | per-command timeout inside the micro-VM |
| `ALLOW_HOST_EXECUTION` | `False` | `True` runs PoCs directly on the host (risky); keep `False` for virtme-ng/QEMU isolation |

Change the `/tmp/...` defaults if you store the tools elsewhere, but clean per scan.

## Docs for used libs and tools 

- httpx quickstart: https://www.python-httpx.org/
- virtme-ng manual: https://github.com/arighi/virtme-ng
- QEMU `microvm` machine type: https://www.qemu.org/docs/master/system/i386/microvm.html
- Streamlit docs: https://docs.streamlit.io/
- Lynis auditing tool: https://github.com/CISOfy/lynis
- Linux Exploit Suggester (LES): https://github.com/The-Z-Labs/linux-exploit-suggester
- LinPEAS builder (custom script options): https://deepwiki.com/peass-ng/PEASS-ng/2.3-linpeas-builder-system
- PEASS output parsers (peas2json): https://deepwiki.com/peass-ng/PEASS-ng/6-output-parsers
- Lynis report => JSON converter: https://github.com/d4t4king/lynis-report-converter
- CVE Services API (CVE Project): https://github.com/CVEProject/cve-services
- CISA KEV JSON feed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (CSV/JSON links on page)
- KernelCI docs: https://docs.kernelci.org/
- SQLAlchemy docs: https://docs.sqlalchemy.org/20/
- Python stdlib `sqlite3`: https://docs.python.org/3/library/sqlite3.html

Of course in the future there will be more integrations with various tools and APIs :)

## base architecture 
`main.py` hosts the CLI/Textual TUI and delegates to `AppServices` for local probes (uname, /proc, Lynis, LinPEAS, LES), threat‑intel pulls (NVD/OSV/GitHub), and sandboxed PoC execution. `recon/` supplies the LocalRecon/ReconFeeds helpers that actually talk to the OS and external APIs. `sqxpl.py` searches for PoCs and stages them for execution tests. `isolate/` runs commands inside virtme-ng/QEMU microvm; `config.py` carries its timeouts and host‑escape. `db/` defines the storage interface with adapters for SQLite (ORM) or in‑memory use. `gui/` is the Textual terminal UI (scan page with hardening/caps/CVE/sandbox tabs, live progress and the engine stdout console); `report/` renders everything through Streamlit or a CLI view, and can save/load JSON snapshots.

This base architecture is not the best and requires many fixes and improvements, but it is enough for a project with a limited time.

## License
- MIT License (see `LICENSE`).

## Contributing
- Open an issue with reproduction steps or desired feature.
- Keep changes lintable and small; prefer PRs that isolate one concern.
- Mention DB backend and kernel version when filing bugs about scan/report output.
