# KernelVulnAuditP

This is a lightweight, Python-based utility that analyzes Linux systems by reading uname and /proc to accurately determine the running kernel version and configuration details.

The tool automatically queries vulnerability databases, such as CISA KEV, CVE Details and cve.org, scrapes and parses CVE entries, and correlates findings to the exact kernel release.

Results are filtered to highlight kernel-related CVEs and prioritize those with known exploits or public disclosures.

The tool performs automated checks to verify the presence of public exploit code or proof-of-concept repositories, aggregates relevant links, and maps vulnerabilities to their CWE classifications.

The output includes a comprehensive, machine-readable JSON report and a user-friendly HTML report with direct links to advisories, exploit sources, CVE pages, and CWE references, making it easy for administrators to assess real risk and plan remediation.

# Installation

```bash
git clone https://github.com/YarBurArt/KernelVulnAuditP.git
```
```bash
cd ./KernelVulnAuditP
```

install temporary dependecies
```bash
chmod u+x ./install_tools.sh
```
```bash
./install_tools.sh
```

run GUI (auto back to CLI if Flet missing)

```bash
uv run python main.py
```

force CLI

```bash
uv run python main.py --cli 
```

generate report (Streamlit if available, else CLI + JSON)

```bash
uv run streamlit run report.py
```

force CLI report

```bash
uv run python report.py --cli 
```

## CLI flags

### `main.py`

| flag | description | notes |
| --- | --- | --- |
| `--cli` / `--gui` | force CLI or Flet-based GUI launcher | GUI starts only if `flet` is installed; otherwise CLI is used automatically |
| `--scan`, `-s` | run local recon + threat‑intel feeds in one shot | uses uname, /proc, Lynis, LinPEAS, LES, OSV, NVD, GitHub search  with KEV filters |
| `--report`, `-r` | print a condensed vulnerability summary | pulls cached DB stats and KEV counts |
| `--exec-tests` | fetch PoCs, compile/run them in the sandbox | uses virtme-ng/QEMU microvm to isolate; respects `ALLOW_HOST_EXECUTION` |
| `--verbose`, `-v` | show top items from NVD/OSV/GitHub queries | helpful while tuning kernels |
| `--cve 6.1.0` | seed kernel version (or CVE ID) for PoC search | default is `6.1.0`; accept any kernel string |
| `--save` | persist scan results to the selected DB backend | honor `--db` |
| `--list-kev` | print CISA KEV entries already in the DB | limit 50, shows ransomware flag |
| `--db simple / orm / memory` | pick SQLite via simple/ORM helper or in‑memory cache | default defined in `config.py` |

------

### `report.py`

| flag | description | notes |
| --- | --- | --- |
| `--verbose`, `-v` | include top items from each section in CLI renderer | |
| `--save`, `-s` | export report JSON (`--output` path) before rendering | works in Streamlit or CLI |
| `--output`, `-o` | set JSON output filename (default `report_data.json`) | |
| `--load`, `-l` | render a previously saved JSON instead of live DB | skips fresh scans |

### Sandbox & isolation
- `config.py` exposes `ALLOW_HOST_EXECUTION` (disable to force virtme-ng / microvm isolation), `ISOLATION_TIMEOUT_SEC`, and paths to Lynis, LinPEAS, LES outputs.
- The default micro-VM uses `virtme-ng --quiet --memory 512M` on top of QEMU `microvm` machine type; adjust in `isolate.py` if you want let less or more RAM/CPU.

## install notes
- `./install_tools.sh [OUTPUT_PATH]` clones Lynis and LES into `/tmp`, then builds a kernel-focused LinPEAS script via the PEASS builder; pass a custom script path if you don’t want `/tmp/linpeas_kernel.sh`.
- After the script runs, update the paths in `config.py` (`PATH_LINPEAS`, `LES_PATH`, `LYNIS_BINARY`, report/log paths) so scans pick up the freshly built tools.
- `uv run python main.py --scan --save --db orm` gives the most complete run (DB persistence + feeds); `--exec-tests` will trigger sandboxed PoC execution, so keep `ALLOW_HOST_EXECUTION` = `False` unless you accept host risk.
- `uv run python report.py --save --output report_data.json` writes the JSON before rendering; add `--verbose` for more lines in CLI mode.

## check this in the config
- Feeds & APIs: `CISA_KEV_URL`, `CVEORG_BASE_URL`, `NIST_API_URL`, `OSV_API_URL`, `CH_API_URL` (kernel changelog mirror).
- Local tool paths: `LYNIS_BINARY`, `LYNIS_REPORT_FILE`, `LYNIS_LOG_FILE`, `PATH_LINPEAS`, `LINPEAS_OUT_JSON`, `LES_PATH`, `LES_REPORT_PATH`.
- Sandbox/db: `POCS_BASE_PATH`, `DB_BACKEND` (`orm` recommended), `ISOLATION_TIMEOUT_SEC`, `ALLOW_HOST_EXECUTION` (keep `False` when using virtme-ng/QEMU).
- Change the `/tmp/...` defaults if your distro cleans tmp on reboot or if you store tools elsewhere.

All of this can be done conveniently in the Flet GUI.

## Docs for used libs and tools 

- httpx quickstart: https://www.python-httpx.org/
- virtme-ng manual: https://github.com/arighi/virtme-ng
- QEMU `microvm` machine type: https://www.qemu.org/docs/master/system/i386/microvm.html
- Flet framework docs: https://flet.dev/docs/
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
`main.py` hosts the CLI/optional Flet UI and delegates to `AppServices` for local probes (uname, /proc, Lynis, LinPEAS, LES), threat‑intel pulls (NVD/OSV/GitHub), and sandboxed PoC execution. `recon.py` supplies the LocalRecon/ReconFeeds helpers that actually talk to the OS and external APIs. `sqxpl.py` searches for PoCs and stages them for execution tests. `isolate.py` runs commands inside virtme-ng/QEMU microvm; `config.py` carries its timeouts and host‑escape. `db.py` defines the storage interface with adapters for SQLite (simple/ORM) or in‑memory use. `report.py` renders everything through Streamlit or a CLI view, and can save/load JSON snapshots.

This base architecture is not the best and requires many fixes and improvements, but it is enough for a project with a limited time.

## License
- MIT License (see `LICENSE`).

## Contributing
- Open an issue with reproduction steps or desired feature.
- Keep changes lintable and small; prefer PRs that isolate one concern.
- Mention DB backend and kernel version when filing bugs about scan/report output.
