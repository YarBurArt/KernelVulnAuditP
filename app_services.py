import asyncio
import logging
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from config import (
    ALLOW_HOST_EXECUTION,
    COMPILE_TIMEOUT_SEC,
    ISOLATION_TIMEOUT_SEC,
)
from core import (
    format_report,
    format_sandbox_detail,
    format_timestamp,
    summarize_sandbox,
)
from db.db import ThreatDB
from db.models import SecurityRecommendation
from isolate import Isolate
from isolate.isolate import _timeout_text, run_cmd
from recon.local_target_recon import LocalRecon
from recon.remote_feeds_recon import ReconFeeds
from schemas import (
    FeedsReconResult,
    HostFileCapabilities,
    HostInfoData,
    HostKernelModule,
    HostProcessCapabilities,
    HostSELinuxBoolean,
    KernelLPE,
    LesCVEItem,
    LocalReconResult,
    ReconResult,
    SecurityRecommendationType,
)
from sqxpl import GitHubExploitSearcher

logger = logging.getLogger(f"kernel_audit.{__name__}")


class _NoopProgress:
    """Stand-in bar for callers step/update/finish safely."""

    def __getattr__(self, _name: str):
        def _noop(*_a, **_k):
            return None

        return _noop


class AppServices:
    """Service layer shared by CLI and GUI flows."""

    def __init__(
        self,
        db: ThreatDB,
        progress: Callable[..., Any] | None = None,
    ):
        self.lr = LocalRecon()
        self.rf = ReconFeeds()
        self.db = db
        # an optional bar factory called with kwargs
        self.progress = progress
        self.poc_searcher = GitHubExploitSearcher()
        self.isolate = Isolate(timeout=ISOLATION_TIMEOUT_SEC)
        self.isolate.allow_host_execution = ALLOW_HOST_EXECUTION

    def _make_bar(self, total: int, label: str):
        if self.progress is None:
            return _NoopProgress()
        return self.progress(total=total, label=label)

    def store_security_recommendations(
        self, recommendations: list[SecurityRecommendationType]
    ) -> int:
        """Persist security recommendations in the DB."""
        return self.db.bulk_insert_recommendations(
            [SecurityRecommendation(**asdict(rec)) for rec in recommendations]
        )

    def run_local_recon(self, store_recs: bool = False) -> LocalReconResult:
        """Run local recon and optionally store recommendations."""
        return asyncio.run(self._run_local_recon_async(store_recs))

    async def _run_local_recon_async(
        self, store_recs: bool = False
    ) -> LocalReconResult:
        """Run local recon; the blocking scan steps run concurrently."""
        bar = self._make_bar(5, "Local recon")
        kernel: str = self.lr.get_kernel_version_simple()
        build_date: int = await asyncio.to_thread(
            self.lr.get_kernel_build_date, kernel
        )
        logger.info("Local recon started in context %s %s", kernel, build_date)

        # lynis, linpeas, les are long-running subprocess audits; the host
        # snapshot scans are independent file/table walks. Running them
        # concurrently overlaps the subprocess waits instead of serializing them
        lynis_task = asyncio.to_thread(self.lr.get_lynis_kernel_hardening_details)
        linpeas_task = asyncio.to_thread(self.lr.get_linpeas_scan_details)
        les_task = asyncio.to_thread(self.lr.get_les_scan_details)
        pids_task = asyncio.to_thread(self.lr.get_pids_caps)
        bpath_task = asyncio.to_thread(self.lr.get_bpath_caps)
        selinux_task = asyncio.to_thread(self.lr.get_host_selinux_bools)
        selinux_hard_task = asyncio.to_thread(self.lr.get_selinux_hardening)

        lynis_result = await lynis_task
        bar.step(label="lynis", note=f"{len(lynis_result)} checks")
        logger.info("Lynis scan completed: %s", len(lynis_result))
        linpeas_result: KernelLPE | None = await linpeas_task
        bar.step(
            label="linpeas",
            note=f"{len(linpeas_result.cves)} CVEs"
            if linpeas_result
            else "no LPE data",
        )
        logger.info("LinPEAS scan completed")
        les_result: list[LesCVEItem] = await les_task
        bar.step(label="les", note=f"{len(les_result)} CVEs")
        logger.info("LES scan completed: %s", len(les_result))

        selinux_booleans: list[HostSELinuxBoolean] = await selinux_task
        process_caps: list[HostProcessCapabilities] = await pids_task
        file_caps: list[HostFileCapabilities] = await bpath_task
        bar.step(
            label="selinux/caps",
            note=f"{len(selinux_booleans)} booleans, "
            f"{len(process_caps) + len(file_caps)} caps",
        )
        selinux_hardening: list[SecurityRecommendationType] = (
            await selinux_hard_task
        )
        capability_hardening: list[SecurityRecommendationType] = (
            await asyncio.to_thread(
                self.lr.get_capability_recommendations,
                process_caps,
                file_caps,
            )
        )
        bar.step(
            label="hardening",
            note=f"{len(selinux_hardening) + len(capability_hardening)} recs",
        )

        result = LocalReconResult(
            system=self.lr.environment_info.get("system", ""),
            build_date=build_date,
            security_recommendations=lynis_result,
            kernel_lpe=linpeas_result or KernelLPE(),
            kernel=kernel,
            possible_cves=les_result,
            selinux_booleans=selinux_booleans,
            process_capabilities=process_caps,
            file_capabilities=file_caps,
            selinux_hardening=selinux_hardening,
            capability_hardening=capability_hardening,
        )
        await asyncio.to_thread(
            self.save_host_recon,
            selinux_booleans,
            process_caps,
            file_caps,
            self.lr.get_loaded_kernel_modules(),
        )
        bar.finish(note="complete")
        return result

    def save_host_recon(
        self,
        selinux_booleans: list[HostSELinuxBoolean],
        process_capabilities: list[HostProcessCapabilities],
        file_capabilities: list[HostFileCapabilities],
        kernel_modules: list[str] | None = None,
    ) -> int:
        """Persist the collected host snapshot (SELinux booleans + capability
        masks + loaded kernel modules) into the DB for the report."""
        arch = self.lr.environment_info.get("architecture")
        architecture = ", ".join(arch) if isinstance(arch, (tuple, list)) else str(arch)

        host = HostInfoData(
            hostname=self.lr.environment_info.get("node", ""),
            kernel_version=self.lr.get_kernel_version_simple(),
            kernel_release=self.lr.kernel_version.get("kernel_release", ""),
            kernel_name=self.lr.kernel_version.get("kernel_name", ""),
            machine=self.lr.kernel_version.get("machine", ""),
            platform_release=self.lr.kernel_version.get("platform_release", ""),
            platform_system=self.lr.kernel_version.get("platform_system", ""),
            platform_version=self.lr.kernel_version.get("platform_version", ""),
            platform=self.lr.environment_info.get("platform", ""),
            proc_version=self.lr.kernel_version.get("proc_version", ""),
            node=self.lr.environment_info.get("node", ""),
            processor=self.lr.environment_info.get("processor", ""),
            architecture=architecture,
            distribution=self.lr.environment_info.get("distribution", ""),
            current_directory=self.lr.environment_info.get("current_directory", ""),
            username=self.lr.environment_info.get("username", ""),
            home_dir=self.lr.environment_info.get("home_dir", ""),
            selinux_booleans=selinux_booleans,
            process_capabilities=process_capabilities,
            file_capabilities=file_capabilities,
            kernel_modules=[
                HostKernelModule(module_name=name)
                for name in (kernel_modules or [])
                if name
            ],
        )
        host_id = self.db.add_host_info(host)
        logger.info(
            "host snapshot %d saved: %d booleans, %d process caps, %d file caps",
            host_id,
            len(selinux_booleans),
            len(process_capabilities),
            len(file_capabilities),
        )
        return host_id

    def run_feeds_recon(self, store_kev: bool = True) -> FeedsReconResult:
        """Fetch threat-intel feeds and optionally store CISA KEV data."""
        return asyncio.run(self._run_feeds_recon_async(store_kev))

    async def _run_feeds_recon_async(self, store_kev: bool = True) -> FeedsReconResult:
        """Fetch threat-intel feeds and optionally store CISA KEV data."""
        kernel: str = self.lr.get_kernel_version_simple()
        build_date: int = await asyncio.to_thread(
            self.lr.get_kernel_build_date, kernel
        )

        logger.debug("Search feeds for kernel %s build_date %s", kernel, build_date)
        bar = self._make_bar(4 if store_kev else 3, "Threat-intel feeds")
        try:
            if store_kev:
                stored = await self._load_and_store_kev(build_date)
                bar.step(label="KEV", note=f"{stored} stored")

            # the three feed searches are independent network calls
            nist_task = asyncio.create_task(self.rf.nist_search(kernel, build_date))
            osv_task = asyncio.create_task(self.rf.osv_search(kernel))
            github_task = asyncio.create_task(self.rf.github_search(kernel))
            findings = list(await nist_task)
            bar.step(label="NIST", note=f"{len(findings)} findings")
            findings += list(await osv_task)
            bar.step(label="OSV", note=f"{len(findings)} findings")
            pocs = list(await github_task)
            bar.step(label="GitHub", note=f"{len(pocs)} PoCs")
        finally:
            # the event loop used by this call is about to be torn down
            # (asyncio.run), so release the pooled connections now.
            await self.rf.close()

        bar.finish(note=f"{len(findings)} findings")
        return FeedsReconResult(findings=findings, pocs=pocs)

    def run_full_recon(self) -> ReconResult:
        """Run local + online recon and return combined result."""
        return asyncio.run(self._run_full_recon_async())

    async def _run_full_recon_async(self) -> ReconResult:
        """Run local + online recon concurrently and return combined result."""
        local_task = asyncio.create_task(self._run_local_recon_async())
        feeds_task = asyncio.create_task(self._run_feeds_recon_async())
        local_r = await local_task
        feeds_r = await feeds_task
        logger.info("full recon is completed, no isolated tests")
        return ReconResult(local=local_r, feeds=feeds_r)

    def run_execution_tests(self) -> dict:
        """validate kernel CVEs by sandbox-executing PoC"""
        return asyncio.run(self._run_execution_tests_async())

    async def _run_execution_tests_async(self) -> dict:
        """validate kernel CVEs by sandbox-executing PoC"""
        context = await self._build_execution_context()
        logger.info("execution tests started in context: %s", context)
        cve_hints = await asyncio.to_thread(self._collect_kernel_cves)
        bar = self._make_bar(len(cve_hints), "Executing PoCs")
        report_entries = []
        try:
            for cve_id, hint in cve_hints.items():
                bar.step(label=cve_id)
                entry = await self._process_single_cve(cve_id, hint, context)

                if entry is not None:
                    report_entries.append(entry)
                bar.detail(label=cve_id, note=self._cve_outcome_note(entry))
        finally:
            await self.rf.close()

        bar.finish(note=f"{len(report_entries)} processed")
        return self._build_execution_report(context, report_entries)

    @staticmethod
    def _parse_kev_date(value: str | None) -> datetime | None:
        if not value:
            return None

        try:
            return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError as exc:
            logger.debug("Failed to parse date '%s': %s", value, exc)
            return None

    def _build_kev_records(
        self,
        kev_item: dict[str, Any],
    ) -> tuple[str | None, dict[str, Any], dict[str, Any]]:

        cve_id = kev_item.get("cveID")
        kev_data = {
            "date_added": self._parse_kev_date(kev_item.get("dateAdded")),
            "due_date": self._parse_kev_date(kev_item.get("dueDate")),
            "required_action": kev_item.get("requiredAction"),
            "known_ransomware": (kev_item.get("knownRansomwareCampaignUse") == "Known"),
            "vendor_project": kev_item.get("vendorProject"),
            "product": kev_item.get("product"),
            "notes": kev_item.get("notes", ""),
        }
        vuln_data = {
            "cve_id": cve_id,
            "description": kev_item.get("shortDescription", ""),
            "in_cisa_kev": True,
            "sources": ["CISA_KEV"],
        }

        return cve_id, kev_data, vuln_data

    def _save_kev_entry(
        self,
        cve_id: str,
        kev_data: dict[str, Any],
        vuln_data: dict[str, Any],
    ) -> bool:
        try:
            self.db.upsert_vulnerability(vuln_data)
            self.db.add_cisa_kev(cve_id, kev_data)
            return True

        except IntegrityError:
            # a previous KEV run already persisted this row
            return False
        except (SQLAlchemyError, ValueError, KeyError, TypeError, OSError):
            logger.exception("Error storing KEV entry %s", cve_id)
            return False

    async def _load_and_store_kev(self, build_date: int | None = None) -> int:
        """load CISA KEV feed and persist in DB, returns number stored"""
        try:
            await self.rf.get_kev()
            await self.rf.load_kev(build_date)
            logger.info(
                "Loaded %s kernel-related KEV entries", len(self.rf.kev_kern_vuln)
            )
        except (httpx.HTTPError, OSError, ValueError) as e:
            logger.warning("Failed to load CISA KEV catalog: %s", e)
            return 0

        # fetch metadata for all KEV CVEs concurrently, then write to DB serially
        cve_ids = [
            str(item["cveID"])
            for item in self.rf.kev_kern_vuln
            if item.get("cveID")
        ]
        details_map = await self.rf.get_cve_details_many(cve_ids)

        stored = 0
        skipped = 0
        kev_items = self.rf.kev_kern_vuln
        bar = self._make_bar(len(kev_items), "CISA KEV")
        for idx, kev_item in enumerate(kev_items, 1):
            bar.step(label=f"KEV {idx}")
            cve_id, kev_data, vuln_data = self._build_kev_records(kev_item)

            if not cve_id:
                continue

            details = details_map.get(cve_id, {})
            if details:
                vuln_data["cvss_v3_score"] = details.get("cvss_v3_score")
                vuln_data["cvss_v3_vector"] = details.get("cvss_v3_vector")
                vuln_data["severity"] = details.get("severity")

            logger.debug("N KEV: %s | N VULN: %s", kev_data, vuln_data)

            if self._save_kev_entry(cve_id, kev_data, vuln_data):
                stored += 1
            else:
                skipped += 1

        bar.finish(note=f"{stored} stored, {skipped} skipped")
        logger.info("Stored %s CISA KEV entries, %s already existed", stored, skipped)
        return stored

    def _collect_kernel_cves(self) -> dict[str, dict[str, Any]]:
        logger.info("Collecting kernel cves by local scans")
        cves: dict[str, dict[str, Any]] = {}
        linpeas: KernelLPE | None = self.lr.get_linpeas_scan_details()
        if linpeas is None:
            logger.warning("No linpeas scans found")
            return cves
        logger.info("linpeas scan completed")
        for entry in linpeas.cves:
            if isinstance(entry, str) and entry:
                cves.setdefault(entry, {})["source"] = "linpeas"

        les_items: list[LesCVEItem] = self.lr.get_les_scan_details()
        logger.info("les scan completed")
        for entry_les in les_items:
            cve_id: str = entry_les.cve_id
            if not cve_id:
                continue
            target = cves.setdefault(cve_id, {})
            target.update(asdict(entry_les))
            target["source"] = "les"
        return cves

    @staticmethod
    def _normalize_source(source: str) -> str:
        return "LES" if source.lower() == "les" else source.upper()

    def _build_vulnerability(
        self,
        cve_id: str,
        hint: dict[str, Any],
        metadata: dict[str, Any],
        context: dict[str, Any] | None,
    ) -> dict[str, Any]:

        description = (
            hint.get("details") or hint.get("title") or metadata.get("description")
        )
        severity = hint.get("severity") or metadata.get("severity")
        raw_data = {"hint": hint, "metadata": metadata.get("raw")}

        if context:
            raw_data["context"] = context

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_v3_score": metadata.get("cvss_v3_score"),
            "severity": severity,
            "sources": [self._normalize_source(hint.get("source", "linpeas"))],
            "raw_data": raw_data,
        }

    async def _persist_cve_hint(
        self,
        cve_id: str,
        hint: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:

        metadata = await self.rf.get_cve_details(cve_id) or {}
        vuln = self._build_vulnerability(cve_id, hint, metadata, context)
        logger.debug("%s hint/refs vuln: %s", cve_id, vuln)
        self.db.upsert_vulnerability(vuln)

        if metadata.get("nist_url"):
            self.db.add_reference(
                cve_id, metadata["nist_url"], ref_type="ADVISORY", source="NIST"
            )

        return {
            "cve_id": vuln["cve_id"],
            "description": vuln["description"],
            "cvss_v3_score": vuln["cvss_v3_score"],
            "severity": vuln["severity"],
            "sources": vuln["sources"],
        }

    async def _build_execution_context(self) -> dict[str, Any]:
        kernel = self.lr.get_kernel_version_simple()
        build_date = await asyncio.to_thread(self.lr.get_kernel_build_date, kernel)
        return {
            "kernel_version": kernel,
            "build_date": build_date,
        }

    async def _process_single_cve(
        self,
        cve_id: str,
        hint: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:

        entry = await self._persist_cve_hint(
            cve_id,
            hint,
            context,
        )
        if entry is None:
            logger.warning("%s additional info hint is not saved", cve_id)
            return None

        repos = await asyncio.to_thread(
            self.poc_searcher.search_repositories,
            cve_id,
            max_results=3,
        )
        downloads = await asyncio.to_thread(GitHubExploitSearcher.load_xpls, repos)

        # PoCs run in bounded concurrency: one hanging compile (bounded by its
        # own timeout) must not serialize the whole CVE set, and several VMs at
        # once would thrash the host.
        sem = asyncio.Semaphore(2)

        async def _record(poc: dict) -> dict:
            async with sem:
                return await asyncio.to_thread(
                    self._record_poc_for_cve, cve_id, poc
                )

        pocs = await asyncio.gather(*(_record(poc) for poc in downloads))
        entry["pocs"] = pocs

        return entry

    @staticmethod
    def _cve_outcome_note(entry: dict[str, Any] | None) -> str:
        """Short outcome line for a CVE execution step (stages panel)."""
        if entry is None:
            return "no data"
        pocs = entry.get("pocs") or []
        if not pocs:
            return "no PoCs"
        crashed = 0
        ok = 0
        errors = 0
        modes: set[str] = set()
        for poc in pocs:
            sbx = poc.get("sandbox")
            if not isinstance(sbx, dict):
                errors += 1
                continue
            if sbx.get("crashed"):
                crashed += 1
            if sbx.get("success"):
                ok += 1
            mode = sbx.get("mode")
            if mode:
                modes.add(mode)
        mode = next(iter(modes), "") if len(modes) == 1 else ""
        bits = [f"{len(pocs)} PoCs"]
        if ok:
            bits.append(f"{ok} ok")
        if crashed:
            bits.append(f"{crashed} crashed")
        if errors:
            bits.append(f"{errors} errors")
        if mode:
            bits.append(mode)
        return " · ".join(bits)

    def _build_execution_report(
        self,
        context: dict[str, Any],
        entries: list[dict[str, Any]],
    ) -> dict[str, Any]:

        build_date = context["build_date"]
        return {
            "kernel": context["kernel_version"],
            "build_date": (
                format_timestamp(build_date) if build_date is not None else None
            ),
            "cves_processed": len(entries),
            "stats": self.db.get_statistics(),
            "entries": entries,
        }

    def _register_poc(self, cve_id: str, poc: dict[str, Any]) -> None:
        exploit_meta = {
            "exploit_type": "PoC",
            "source": "GitHub",
            "url": poc.get("url"),
            "verified": True,
        }

        logger.debug("record poc meta: %s", exploit_meta)
        self.db.add_exploit(cve_id, exploit_meta)

        if poc.get("url"):
            self.db.add_reference(
                cve_id, poc["url"], ref_type="EXPLOIT", source="GitHub"
            )

    @staticmethod
    def _build_poc_summary(poc: dict[str, Any]) -> dict[str, Any]:
        return {
            "url": poc.get("url"),
            "language": poc.get("language"),
            "stars": poc.get("stars"),
            "compile_cmd": poc.get("compile_cmd"),
            "test_cmd": poc.get("test_cmd"),
        }

    def _execute_poc(
        self,
        cve_id: str,
        poc: dict[str, Any],
    ) -> dict[str, Any]:
        repo: str = poc.get("local_path", "")

        if not repo:
            return {}

        repo_path = Path(repo)
        compile_cmd = poc.get("compile_cmd")
        test_cmd = poc.get("test_cmd")

        # no build or run steps -> nothing to sandbox
        if not (compile_cmd and str(compile_cmd).strip()) and not (
            test_cmd and str(test_cmd).strip()
        ):
            return {}

        # build the PoC on the host where the sources and toolchain exist;
        # the qemu initrd ships no compiler, so only the produced binary is
        # handed to the sandbox. A failing compile is a legitimate outcome.
        if compile_cmd and str(compile_cmd).strip():
            try:
                self._compile_poc(
                    repo_path,
                    str(compile_cmd),
                    on_output=lambda line: logger.debug(
                        "%s compile: %s", cve_id, line
                    ),
                )
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
                logger.warning("%s: compile failed: %s", cve_id, exc)
                return {"sandbox_error": f"compile failed: {exc}"}

        binary = self._resolve_poc_binary(repo_path, test_cmd, compile_cmd)
        if binary is None:
            return {"sandbox_error": "no executable produced by the PoC build"}

        command = str(test_cmd or f"./{binary.name}")

        try:
            logger.info("%s: %s - is started", cve_id, command)
            result = self.isolate.run_binary(binary)
            if result is None:
                return {
                    "sandbox_error": (
                        "no sandbox backend available "
                        "(virtme-ng/qemu missing and host denied)"
                    )
                }

            logger.info("%s poc - is finished", cve_id)
            self._store_sandbox_run(cve_id, result, command)

            return {
                "sandbox": summarize_sandbox(result),
            }

        except (
            OSError,
            RuntimeError,
            subprocess.TimeoutExpired,
            ValueError,
            TypeError,
            KeyError,
            FileNotFoundError,
            PermissionError,
        ) as exc:
            # A failed sandbox run is a legitimate test outcome; keep the
            # user-facing summary at WARNING and the full traceback at DEBUG
            # so genuine bugs in our runner aren't hidden by the short line.
            logger.warning("%s: %s - is failed: %s", cve_id, command, exc)
            logger.debug("sandbox failure traceback for %s", cve_id, exc_info=True)

            return {
                "sandbox_error": str(exc),
            }

    @staticmethod
    def _compile_poc(
        repo_path: Path,
        compile_cmd: str,
        timeout: int = COMPILE_TIMEOUT_SEC,
        on_output: Callable[[str], None] | None = None,
    ) -> None:
        """Run the PoC compile command inside its cloned repo directory.

        PoCs are built statically with musl-gcc: the qemu initrd is a minimal
        rootfs without glibc, and glibc-linked binaries abort there. A gcc/cc
        shim plus CC/CFLAGS force ``make``-based builds to do the same.

        The build is bounded by ``timeout`` and killed as a whole process
        tree; ``on_output`` receives each stdout/stderr line as it is produced
        so the TUI can show live compile progress instead of a silent wait.
        """
        cmd = compile_cmd
        env = os.environ.copy()
        shim_dir: Path | None = None
        musl_gcc = shutil.which("musl-gcc")

        if musl_gcc:
            # direct gcc/cc invocations -> musl-gcc -static (only these get
            # the -static flag; make/other tools must not see it as an option)
            compiler_direct = bool(re.match(r"^\s*(?:gcc|cc)\s+", cmd))
            cmd = re.sub(r"^\s*(?:gcc|cc)\s+", "musl-gcc ", cmd, count=1)
            if compiler_direct and "-static" not in cmd and not re.search(
                r"-shared\b", cmd
            ):
                cmd = f"{cmd} -static"
            # musl-gcc is a thin wrapper that execs $REALGCC (the real gcc);
            # point it at the real binary so a gcc/cc shim never recurses
            real_gcc = shutil.which("gcc")
            if real_gcc:
                env["REALGCC"] = real_gcc
            # Makefile builds call $(CC)/$(CFLAGS) or hardcode gcc; a shim
            # named gcc/cc forces every such invocation through musl-gcc -static
            # (glibc and dynamic-musl binaries abort in the minimal initrd)
            shim_dir = Path(tempfile.mkdtemp(prefix="kernaudit-cc-"))
            shim_script = f"#!/bin/sh\nexec {musl_gcc} -static \"$@\"\n"
            for name in ("gcc", "cc"):
                shim = shim_dir / name
                shim.write_text(shim_script)
                shim.chmod(0o755)
            env["PATH"] = f"{shim_dir}:{env.get('PATH', '')}"
            env["CC"] = "musl-gcc -static"
            env["CFLAGS"] = f"{env.get('CFLAGS', '')} -static".strip()

        try:
            proc = run_cmd(
                cmd,
                shell=True,
                cwd=repo_path,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                line_callback=on_output,
            )
        except subprocess.TimeoutExpired as exc:
            out_text, err_text = _timeout_text(exc)
            partial = (err_text or out_text).strip()[:400]
            raise RuntimeError(
                f"compile timed out after {timeout}s\n{partial}"
            ) from exc
        finally:
            if shim_dir is not None:
                shutil.rmtree(shim_dir, ignore_errors=True)

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()[:400]
            raise RuntimeError(f"rc={proc.returncode}: {detail}")

    @staticmethod
    def _resolve_poc_binary(
        repo_path: Path,
        test_cmd: Any,
        compile_cmd: Any,
    ) -> Path | None:
        """Find the executable the compile/test steps produced in the repo."""
        name: str | None = None

        # the runnable the test step references (./prog -> prog)
        if test_cmd:
            match = re.match(r"^\s*\./(\S+)", str(test_cmd))
            if match:
                name = match.group(1)

        # else the -o output of the compile step
        if name is None and compile_cmd:
            match = re.search(r"(?<!\S)-o\s+(\S+)", str(compile_cmd))
            if match:
                name = match.group(1).rstrip(",;")

        # bare "gcc foo.c" (no -o) produces a.out
        if (
            name is None
            and compile_cmd
            and "gcc" in str(compile_cmd)
            and re.search(r"\.c\b", str(compile_cmd))
            and not re.search(r"(?<!\S)-o\b", str(compile_cmd))
        ):
            name = "a.out"

        if name:
            candidate = (repo_path / name).resolve()
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate

        # fall back to the newest executable at the repo root (e.g. make)
        best: Path | None = None
        try:
            for f in repo_path.iterdir():
                if f.is_file() and os.access(f, os.X_OK) and (
                    best is None or f.stat().st_mtime > best.stat().st_mtime
                ):
                    best = f
        except OSError:
            return None
        return best

    def _record_poc_for_cve(
        self,
        cve_id: str,
        poc: dict[str, Any],
    ) -> dict[str, Any]:
        self._register_poc(cve_id, poc)
        summary = self._build_poc_summary(poc)
        summary.update(self._execute_poc(cve_id, poc))

        return summary

    def _store_sandbox_run(self, cve_id: str, result, command: str) -> None:
        logs = getattr(result, "logs", {}) or {}
        xpl_hash = logs.get("exploit_hash", logs.get("binary", " "))

        sandbox_data = {
            "sandbox_platform": getattr(result, "execution_mode", "unknown"),
            "run_timestamp": datetime.now(UTC),
            "exploit_file_hash": xpl_hash,
            "execution_success": getattr(result, "returncode", 1) == 0,
            "exit_code": getattr(result, "returncode", -1),
            "crashed": getattr(result, "crashed", False),
            "stdout": getattr(result, "stdout", " "),
            "stderr": getattr(result, "stderr", " "),
            "stdin": command,
            "open_processes": getattr(result, "processes", []),
            "open_files": getattr(result, "files", []),
            "modules": getattr(result, "modules", []),
            "kernel_info": getattr(result, "kernel_info", {}),
            "resources": getattr(result, "resources", {}),
            "notes": logs.get("command"),
        }

        logger.debug(
            "%s full sandbox POC data:\n%s",
            cve_id,
            format_sandbox_detail(sandbox_data),
            extra={"skip_console": True},
        )
        self.db.add_sandbox_run(cve_id, sandbox_data)

    def save_recon_results(self, results: dict) -> int:
        """Persist a previous execution report into the DB."""
        kernel = results.get("kernel")
        build_date = results.get("build_date")
        context = {"kernel_version": kernel, "build_date": build_date}
        saved = 0
        for entry in results.get("entries", []):
            cve_id = entry.get("cve_id")
            if not cve_id:
                continue
            vuln = {
                "cve_id": cve_id,
                "description": entry.get("description"),
                "cvss_v3_score": entry.get("cvss_v3_score"),
                "severity": entry.get("severity"),
                "sources": entry.get("sources", []),
                "raw_data": {
                    "entry": entry,
                    "context": context,
                },
            }
            logger.info("saving recon results for %s", cve_id)
            logger.debug("recon item for %s is: %s", cve_id, vuln)
            self.db.upsert_vulnerability(vuln)
            saved += 1
        return saved

    def get_cached_recon(self, kernel: str):
        """Return cached CVE entries tied to a kernel version."""
        results = []
        offset = 0
        chunk = 100
        while True:
            batch = self.db.search(limit=chunk, offset=offset)
            if not batch:
                logger.debug("no cached recon entries")
                break
            for vuln in batch:
                raw = vuln.get("raw_data", {})
                context = raw.get("context", {})
                if context.get("kernel_version") == kernel:
                    logger.debug("found cached recon entry: %s", vuln)
                    results.append(vuln)
            if len(batch) < chunk:
                break
            offset += chunk
        return results

    def get_statistics(self):
        """Return aggregated statistics from the DB."""
        stats = self.db.get_statistics()
        rec_stats = self.db.get_recommendations_stats()
        stats["security_recommendations"] = rec_stats
        return stats

    def get_security_recommendations(
        self, category: str | None = None, status: str | None = None, limit: int = 100
    ) -> list[dict]:
        """Get security recommendations with optional filters."""
        logger.debug(f"getting recommendations/params for {category}")
        return self.db.get_security_recommendations(
            category=category, status=status, limit=limit
        )

    def get_cisa_kev_entries(self, limit: int = 100) -> list[dict]:
        """Get CISA KEV entries from DB."""
        return self.db.get_cisa_kev_list(limit=limit)

    def generate_report(self):
        logger.debug("generating base report")
        data = self.run_full_recon()
        return format_report(asdict(data))


__all__ = ["AppServices"]
