import asyncio
import logging
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from application.dto import (
    FeedsReconResult,
    LesCVEItem,
    LocalReconResult,
    ReconResult,
)
from config import (
    ALLOW_HOST_EXECUTION,
    ISOLATION_TIMEOUT_SEC,
)
from core.entities import (
    CisaKevEntry,
    CveExecution,
    ExecutionReport,
    Exploit,
    HostFileCapabilities,
    HostInfo,
    HostKernelModule,
    HostProcessCapabilities,
    HostSELinuxBoolean,
    KernelLPE,
    PocExecution,
    SandboxRun,
    SandboxRunResult,
    SecurityRecommendation,
    SecurityRecommendationType,
    Vulnerability,
)
from db.db import ThreatDB
from isolate import Isolate, PoCRunner
from presentation.formatting import format_timestamp
from presentation.glyphs import unicode_glyph
from presentation.sandbox import format_sandbox_detail
from recon.local_target_recon import LocalRecon
from recon.remote_feeds_recon import ReconFeeds
from report.base_report import format_report
from sqxpl import GitHubExploitSearcher, PocInfo

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
        self.poc_runner = PoCRunner(self.isolate)

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

        bar.detail(label="lynis", note="checking sysctl hardening")
        lynis_result = await lynis_task
        bar.step(label="lynis", note=f"{len(lynis_result)} checks")
        logger.info("Lynis scan completed: %s", len(lynis_result))

        bar.detail(label="linpeas", note="running kernel LPE scan")
        linpeas_result: KernelLPE | None = await linpeas_task
        bar.step(
            label="linpeas",
            note=f"{len(linpeas_result.cves)} CVEs"
            if linpeas_result
            else "no LPE data",
        )
        logger.info("LinPEAS scan completed")

        bar.detail(label="les", note="running exploit suggester")
        les_result: list[LesCVEItem] = await les_task
        bar.step(label="les", note=f"{len(les_result)} CVEs")
        logger.info("LES scan completed: %s", len(les_result))

        bar.detail(label="selinux/caps", note="collecting booleans & caps")
        selinux_booleans: list[HostSELinuxBoolean] = await selinux_task
        process_caps: list[HostProcessCapabilities] = await pids_task
        file_caps: list[HostFileCapabilities] = await bpath_task
        bar.step(
            label="selinux/caps",
            note=f"{len(selinux_booleans)} booleans, "
            f"{len(process_caps) + len(file_caps)} caps",
        )

        bar.detail(label="hardening", note="comparing recommendations")
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

        host = HostInfo(
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

    def run_execution_tests(self) -> ExecutionReport:
        """validate kernel CVEs by sandbox-executing PoC"""
        return asyncio.run(self._run_execution_tests_async())

    async def _run_execution_tests_async(self) -> ExecutionReport:
        """validate kernel CVEs by sandbox-executing PoC"""
        context = await self._build_execution_context()
        logger.info("execution tests started in context: %s", context)
        cve_hints = await asyncio.to_thread(self._collect_kernel_cves)
        bar = self._make_bar(len(cve_hints), "Executing PoCs")
        report_entries: list[CveExecution] = []
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
    ) -> tuple[str | None, CisaKevEntry, Vulnerability]:

        cve_id = kev_item.get("cveID")
        kev_data = CisaKevEntry(
            date_added=self._parse_kev_date(kev_item.get("dateAdded")),
            due_date=self._parse_kev_date(kev_item.get("dueDate")),
            required_action=kev_item.get("requiredAction"),
            known_ransomware=(kev_item.get("knownRansomwareCampaignUse") == "Known"),
            vendor_project=kev_item.get("vendorProject"),
            product=kev_item.get("product"),
            notes=kev_item.get("notes", ""),
        )
        vuln_data = Vulnerability(
            cve_id=cve_id or "",
            description=kev_item.get("shortDescription", ""),
            in_cisa_kev=True,
            sources=["CISA_KEV"],
        )

        return cve_id, kev_data, vuln_data

    def _save_kev_entry(
        self,
        cve_id: str,
        kev_data: CisaKevEntry,
        vuln_data: Vulnerability,
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
                vuln_data.cvss_v3_score = details.get("cvss_v3_score")
                vuln_data.cvss_v3_vector = details.get("cvss_v3_vector")
                vuln_data.severity = details.get("severity")

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
    ) -> Vulnerability:

        description = (
            hint.get("details") or hint.get("title") or metadata.get("description")
        )
        severity = hint.get("severity") or metadata.get("severity")
        raw_data = {"hint": hint, "metadata": metadata.get("raw")}

        if context:
            raw_data["context"] = context

        return Vulnerability(
            cve_id=cve_id,
            description=description,
            cvss_v3_score=metadata.get("cvss_v3_score"),
            severity=severity,
            sources=[self._normalize_source(hint.get("source", "linpeas"))],
            raw_data=raw_data,
        )

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
            "cve_id": vuln.cve_id,
            "description": vuln.description,
            "cvss_v3_score": vuln.cvss_v3_score,
            "severity": vuln.severity,
            "sources": vuln.sources,
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
    ) -> CveExecution | None:

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

        async def _record(poc: PocInfo) -> PocExecution:
            async with sem:
                return await asyncio.to_thread(
                    self._record_poc_for_cve, cve_id, poc
                )

        pocs = await asyncio.gather(*(_record(poc) for poc in downloads))

        return CveExecution(
            cve_id=entry["cve_id"],
            description=entry["description"],
            cvss_v3_score=entry["cvss_v3_score"],
            severity=entry["severity"],
            sources=entry["sources"],
            pocs=pocs,
        )

    @staticmethod
    def _cve_outcome_note(entry: CveExecution | None) -> str:
        """Short outcome line for a CVE execution step (stages panel)."""
        if entry is None:
            return "no data"
        pocs = entry.pocs
        if not pocs:
            return "no PoCs"
        crashed = 0
        ok = 0
        errors = 0
        modes: set[str] = set()
        for poc in pocs:
            sbx = poc.sandbox
            if sbx is None:
                errors += 1
                continue
            if sbx.crashed:
                crashed += 1
            if sbx.success:
                ok += 1
            if sbx.execution_mode:
                modes.add(sbx.execution_mode)
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
        return unicode_glyph(" · ", " . ").join(bits)

    def _build_execution_report(
        self,
        context: dict[str, Any],
        entries: list[CveExecution],
    ) -> ExecutionReport:

        build_date = context["build_date"]
        return ExecutionReport(
            kernel=context["kernel_version"],
            build_date=(
                format_timestamp(build_date) if build_date is not None else None
            ),
            cves_processed=len(entries),
            stats=self.db.get_statistics(),
            entries=entries,
        )

    def _register_poc(self, cve_id: str, poc: PocInfo) -> None:
        exploit_meta = Exploit(
            exploit_type="PoC",
            source="GitHub",
            url=poc.get("url"),
            verified=True,
        )

        logger.debug("record poc meta: %s", exploit_meta)
        self.db.add_exploit(cve_id, exploit_meta)

        if poc.get("url"):
            self.db.add_reference(
                cve_id, poc["url"], ref_type="EXPLOIT", source="GitHub"
            )

    @staticmethod
    def _build_poc_summary(poc: PocInfo) -> PocExecution:
        return PocExecution(
            url=poc["url"],
            language=poc.get("language") or "",
            stars=poc.get("stars") or 0,
            compile_cmd=poc.get("compile_cmd") or "",
            test_cmd=poc.get("test_cmd") or "",
        )

    def _execute_poc(
        self,
        cve_id: str,
        poc: PocInfo,
    ) -> PocExecution:
        repo: str = poc.get("local_path") or ""
        if not repo:
            return PocExecution()

        outcome = self.poc_runner.run(
            Path(repo),
            str(poc.get("compile_cmd") or ""),
            str(poc.get("test_cmd") or ""),
            on_output=lambda line: logger.debug("%s compile: %s", cve_id, line),
        )

        if outcome.sandbox is not None:
            self._store_sandbox_run(cve_id, outcome.sandbox, outcome.command or "")
            return PocExecution(sandbox=outcome.sandbox)
        if outcome.error is not None:
            return PocExecution(sandbox_error=outcome.error)
        return PocExecution()

    def _record_poc_for_cve(
        self,
        cve_id: str,
        poc: PocInfo,
    ) -> PocExecution:
        self._register_poc(cve_id, poc)
        execution = self._build_poc_summary(poc)
        outcome = self._execute_poc(cve_id, poc)
        execution.sandbox = outcome.sandbox
        execution.sandbox_error = outcome.sandbox_error

        return execution

    def _store_sandbox_run(
        self, cve_id: str, result: SandboxRunResult, command: str
    ) -> None:
        run = SandboxRun(
            sandbox_platform=result.execution_mode,
            run_timestamp=datetime.now(UTC),
            exploit_file_hash=getattr(result.logs, "binary", None) or " ",
            execution_success=result.returncode == 0,
            exit_code=result.returncode,
            crashed=result.crashed,
            stdout=result.stdout,
            stderr=result.stderr,
            stdin=command,
            open_processes=result.processes,
            open_files=result.files,
            modules=result.modules,
            kernel_info=asdict(result.kernel_info),
            resources=asdict(result.resources),
            notes=getattr(result.logs, "command", None),
        )

        logger.debug(
            "%s full sandbox POC data:\n%s",
            cve_id,
            format_sandbox_detail(asdict(run)),
            extra={"skip_console": True},
        )
        self.db.add_sandbox_run(cve_id, run)

    def save_recon_results(self, results: ExecutionReport) -> int:
        """Persist a previous execution report into the DB."""
        context = {"kernel_version": results.kernel, "build_date": results.build_date}
        saved = 0
        for entry in results.entries:
            if not entry.cve_id:
                continue
            vuln = Vulnerability(
                cve_id=entry.cve_id,
                description=entry.description,
                cvss_v3_score=entry.cvss_v3_score,
                severity=entry.severity,
                sources=entry.sources,
                raw_data={
                    "entry": asdict(entry),
                    "context": context,
                },
            )
            logger.info("saving recon results for %s", entry.cve_id)
            logger.debug("recon item for %s is: %s", entry.cve_id, vuln)
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
                raw = vuln.raw_data or {}
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
        return {**asdict(stats), "security_recommendations": asdict(rec_stats)}

    def get_security_recommendations(
        self, category: str | None = None, status: str | None = None, limit: int = 100
    ) -> list[SecurityRecommendation]:
        """Get security recommendations with optional filters."""
        logger.debug(f"getting recommendations/params for {category}")
        return self.db.get_security_recommendations(
            category=category, status=status, limit=limit
        )

    def get_cisa_kev_entries(
        self, limit: int = 100
    ) -> list[Vulnerability]:
        """Get CISA KEV entries from DB."""
        return self.db.get_cisa_kev_list(limit=limit)

    def generate_report(self):
        logger.debug("generating base report")
        data = self.run_full_recon()
        return format_report(asdict(data))


__all__ = ["AppServices"]
