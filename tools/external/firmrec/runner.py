"""FirmRec adapter: recurring-vulnerability detector over firmware.

FirmRec (CCS'24, seclab-fudan/FirmRec) consumes a *firmware image* plus a
*vuln_info* signature DB and emits recurring-vulnerability detections. It is the
only external tool that **requires known-vulnerability signatures**, so this
analyzer is gated by two independent switches
(see ``skills/08-external-analyzers/firmrec/SKILL.md``):

  1. ``external.firmrec.enabled`` must be true (off by default).
  2. It is force-disabled on any *blind* run by ``tools/external/adapter`` via
     ``RECURRENCE_ONLY_TOOLS`` -- a recurrence tool must never leak ground truth
     into the benchmark.

Two execution backends are supported:

* ``local``  -- run a native upstream checkout with the operator's Python env.
* ``docker`` -- run the built ``firmhound/firmrec:local`` working image.

``backend: auto`` prefers Docker and falls back to a configured local checkout. The adapter
stages upstream's real ``inout`` contract (``images/<VENDOR>/<IMAGE>``,
``vuln_info/<VENDOR>/<NAME>/meta.json``, ``experiment.json``) and parses
``inout/emu_results/result.csv``. Missing tools or inputs always degrade to
``skipped``/``failed`` with a limitation; they never abort the pipeline.
"""

from __future__ import annotations

import os
import shlex
import time
from pathlib import Path
from typing import Any

import yaml

from fsa.safety.policy_engine import PolicyEngine, SafetyViolation
from tools.external.backends import (
    docker_available,
    docker_image_exists,
    run_docker,
    run_local,
)
from tools.external.base import AnalysisContext, ExternalAnalyzer, ProbeResult, RunOutcome
from tools.external.firmrec.parser import (
    parse_firmrec_output,
    parse_upstream_output,
)
from tools.external.firmrec.staging import (
    collect_vuln_refs,
    our_mode_ready,
    safe_name,
    stage_firmware,
    stage_upstream_vuln_info,
    write_experiment,
    write_local_config,
)

IMAGE = "firmhound/firmrec:local"
UPSTREAM_RESULT_STEP = "4.4"


def _env(name: str, fallback: str = "") -> str:
    return os.environ.get(name, fallback)


def _path_or_none(value: Any) -> Path | None:
    text = str(value or "").strip()
    if not text:
        return None
    return Path(text).expanduser()


class FirmrecAnalyzer(ExternalAnalyzer):
    """FirmRec runner with native and Docker backends."""

    name = "firmrec"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = config or {}
        self.image: str = str(cfg.get("image", IMAGE))
        self.backend: str = str(cfg.get("backend", "auto")).lower()
        if self.backend not in {"auto", "local", "docker"}:
            self.backend = "auto"
        self.repo_dir = _path_or_none(_env("FSA_FIRMREC_REPO_DIR", str(cfg.get("repo_dir", ""))))
        self.python_bin = _path_or_none(
            _env("FSA_FIRMREC_PYTHON_BIN", str(cfg.get("python_bin", "")))
        )
        self.ghidra_headless = _path_or_none(
            _env("FSA_FIRMREC_GHIDRA_HEADLESS", str(cfg.get("ghidra_headless", "")))
        )
        self.firmrec_static_jar = _path_or_none(cfg.get("firmrec_static_jar"))
        if self.firmrec_static_jar is None and self.repo_dir is not None:
            self.firmrec_static_jar = self.repo_dir / "firmentry" / "firmrec-static.jar"

        self.vuln_info_source: str = str(cfg.get("vuln_info_source", "our"))
        self.vuln_info_dir = _path_or_none(cfg.get("vuln_info_dir"))
        self.official_vuln_info_path = _path_or_none(cfg.get("official_vuln_info_path"))
        self.vuln_firmware_dir = _path_or_none(cfg.get("vuln_firmware_dir"))
        self.mode: str = str(cfg.get("mode", "signature_only"))
        self.signature_db: str = str(cfg.get("signature_db", "./benchmarks/CVEs"))
        self.timeout_s: int = int(cfg.get("timeout_s", 7200))
        self.vendor: str = str(cfg.get("vendor", "unknown"))
        self.image_name: str = str(cfg.get("image_name", ""))
        self.allow_rootfs_tar: bool = bool(cfg.get("allow_rootfs_tar", True))
        self.pg_user: str = str(cfg.get("pg_user", "root"))
        self.pg_password: str = _env(
            "FSA_FIRMREC_PG_PASSWORD", str(cfg.get("pg_password", "firmrec"))
        )
        self.pg_database: str = str(cfg.get("pg_database", ""))
        self.llm_key: str = str(cfg.get("llm_key", ""))
        self.llm_url: str = str(cfg.get("llm_url", ""))
        self.llm_model: str = str(cfg.get("llm_model", ""))
        self.policy = PolicyEngine.from_yaml()
        self._resolved_backend: str = ""
        self._prepare_limitations: list[str] = []
        self._vuln_refs: list[str] = []

    # -- backend selection -------------------------------------------------- #

    def _resolve_backend(self) -> str:
        if self._resolved_backend:
            return self._resolved_backend
        if self.backend in {"local", "docker"}:
            self._resolved_backend = self.backend
            return self._resolved_backend
        ok, _ = docker_available()
        if ok and docker_image_exists(self.image):
            self._resolved_backend = "docker"
        else:
            self._resolved_backend = "local"
        return self._resolved_backend

    def _local_missing(self) -> list[str]:
        missing: list[str] = []
        if self.repo_dir is None or not self.repo_dir.is_dir():
            missing.append("repo_dir")
        elif not (self.repo_dir / "firmrec" / "pipeline").is_dir():
            missing.append("repo_dir/does-not-contain-firmrec.pipeline")
        if self.repo_dir is not None and not (self.repo_dir / "extractor" / "extract.sh").is_file():
            missing.append("repo_dir/extractor/extract.sh")
        if not Path(__file__).with_name("native_wrapper.py").is_file():
            missing.append("native_wrapper.py")
        if self.python_bin is None or not self.python_bin.is_file():
            missing.append("python_bin")
        if self.ghidra_headless is None or not self.ghidra_headless.is_file():
            missing.append("ghidra_headless")
        if self.firmrec_static_jar is None or not self.firmrec_static_jar.is_file():
            missing.append("firmrec_static_jar")
        return missing

    def _repo_policy_error(self) -> str | None:
        if self.repo_dir is None:
            return "repo_dir is not configured"
        try:
            self.policy.check_path(self.repo_dir)
        except SafetyViolation as exc:
            return f"{exc} (place the checkout under ./vendor or add it to allowed_paths)"
        return None

    def _vuln_info_missing(self) -> list[str]:
        if self.vuln_info_dir is not None:
            if collect_vuln_refs(self.vuln_info_dir):
                return []
            return ["vuln_info_dir:no <VENDOR>/<NAME>/meta.json"]
        if self.vuln_info_source == "official":
            if self.official_vuln_info_path and collect_vuln_refs(self.official_vuln_info_path):
                return []
            return ["official_vuln_info_path"]
        if self.vuln_info_source == "our":
            if our_mode_ready(self.signature_db, self.vuln_firmware_dir):
                return []
            return ["vuln_firmware_images"]
        return [f"unsupported-vuln-info-source:{self.vuln_info_source}"]

    # -- probe -------------------------------------------------------------- #

    def probe(self) -> ProbeResult:
        """Detect a usable backend and inputs. Never raises."""
        backend = self._resolve_backend()
        if backend == "local":
            missing = self._local_missing()
            if missing:
                return ProbeResult(
                    available=False,
                    backend="local",
                    missing=missing,
                    notes=(
                        "set external.firmrec.repo_dir/python_bin/ghidra_headless, "
                        "or install the Docker image for the docker backend"
                    ),
                )
            policy_error = self._repo_policy_error()
            if policy_error:
                return ProbeResult(
                    available=False,
                    backend="local",
                    missing=["repo_dir:path_whitelist"],
                    notes=policy_error,
                )
            vuln_missing = self._vuln_info_missing()
            if vuln_missing:
                return ProbeResult(
                    available=False,
                    backend="local",
                    missing=vuln_missing,
                    notes=(
                        "upstream FirmRec needs real vulnerable firmware images; "
                        "set vuln_info_dir/official_vuln_info_path"
                    ),
                )
            return ProbeResult(
                available=True,
                version=self._local_version(),
                backend="local",
                notes=(
                    "native FirmRec checkout is ready; "
                    "PostgreSQL readiness is verified by the run"
                ),
            )

        ok, detail = docker_available()
        if not ok:
            return ProbeResult(
                available=False, backend="docker", missing=["docker-daemon"], notes=detail
            )
        if not docker_image_exists(self.image):
            return ProbeResult(
                available=False,
                backend="docker",
                missing=[f"image:{self.image}"],
                notes=f"run: docker pull {self.image}",
            )
        vuln_missing = self._vuln_info_missing()
        if vuln_missing:
            return ProbeResult(
                available=False,
                backend="docker",
                missing=vuln_missing,
                notes="upstream FirmRec needs real vulnerable firmware images",
            )
        return ProbeResult(
            available=True,
            version=self._image_version(),
            backend="docker",
            notes=detail or "docker image ready; PostgreSQL is started inside the container",
        )

    def _local_version(self) -> str:
        if self.repo_dir is None:
            return "local"
        res = run_local(
            ["git", "-C", str(self.repo_dir), "rev-parse", "--short", "HEAD"], timeout=5.0
        )
        return res.stdout.strip() if res.status == "ok" and res.stdout.strip() else "local"

    def _image_version(self) -> str:
        res = run_local(
            ["docker", "image", "inspect", self.image, "--format", "{{.Id}}"], timeout=30.0
        )
        if res.status == "ok" and res.stdout.strip():
            return res.stdout.strip()[:19]
        return "unknown"

    # -- prepare ------------------------------------------------------------ #

    def _database_name(self, run_id: str) -> str:
        if self.pg_database:
            return safe_name(self.pg_database, "firmrec")[:63]
        # Leave room for upstream's "<db_name>_vuln" suffix (PostgreSQL limit 63).
        return safe_name(f"firmrec_{run_id}", "firmrec")[:57]

    def prepare(self, ctx: AnalysisContext) -> Path:
        """Stage upstream's ``inout`` tree and the backend-specific config."""
        self._prepare_limitations = []
        inout = ctx.workdir / "inout"
        for path in (
            inout / "firmware" / "images",
            inout / "vuln_info",
            inout / "poc_info",
            inout / "emu_results",
            inout / "ghidra",
            ctx.workdir / "logs",
            ctx.workdir / "out",
        ):
            path.mkdir(parents=True, exist_ok=True)

        try:
            self.policy.check_path(ctx.workdir)
        except SafetyViolation as exc:
            raise ValueError(f"FirmRec workdir rejected by safety policy: {exc}") from exc

        staged_fw = stage_firmware(
            ctx,
            vendor=self.vendor,
            image_name=self.image_name,
            allow_rootfs_tar=self.allow_rootfs_tar,
        )
        self._prepare_limitations.extend(staged_fw.limitations)

        staged_vulns = stage_upstream_vuln_info(
            ctx.workdir,
            source=self.vuln_info_source,
            official_dir=self.official_vuln_info_path,
            vuln_info_dir=self.vuln_info_dir,
            cve_root=self.signature_db,
            vuln_firmware_dir=self.vuln_firmware_dir,
        )
        self._prepare_limitations.extend(staged_vulns.limitations)
        if not staged_vulns.vuln_refs:
            raise ValueError(
                "FirmRec has no upstream vuln_info entries: "
                + ("; ".join(staged_vulns.limitations) or "configure vuln_info_dir")
            )
        self._vuln_refs = list(staged_vulns.vuln_refs)

        write_experiment(
            ctx.workdir,
            run_id=ctx.run_id,
            vuln_refs=self._vuln_refs,
            image_ref=staged_fw.image_ref,
        )

        db_name = self._database_name(ctx.run_id)
        if self._resolve_backend() == "local":
            assert self.repo_dir is not None
            assert self.python_bin is not None
            assert self.ghidra_headless is not None
            assert self.firmrec_static_jar is not None
            write_local_config(
                ctx.workdir,
                repo_dir=self.repo_dir,
                inout=inout,
                db_name=db_name,
                db_user=self.pg_user,
                db_password=self.pg_password,
                firmrec_static_jar=self.firmrec_static_jar,
                ghidra_headless=self.ghidra_headless,
                llm_key=self.llm_key,
                llm_url=self.llm_url,
                llm_model=self.llm_model,
            )
        else:
            self._write_docker_config(ctx.workdir, db_name=db_name)

        return inout

    def _write_docker_config(self, workdir: Path, *, db_name: str) -> Path:
        payload = {
            "poc_info_dir": "/root/inout/poc_info",
            "vuln_info_dir": "/root/inout/vuln_info",
            "firmware_dir": "/root/inout/firmware",
            "firmrec_output_dir": "/root/inout",
            "project_path": "/root/inout/ghidra",
            "emu_result_dir": "/root/inout/emu_results",
            "firmrec_static_jar": "/root/firmentry/firmrec-static.jar",
            "ghidra_headless_path": "/root/ghidra/support/analyzeHeadless",
            "db_name": db_name,
            "db_user": self.pg_user,
            "db_user_passwd": self.pg_password,
            "llm_key": self.llm_key,
            "llm_url": self.llm_url,
            "llm_model": self.llm_model,
        }
        path = workdir / "config.docker.yaml"
        path.write_text(
            yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8"
        )
        path.chmod(0o600)
        return path

    # -- run ---------------------------------------------------------------- #

    def _check_command(self, command: str) -> None:
        self.policy.check_command(command)

    def _write_log(self, workdir: Path, name: str, content: str) -> None:
        (workdir / "logs" / name).write_text(content, encoding="utf-8")

    def run(self, ctx: AnalysisContext) -> RunOutcome:
        started = time.monotonic()
        backend = self._resolve_backend()
        env = {"LC_ALL": "C", "PGPASSWORD": self.pg_password}
        deadline = started + float(self.timeout_s)

        if backend == "local":
            assert self.python_bin is not None
            wrapper = Path(__file__).with_name("native_wrapper.py")
            config = ctx.workdir / "config.local.json"
            cmd = [str(self.python_bin), str(wrapper), str(config), "all"]
            self._check_command(shlex.join(cmd))
            res = run_local(
                cmd,
                cwd=self.repo_dir,
                timeout=max(1.0, deadline - time.monotonic()),
                env=env,
            )
            self._write_log(
                ctx.workdir,
                "firmrec.log",
                f"# cmd: {shlex.join(cmd)}\nstatus={res.status}\n"
                f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}\n",
            )
            limitation = ""
            if res.status == "ok":
                collect = [str(self.python_bin), str(wrapper), str(config), UPSTREAM_RESULT_STEP]
                collect_res = run_local(
                    collect,
                    cwd=self.repo_dir,
                    timeout=max(1.0, deadline - time.monotonic()),
                    env=env,
                )
                self._write_log(
                    ctx.workdir,
                    "firmrec-result.log",
                    f"# cmd: {shlex.join(collect)}\nstatus={collect_res.status}\n"
                    f"stdout:\n{collect_res.stdout}\nstderr:\n{collect_res.stderr}\n",
                )
                if collect_res.status != "ok":
                    limitation = (
                        "step 4.4 (result collection) failed; result.csv may be missing: "
                        f"{collect_res.stderr[:200]}"
                    )
        else:
            script = (
                "pg_isready || pg_ctlcluster 11 main start; "
                f"python -m firmrec.pipeline all && python -m firmrec.pipeline "
                f"{UPSTREAM_RESULT_STEP}"
            )
            self._check_command(script)
            res = run_docker(
                self.image,
                ["-lc", script],
                entrypoint="/bin/bash",
                mounts={
                    ctx.workdir / "inout": "/root/inout",
                    ctx.workdir / "config.docker.yaml": "/root/config.yaml",
                },
                env=env,
                timeout=float(self.timeout_s),
                memory="16g",
            )
            self._write_log(
                ctx.workdir,
                "firmrec.log",
                f"# cmd: {script}\nstatus={res.status}\n"
                f"stdout:\n{res.stdout}\nstderr:\n{res.stderr}\n",
            )
            limitation = ""

        duration = round(time.monotonic() - started, 1)
        if res.status == "timeout":
            return RunOutcome(
                status="timeout",
                duration_s=duration,
                limitation="firmrec pipeline timed out; check PostgreSQL and the run logs",
                outputs=[ctx.workdir / "inout"],
            )
        if res.status == "missing":
            return RunOutcome(
                status="failed",
                duration_s=duration,
                limitation=f"firmrec backend unavailable: {res.stderr or self.image}",
            )
        if res.status != "ok":
            return RunOutcome(
                status="failed",
                duration_s=duration,
                limitation=f"firmrec pipeline failed: {res.stderr[:300]}",
                outputs=[ctx.workdir / "inout"],
            )

        inout = ctx.workdir / "inout"
        result_csvs = (
            inout / "emu_results" / "result.csv",
            inout / "simexp_results" / "result.csv",
            inout / "result.csv",
        )
        if not any(path.is_file() for path in result_csvs) and not limitation:
            limitation = (
                "firmrec finished but no inout/**/result.csv was produced; " "verify step 4.4 ran"
            )
        return RunOutcome(
            status="ok",
            duration_s=duration,
            limitation=limitation,
            outputs=[ctx.workdir / "inout"],
        )

    # -- parse -------------------------------------------------------------- #

    def parse(self, ctx: AnalysisContext, outcome: RunOutcome) -> list[dict[str, Any]]:
        backend = self._resolve_backend()
        version = self._local_version() if backend == "local" else self._image_version()
        inout = ctx.workdir / "inout"
        notes = list(self._prepare_limitations)

        findings, stats = parse_upstream_output(
            inout,
            rootfs=Path(ctx.rootfs_dir),
            run_id=ctx.run_id,
            tool_version=version,
            duration_s=outcome.duration_s,
            vuln_refs=self._vuln_refs,
        )
        if not stats.files_seen and not findings:
            findings, stats = parse_firmrec_output(
                ctx.workdir / "out",
                rootfs=Path(ctx.rootfs_dir),
                run_id=ctx.run_id,
                tool_version=version,
                duration_s=outcome.duration_s,
            )
        notes.extend(stats.limitations)
        if notes:
            existing = outcome.limitation or ""
            outcome.limitation = "; ".join(
                dict.fromkeys([item for item in [existing, *notes] if item])
            )[:1000]
        return findings


def build(config: dict[str, Any] | None = None) -> FirmrecAnalyzer:
    """Factory used by ``tools/registry/external.yaml``."""
    return FirmrecAnalyzer(config)
