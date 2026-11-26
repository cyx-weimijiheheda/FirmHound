"""开发任务脚本（Linux）。日常用 `make` 调用，也可以直接跑本文件。

Usage:
    .venv/bin/python scripts/dev.py <command>

Commands:
    help          Show this help message
    venv          Create the project .venv if missing
    install       Install production dependencies
    dev           Install package in editable mode with dev dependencies
    test          Run deterministic unit tests
    test-all      Run unit + optional host integration tests
    integration   Run host integration tests only
    ext-smoke     Probe all four optional external analyzers
    firmrec-doctor Probe the FirmRec native/Docker backend
    firmrec-venv  Create the optional FirmRec Python 3.9 environment
    firmrec-deps  Install optional FirmRec Python dependencies
    firmrec-smoke Run FirmRec against an existing run directory
    lint          Run ruff check
    format        Run ruff format
    clean         Remove build artifacts and caches
    smoke         Run end-to-end smoke test with fixture firmware

解释器优先用项目内的 .venv；没有 .venv 时退回当前 python，并在装依赖时报错提示先建环境。
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
VENV_PYTHON = REPO_ROOT / ".venv" / "bin" / "python"
PYTHON = str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable


def _in_venv() -> bool:
    return sys.prefix != sys.base_prefix


def _require_venv(action: str) -> None:
    """Refuse to install into the system interpreter or an unsupported Python."""
    if not (3, 11) <= sys.version_info[:2] <= (3, 13):
        _log(
            "unsupported_python",
            action=action,
            version=sys.version.split()[0],
            supported="3.11-3.13",
            hint="PyO3-based dependencies do not support 3.14; use "
            "`make setup PYTHON=python3.13`",
        )
        raise SystemExit(1)
    if _in_venv():
        return
    _log(
        "not_in_venv",
        action=action,
        hint="先执行 `make venv`，或用 .venv/bin/python scripts/dev.py",
    )
    raise SystemExit(1)


def _log(event: str, **fields: object) -> None:
    """One-line log to stderr; keeps this script dependency-free."""
    detail = " ".join(f"{key}={value}" for key, value in fields.items())
    print(f"[dev] {event} {detail}".rstrip(), file=sys.stderr)


def run(cmd: list[str] | str, *, cwd: Path | None = None) -> int:
    """Run a command and return its exit code."""
    _log("command_start", command=cmd)
    return subprocess.call(cmd, shell=isinstance(cmd, str), cwd=cwd)


def _ensure_local_configs() -> None:
    """Create ignored local configs from tracked ``*.example.yaml`` templates."""
    config_dir = REPO_ROOT / "config"
    for stem in ("dev", "models", "safety"):
        target = config_dir / f"{stem}.yaml"
        example = config_dir / f"{stem}.example.yaml"
        if not target.exists() and example.exists():
            shutil.copy2(example, target)
            _log("config_created", path=str(target), source=str(example))


def cmd_help(args: argparse.Namespace) -> int:
    """Show help."""
    parser.print_help()
    return 0


def cmd_venv(args: argparse.Namespace) -> int:
    """Create the project .venv when missing, after checking the Python version."""
    _ensure_local_configs()
    venv_dir = REPO_ROOT / ".venv"
    venv_python = venv_dir / "bin" / "python"
    if venv_python.exists():
        _log("venv_ready", path=str(venv_dir))
        return 0
    if not (3, 11) <= sys.version_info[:2] <= (3, 13):
        _log(
            "unsupported_python",
            action="venv",
            version=sys.version.split()[0],
            supported="3.11-3.13",
            hint="use `make dev PYTHON=python3.13`",
        )
        return 1
    rc = run([sys.executable, "-m", "venv", str(venv_dir)], cwd=REPO_ROOT)
    if rc != 0:
        _log("venv_failed", hint="install the venv module for this Python")
        return rc
    return run(
        [str(venv_python), "-m", "pip", "install", "-q", "--upgrade", "pip"],
        cwd=REPO_ROOT,
    )


def _firmrec_venv() -> tuple[Path | None, int]:
    """Create the optional FirmRec Python 3.9 environment; return (python, rc)."""
    python_bin = os.environ.get("FIRMREC_PYTHON", "python3.9")
    raw_venv = Path(os.environ.get("FIRMREC_VENV", ".venv-firmrec"))
    venv_dir = raw_venv if raw_venv.is_absolute() else REPO_ROOT / raw_venv
    venv_python = venv_dir / "bin" / "python"
    if venv_python.exists():
        return venv_python, 0
    if shutil.which(python_bin) is None:
        _log(
            "firmrec_python_missing",
            python=python_bin,
            hint="set FIRMREC_PYTHON to a Python 3.9 interpreter",
        )
        return None, 1
    rc = run([python_bin, "-m", "venv", str(venv_dir)], cwd=REPO_ROOT)
    if rc != 0:
        return None, rc
    rc = run(
        [str(venv_python), "-m", "pip", "install", "-q", "--upgrade", "pip"],
        cwd=REPO_ROOT,
    )
    return venv_python, rc


def cmd_firmrec_venv(args: argparse.Namespace) -> int:
    """Create the optional FirmRec Python environment."""
    _python, rc = _firmrec_venv()
    return rc


def cmd_firmrec_deps(args: argparse.Namespace) -> int:
    """Install the optional FirmRec Python dependencies."""
    venv_python, rc = _firmrec_venv()
    if venv_python is None:
        return rc
    return run(
        [str(venv_python), "-m", "pip", "install", "-r", "requirements-firmrec.txt"],
        cwd=REPO_ROOT,
    )


def cmd_install(args: argparse.Namespace) -> int:
    """Install production dependencies."""
    _require_venv("install")
    _ensure_local_configs()
    return run([PYTHON, "-m", "pip", "install", "-r", "requirements.txt"], cwd=REPO_ROOT)


def cmd_dev(args: argparse.Namespace) -> int:
    """Install editable package and dev dependencies."""
    _require_venv("dev")
    _ensure_local_configs()
    rc = run([PYTHON, "-m", "pip", "install", "-r", "requirements.txt"], cwd=REPO_ROOT)
    if rc != 0:
        return rc
    return run([PYTHON, "-m", "pip", "install", "-e", "."], cwd=REPO_ROOT)


def _pytest(paths: list[str]) -> int:
    """Run pytest with an explicit test scope."""
    return subprocess.call([PYTHON, "-m", "pytest", *paths], cwd=REPO_ROOT)


def cmd_test(args: argparse.Namespace) -> int:
    """Run the deterministic CI unit-test suite."""
    return _pytest(["tests/unit"])


def cmd_test_all(args: argparse.Namespace) -> int:
    """Run unit tests plus host-dependent integration tests."""
    return _pytest(["tests"])


def cmd_integration(args: argparse.Namespace) -> int:
    """Run host-dependent integration tests only."""
    return _pytest(["tests/integration"])


def cmd_ext_smoke(args: argparse.Namespace) -> int:
    """Probe optional external analyzers without requiring them to be installed."""
    from tools.external.adapter import EXTERNAL_TOOLS, _build_analyzer, _load_global_external

    external = _load_global_external()
    results: dict[str, dict[str, object]] = {}
    for tool in EXTERNAL_TOOLS:
        cfg = dict(external.get(tool, {}) or {})
        analyzer = _build_analyzer(tool, cfg)
        if analyzer is None:
            results[tool] = {
                "status": "failed",
                "available": False,
                "limitation": "adapter could not be constructed",
            }
            continue
        try:
            probe = analyzer.probe()
            results[tool] = {
                "status": "ok" if probe.available else "degraded",
                "available": probe.available,
                "version": probe.version,
                "backend": probe.backend,
                "missing": probe.missing,
                "limitation": probe.notes,
            }
        except Exception as exc:  # noqa: BLE001 - smoke must report every tool
            results[tool] = {
                "status": "failed",
                "available": False,
                "limitation": f"{type(exc).__name__}: {exc}",
            }
    overall = "ok" if all(item["status"] == "ok" for item in results.values()) else "degraded"
    _log("external_probe_complete", status=overall, tools=results)
    return 0


def cmd_firmrec_doctor(args: argparse.Namespace) -> int:
    """Probe the FirmRec backend without running the pipeline."""
    from tools.external.adapter import _load_global_external
    from tools.external.firmrec.doctor import check_stack, format_report

    external = _load_global_external()
    cfg = dict(external.get("firmrec", {}) or {})
    report = check_stack(cfg)
    print(format_report(report))
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


def cmd_firmrec_smoke(args: argparse.Namespace) -> int:
    """Run FirmRec against an existing run directory."""
    if not args.run_dir:
        _log("missing_run_dir", hint="pass --run-dir runs/<id>")
        return 1
    from tools.external.adapter import run_firmrec

    result = run_firmrec(args.run_dir)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_lint(args: argparse.Namespace) -> int:
    """Run ruff check."""
    return run(
        [PYTHON, "-m", "ruff", "check", "fsa", "tools", "scripts", "tests"],
        cwd=REPO_ROOT,
    )


def cmd_format(args: argparse.Namespace) -> int:
    """Run ruff format."""
    return run(
        [PYTHON, "-m", "ruff", "format", "fsa", "tools", "scripts", "tests"],
        cwd=REPO_ROOT,
    )


def cmd_clean(args: argparse.Namespace) -> int:
    """Remove build artifacts and caches."""
    paths = [
        REPO_ROOT / "build",
        REPO_ROOT / "dist",
        REPO_ROOT / "*.egg-info",
        REPO_ROOT / ".pytest_cache",
        REPO_ROOT / ".coverage",
        REPO_ROOT / ".ruff_cache",
    ]
    for p in paths:
        if p.is_dir():
            shutil.rmtree(p)
        elif "*" in str(p):
            for match in REPO_ROOT.glob(p.name):
                if match.is_dir():
                    shutil.rmtree(match)

    skip = {".venv", ".git", "node_modules"}
    for pycache in REPO_ROOT.rglob("__pycache__"):
        if pycache.is_dir() and not skip & set(pycache.parts):
            shutil.rmtree(pycache)
    _log("clean_complete", status="ok")
    return 0


def cmd_smoke(args: argparse.Namespace) -> int:
    """Run an end-to-end smoke test through the product CLI."""
    suffix = uuid.uuid4().hex[:8]
    rootfs = REPO_ROOT / "tmp" / f"dev-smoke-rootfs-{suffix}"
    if rootfs.exists():
        shutil.rmtree(rootfs)
    (rootfs / "www" / "cgi-bin").mkdir(parents=True, exist_ok=True)
    (rootfs / "etc" / "init.d").mkdir(parents=True, exist_ok=True)
    (rootfs / "www" / "cgi-bin" / "ping.cgi").write_text(
        '#!/bin/sh\neval "ping -c 4 $QUERY_STRING"\n',
        encoding="utf-8",
    )
    (rootfs / "etc" / "init.d" / "S50web").write_text(
        "httpd -h /www -p 80\n",
        encoding="utf-8",
    )
    return run(
        [
            PYTHON,
            "-m",
            "fsa.cli",
            "--config",
            "config/dev.yaml",
            "analyze",
            str(rootfs),
            "--input-type",
            "rootfs",
            "--depth",
            "quick",
            "--authorization-holder",
            "local-smoke-fixture",
            "--run-id",
            f"dev-smoke-{suffix}",
        ],
        cwd=REPO_ROOT,
    )


def main(argv: list[str] | None = None) -> int:
    global parser  # noqa: PLW0603
    parser = argparse.ArgumentParser(
        prog="dev.py", description="开发任务脚本（Linux；解释器优先取 .venv）"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("help", help="Show this help message")
    sub.add_parser("venv", help="Create the project .venv if missing")
    sub.add_parser("install", help="Install production dependencies")
    sub.add_parser("dev", help="Install editable package and dev dependencies")
    sub.add_parser("test", help="Run deterministic unit tests with pytest")
    sub.add_parser("test-all", help="Run unit and optional integration tests")
    sub.add_parser("integration", help="Run host integration tests")
    sub.add_parser("ext-smoke", help="Probe optional external analyzers")
    sub.add_parser("firmrec-doctor", help="Probe the FirmRec native/Docker backend")
    sub.add_parser("firmrec-venv", help="Create the optional FirmRec Python 3.9 env")
    sub.add_parser("firmrec-deps", help="Install optional FirmRec Python dependencies")
    firmrec_smoke = sub.add_parser(
        "firmrec-smoke", help="Run FirmRec against an existing run directory"
    )
    firmrec_smoke.add_argument("--run-dir", required=True, help="Pipeline run directory.")
    sub.add_parser("lint", help="Run ruff check")
    sub.add_parser("format", help="Run ruff format")
    sub.add_parser("clean", help="Remove build artifacts and caches")
    sub.add_parser("smoke", help="Run end-to-end smoke test with fixture firmware")

    args = parser.parse_args(argv)
    handlers = {
        "help": cmd_help,
        "venv": cmd_venv,
        "install": cmd_install,
        "dev": cmd_dev,
        "test": cmd_test,
        "test-all": cmd_test_all,
        "integration": cmd_integration,
        "ext-smoke": cmd_ext_smoke,
        "firmrec-doctor": cmd_firmrec_doctor,
        "firmrec-venv": cmd_firmrec_venv,
        "firmrec-deps": cmd_firmrec_deps,
        "firmrec-smoke": cmd_firmrec_smoke,
        "lint": cmd_lint,
        "format": cmd_format,
        "clean": cmd_clean,
        "smoke": cmd_smoke,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
