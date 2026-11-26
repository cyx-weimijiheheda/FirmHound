"""Native FirmRec backend: probe, staging, and the config wrapper."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tools.external.base import AnalysisContext
from tools.external.firmrec import runner
from tools.external.firmrec.runner import FirmrecAnalyzer


def _make_repo(root: Path) -> Path:
    repo = root / "FirmRec"
    (repo / "firmrec" / "pipeline").mkdir(parents=True)
    (repo / "firmrec" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "firmrec" / "consts.py").write_text(
        "class ConstPaths:\n    CONFIG_PATH = 'default'\n", encoding="utf-8"
    )
    (repo / "firmrec" / "pipeline" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "firmrec" / "pipeline" / "gen_cmds.py").write_text(
        "import sys\n"
        "from pathlib import Path\n"
        "from firmrec.config import gconfig\n"
        "def firmrec_main():\n"
        "    step = sys.argv[1] if len(sys.argv) > 1 else 'all'\n"
        "    if step != '4.4':\n"
        "        return\n"
        "    out = Path(gconfig.get('emu_result_dir'))\n"
        "    out.mkdir(parents=True, exist_ok=True)\n"
        "    (out / 'result.csv').write_text(\n"
        "        'firmware_id,vendor,bin_path,entry_addr,source,keyword,sink,"
        "vuln_reason,run_time\\n'\n"
        "        'fw1,acme,bin/httpd,0x40,getenv,REMOTE_ADDR,system,"
        "command injection,1.0\\n',\n"
        "        encoding='utf-8',\n"
        "    )\n",
        encoding="utf-8",
    )
    (repo / "extractor").mkdir()
    (repo / "extractor" / "extract.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (repo / "firmentry").mkdir()
    (repo / "firmentry" / "firmrec-static.jar").write_text("jar", encoding="utf-8")
    (repo / "ghidra").mkdir()
    (repo / "ghidra" / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
    (repo / ".venv-firmrec").mkdir()
    python_bin = repo / ".venv-firmrec" / "python"
    python_bin.write_text("#!/bin/sh\n", encoding="utf-8")
    python_bin.chmod(0o755)
    return repo


def _make_vuln_info(root: Path) -> Path:
    vuln_info = root / "vuln_info"
    vuln_dir = vuln_info / "acme" / "CVE-2024-0001"
    vuln_dir.mkdir(parents=True)
    (vuln_dir / "meta.json").write_text("{}", encoding="utf-8")
    (vuln_dir / "vuln.bin").write_bytes(b"firmware")
    return vuln_info


def _analyzer(root: Path, **overrides) -> FirmrecAnalyzer:
    repo = _make_repo(root)
    config = {
        "backend": "local",
        "repo_dir": str(repo),
        "python_bin": str(repo / ".venv-firmrec" / "python"),
        "ghidra_headless": str(repo / "ghidra" / "analyzeHeadless"),
        "firmrec_static_jar": str(repo / "firmentry" / "firmrec-static.jar"),
        "vuln_info_dir": str(_make_vuln_info(root)),
        "vendor": "acme",
        "pg_password": "secret",
    }
    config.update(overrides)
    analyzer = FirmrecAnalyzer(config)
    analyzer.policy.check_path = lambda _path: None  # type: ignore[method-assign]
    return analyzer


def test_probe_local_available_when_paths_and_vuln_info_exist(tmp_path: Path) -> None:
    analyzer = _analyzer(tmp_path)
    probe = analyzer.probe()

    assert probe.available is True
    assert probe.backend == "local"
    assert probe.missing == []


def test_auto_backend_falls_back_to_docker(tmp_path: Path, monkeypatch) -> None:
    analyzer = FirmrecAnalyzer(
        {
            "backend": "auto",
            "vuln_info_dir": str(_make_vuln_info(tmp_path)),
        }
    )
    monkeypatch.setattr(runner, "docker_available", lambda: (True, "ok"))
    monkeypatch.setattr(runner, "docker_image_exists", lambda _image: True)
    analyzer.policy.check_path = lambda _path: None  # type: ignore[method-assign]

    assert analyzer._resolve_backend() == "docker"
    probe = analyzer.probe()
    assert probe.available is True
    assert probe.backend == "docker"


def test_auto_prefers_docker_over_complete_native_stack(tmp_path: Path, monkeypatch) -> None:
    analyzer = _analyzer(tmp_path, backend="auto")
    monkeypatch.setattr(runner, "docker_available", lambda: (True, "ok"))
    monkeypatch.setattr(runner, "docker_image_exists", lambda _image: True)
    assert analyzer._resolve_backend() == "docker"


def test_doctor_docker_does_not_require_host_stack(tmp_path: Path, monkeypatch) -> None:
    from tools.external.firmrec import doctor

    monkeypatch.setattr(runner, "docker_available", lambda: (True, "ok"))
    monkeypatch.setattr(runner, "docker_image_exists", lambda _image: True)
    monkeypatch.setattr(doctor.shutil, "which", lambda _name: None)
    report = doctor.check_stack(
        {"backend": "docker", "vuln_info_dir": str(_make_vuln_info(tmp_path))}
    )
    assert report["status"] == "ok"
    assert report["backend"] == "docker"
    assert report["missing"] == []
    assert report["commands"] == {}
    assert "image:" in doctor.format_report(report)


def test_doctor_docker_reports_missing_image_without_native_requirements(monkeypatch) -> None:
    from tools.external.firmrec import doctor

    monkeypatch.setattr(runner, "docker_available", lambda: (True, "ok"))
    monkeypatch.setattr(runner, "docker_image_exists", lambda _image: False)
    report = doctor.check_stack({"backend": "docker"})
    assert report["status"] == "missing"
    assert report["missing"] == ["image:firmhound/firmrec:local"]


def test_prepare_stages_raw_image_and_upstream_experiment(tmp_path: Path) -> None:
    analyzer = _analyzer(tmp_path)
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    firmware = tmp_path / "router.bin"
    firmware.write_bytes(b"firmware")
    workdir = tmp_path / "work"
    ctx = AnalysisContext(
        run_id="run-1",
        rootfs_dir=rootfs,
        workdir=workdir,
        firmware_path=firmware,
        config={},
    )

    inout = analyzer.prepare(ctx)

    assert (inout / "firmware" / "images" / "acme" / "router-bin").is_file()
    experiment = json.loads((inout / "experiment.json").read_text(encoding="utf-8"))
    assert experiment["name"] == "run-1"
    assert experiment["images"] == ["acme/router-bin"]
    assert experiment["vulns"] == ["acme/CVE-2024-0001"]
    assert (workdir / "config.local.json").is_file()
    assert (workdir / "config.local.yaml").is_file()
    payload = json.loads((workdir / "config.local.json").read_text(encoding="utf-8"))
    assert payload["repo_dir"] == str(analyzer.repo_dir)
    assert payload["gconfig"]["firmware_dir"].endswith("inout/firmware")
    assert payload["upstream_config_path"].endswith("config.local.yaml")
    # Secrets-bearing config must not be world-readable.
    assert (workdir / "config.local.json").stat().st_mode & 0o777 == 0o600
    assert analyzer._database_name("run-1") == "firmrec_run-1"


def test_prepare_rootfs_tar_fallback_records_limitation(tmp_path: Path) -> None:
    analyzer = _analyzer(tmp_path)
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "bin" / "httpd").write_text("x", encoding="utf-8")
    workdir = tmp_path / "work"
    ctx = AnalysisContext(run_id="run-2", rootfs_dir=rootfs, workdir=workdir, config={})

    inout = analyzer.prepare(ctx)

    images = list((inout / "firmware" / "images" / "acme").iterdir())
    assert len(images) == 1
    assert images[0].suffix == ""  # deliberately no dot; upstream requires safe names
    assert any("packed rootfs" in item for item in analyzer._prepare_limitations)


def test_native_wrapper_injects_config_before_upstream_imports(tmp_path: Path) -> None:
    repo = tmp_path / "fake-repo"
    (repo / "firmrec" / "pipeline").mkdir(parents=True)
    (repo / "firmrec" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "firmrec" / "config.py").write_text(
        "raise RuntimeError('real config must not be imported')\n", encoding="utf-8"
    )
    (repo / "firmrec" / "consts.py").write_text(
        "from firmrec.config import gconfig\n"
        "class ConstPaths:\n"
        "    CONFIG_PATH = 'default'\n"
        "    FIRMWARE_DIR = gconfig.get('firmware_dir')\n",
        encoding="utf-8",
    )
    (repo / "firmrec" / "pipeline" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "firmrec" / "pipeline" / "gen_cmds.py").write_text(
        "import sys\n"
        "import firmrec.consts as consts\n"
        "def firmrec_main():\n"
        "    print('ARGV=' + '|'.join(sys.argv[1:]))\n"
        "    print('CONFIG=' + consts.ConstPaths.CONFIG_PATH)\n"
        "    print('FIRMWARE=' + str(consts.ConstPaths.FIRMWARE_DIR))\n",
        encoding="utf-8",
    )
    payload = {
        "repo_dir": str(repo),
        "gconfig": {"firmware_dir": str(tmp_path / "inout" / "firmware")},
        "upstream_config_path": str(tmp_path / "config.local.yaml"),
    }
    payload_path = tmp_path / "payload.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    wrapper = Path(runner.__file__).with_name("native_wrapper.py")

    proc = subprocess.run(
        [sys.executable, str(wrapper), str(payload_path), "all"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    assert "ARGV=all" in proc.stdout
    assert f"CONFIG={tmp_path / 'config.local.yaml'}" in proc.stdout
    assert f"FIRMWARE={tmp_path / 'inout' / 'firmware'}" in proc.stdout


def test_local_execute_runs_wrapper_and_parses_result_csv(tmp_path: Path) -> None:
    analyzer = _analyzer(tmp_path, python_bin=sys.executable)
    rootfs = tmp_path / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "bin" / "httpd").write_bytes(b"\x7fELF")
    firmware = tmp_path / "router.bin"
    firmware.write_bytes(b"firmware")
    ctx = AnalysisContext(
        run_id="run-exec",
        rootfs_dir=rootfs,
        workdir=tmp_path / "work",
        firmware_path=firmware,
        config={},
    )

    result = analyzer.execute(ctx)

    assert result.status == "ok", result.limitation
    assert result.findings
    finding = result.findings[0]
    assert finding["tool"] == "firmrec"
    assert finding["binary_id"] == "bin/httpd"
    assert finding["matched_cve"] == "CVE-2024-0001"
    assert (tmp_path / "work" / "inout" / "emu_results" / "result.csv").is_file()
