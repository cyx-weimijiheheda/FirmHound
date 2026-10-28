"""End-to-end tests for the formal ``fsa analyze`` command."""

from __future__ import annotations

import json
import shutil
import sys
import uuid
import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from fsa.cli import main
from fsa.utils.jsonio import load_json, save_json, save_yaml
from fsa.utils.runlock import RunLock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "fixtures"))
from elf_builder import write_elf64  # noqa: E402


def _test_config(tmp_path: Path, extra_paths: tuple[Path, ...] = ()) -> Path:
    repo = Path(__file__).resolve().parents[2]
    runs = tmp_path / "runs"
    temp = tmp_path / "temp"
    rootfs = tmp_path / "rootfs"
    safety_path = tmp_path / "safety.yaml"
    save_yaml(
        safety_path,
        {
            "enforce": True,
            "abort_on_violation": True,
            "allowed_paths": [str(runs), str(temp), str(rootfs), *map(str, extra_paths)],
            "blocked_paths": [],
            "command_blacklist": [],
            "network": {"allow_public": False, "allowed_hosts": ["localhost"]},
            "model": {},
        },
    )
    config_path = tmp_path / "dev.yaml"
    save_yaml(
        config_path,
        {
            "runtime": {"default": "mock"},
            "paths": {
                "runs": str(runs),
                "temp": str(temp),
                "schemas": str(repo / "schemas"),
                "models": str(repo / "config" / "models.yaml"),
            },
            "safety": {"config": str(safety_path), "enforce": True},
            "analysis": {
                "max_binaries": 50,
                "max_strings_per_binary": 100,
                "verify_top_k": 5,
            },
            "external": {"enabled": False},
        },
    )
    return config_path


def _rootfs(tmp_path: Path) -> Path:
    root = tmp_path / "rootfs"
    (root / "bin").mkdir(parents=True)
    (root / "www" / "cgi-bin").mkdir(parents=True)
    (root / "etc" / "init.d").mkdir(parents=True)
    write_elf64(
        root / "bin" / "httpd",
        imports=["system", "sprintf", "getenv"],
        defined_syms=["formexeCommand"],
        rodata_strings=["QUERY_STRING", "/cgi-bin/diagnostic.cgi"],
    )
    (root / "www" / "index.html").write_text("<html>router</html>", encoding="utf-8")
    (root / "etc" / "init.d" / "S50httpd").write_text("/bin/httpd -p 80\n", encoding="utf-8")
    return root


@pytest.mark.parametrize("depth", ["quick", "standard", "full"])
def test_cli_analyze_rootfs_reaches_done(depth: str) -> None:
    workspace = (Path("tmp") / f"cli-e2e-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        rootfs = _rootfs(workspace)
        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "analyze",
                str(rootfs),
                "--depth",
                depth,
                "--authorization-holder",
                "fixture-owner",
                "--run-id",
                "cli-e2e",
            ],
        )
        assert result.exit_code == 0, result.output
        run = workspace / "runs" / "cli-e2e"
        state = load_json(run / "state" / "run_state.json")
        assert state["status"] == "done"
        assert state["current_stage"] == "DONE"
        assert load_json(run / "artifacts" / "rootfs.json")["input_type"] == "rootfs"
        assert load_json(run / "artifacts" / "binary_summaries.json")["summaries"]
        assert load_json(run / "artifacts" / "candidates.json")["candidates"]
        assert load_json(run / "artifacts" / "verdict.json")["verdicts"]
        assert (run / "report.md").read_text(encoding="utf-8").count("\n## ") == 24
        assert "误报控制摘要" in (run / "report.md").read_text(encoding="utf-8")
        assert "自主分析轨迹" in (run / "report.md").read_text(encoding="utf-8")
        assert (run / "final_verdict.json").is_file()
        stats = load_json(run / "final_verdict.json")["stats"]
        assert "false_positive_control" in stats
        assert load_json(run / "artifacts" / "report_compliance.json")["status"] == "ok"
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_analyze_progress_flag_prints_stage_lines() -> None:
    workspace = (Path("tmp") / f"cli-progress-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        rootfs = _rootfs(workspace)
        runner = CliRunner()
        base = [
            "--config",
            str(config),
            "analyze",
            str(rootfs),
            "--depth",
            "quick",
            "--authorization-holder",
            "fixture-owner",
        ]

        noisy = runner.invoke(
            main, [*base, "--run-id", "cli-progress", "--progress"]
        )
        assert noisy.exit_code == 0, noisy.output
        assert "[2/" in noisy.output
        assert "BASELINE" in noisy.output

        quiet = runner.invoke(
            main, [*base, "--run-id", "cli-quiet", "--no-progress"]
        )
        assert quiet.exit_code == 0, quiet.output
        assert "BASELINE" not in quiet.output
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_agent_progress_shows_tokens_and_can_hide_them() -> None:
    workspace = (Path("tmp") / f"cli-agent-progress-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        rootfs = _rootfs(workspace)
        runner = CliRunner()
        base = [
            "--config",
            str(config),
            "analyze",
            str(rootfs),
            "--depth",
            "quick",
            "--authorization-holder",
            "fixture-owner",
            "--agent",
            "--progress",
            "--progress-interval",
            "0.1",
        ]

        shown = runner.invoke(main, [*base, "--run-id", "agent-progress-on"])
        assert shown.exit_code == 0, shown.output
        assert "agent step " in shown.output
        assert "tok " in shown.output
        assert "resolved " in shown.output

        hidden = runner.invoke(
            main,
            [*base, "--run-id", "agent-progress-off", "--no-agent-show-tokens"],
        )
        assert hidden.exit_code == 0, hidden.output
        assert "agent step " in hidden.output
        assert "tok " not in hidden.output
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_resume_applies_agent_display_overrides() -> None:
    workspace = (Path("tmp") / f"cli-resume-display-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        rootfs = _rootfs(workspace)
        runner = CliRunner()
        run_id = "resume-display"
        first = runner.invoke(
            main,
            [
                "--config",
                str(config),
                "analyze",
                str(rootfs),
                "--depth",
                "quick",
                "--authorization-holder",
                "fixture-owner",
                "--agent",
                "--run-id",
                run_id,
            ],
        )
        assert first.exit_code == 0, first.output

        second = runner.invoke(
            main,
            [
                "--config",
                str(config),
                "resume",
                run_id,
                "--from-stage",
                "AGENT_LOOP",
                "--no-agent-show-tokens",
                "--agent-print-model",
                "--no-progress",
                "--json-output",
            ],
        )
        assert second.exit_code == 0, second.output
        run = workspace / "runs" / run_id
        task = load_json(run / "state" / "task_card.json")
        assert task["agent"]["progress"] == {
            "every_steps": 10,
            "show_tokens": False,
            "show_model": True,
        }
        state = load_json(run / "state" / "run_state.json")
        assert state["task_card"]["agent"]["progress"]["show_model"] is True
        assert state["status"] == "done"
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_resume_treats_released_lock_as_interrupted() -> None:
    workspace = (Path("tmp") / f"cli-stale-run-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        rootfs = _rootfs(workspace)
        runner = CliRunner()
        run_id = "stale-run"
        first = runner.invoke(
            main,
            [
                "--config",
                str(config),
                "analyze",
                str(rootfs),
                "--depth",
                "quick",
                "--authorization-holder",
                "fixture-owner",
                "--agent",
                "--run-id",
                run_id,
            ],
        )
        assert first.exit_code == 0, first.output
        run = workspace / "runs" / run_id
        state = load_json(run / "state" / "run_state.json")
        state["status"] = "running"
        state["current_stage"] = "AGENT_LOOP"
        save_json(run / "state" / "run_state.json", state)

        second = runner.invoke(
            main,
            [
                "--config",
                str(config),
                "resume",
                run_id,
                "--from-stage",
                "AGENT_LOOP",
                "--no-progress",
                "--json-output",
            ],
        )
        assert second.exit_code == 0, second.output
        state = load_json(run / "state" / "run_state.json")
        assert state["status"] == "done"
        assert state["metadata"]["last_rewind"]["stale_running"] is True
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_resume_refuses_when_run_lock_is_held() -> None:
    workspace = (Path("tmp") / f"cli-locked-run-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        rootfs = _rootfs(workspace)
        runner = CliRunner()
        run_id = "locked-run"
        first = runner.invoke(
            main,
            [
                "--config",
                str(config),
                "analyze",
                str(rootfs),
                "--depth",
                "quick",
                "--authorization-holder",
                "fixture-owner",
                "--run-id",
                run_id,
            ],
        )
        assert first.exit_code == 0, first.output
        run = workspace / "runs" / run_id
        lock = RunLock(run)
        assert lock.acquire() is True
        try:
            second = runner.invoke(
                main,
                [
                    "--config",
                    str(config),
                    "resume",
                    run_id,
                    "--no-progress",
                    "--json-output",
                ],
            )
            assert second.exit_code != 0
            assert "Run is active" in second.output
        finally:
            lock.release()
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_resume_from_stage_rewinds_finished_run() -> None:
    workspace = (Path("tmp") / f"cli-rewind-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        rootfs = _rootfs(workspace)
        run_id = "cli-rewind"
        runner = CliRunner()
        first = runner.invoke(
            main,
            [
                "--config",
                str(config),
                "analyze",
                str(rootfs),
                "--depth",
                "quick",
                "--authorization-holder",
                "fixture-owner",
                "--run-id",
                run_id,
            ],
        )
        assert first.exit_code == 0, first.output
        run = workspace / "runs" / run_id
        assert load_json(run / "state" / "run_state.json")["status"] == "done"

        second = runner.invoke(
            main,
            [
                "--config",
                str(config),
                "resume",
                run_id,
                "--from-stage",
                "report",
                "--json-output",
            ],
        )
        assert second.exit_code == 0, second.output
        payload = json.loads(second.output)
        assert payload["status"] == "done"
        assert payload["rewound_from"] == "REPORT"
        assert Path(payload["backup"]).is_file()

        state = load_json(run / "state" / "run_state.json")
        assert state["status"] == "done"
        assert state["current_stage"] == "DONE"
        assert state["metadata"]["last_rewind"]["from_stage"] == "REPORT"
        assert "REPORT" in state["completed_stages"]
        assert (run / "report.md").read_text(encoding="utf-8").count("\n## ") == 24

        bad = runner.invoke(
            main,
            ["--config", str(config), "resume", run_id, "--from-stage", "NOPE"],
        )
        assert bad.exit_code != 0
        assert "Unknown stage" in bad.output
        assert load_json(run / "state" / "run_state.json")["status"] == "done"
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_status_rejects_path_traversal() -> None:
    workspace = (Path("tmp") / f"cli-status-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        result = CliRunner().invoke(
            main,
            ["--config", str(config), "status", "../outside"],
        )
        assert result.exit_code != 0
        assert "run_id" in result.output
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_plan_rejects_missing_firmware_path() -> None:
    workspace = (Path("tmp") / f"cli-plan-missing-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        missing = workspace / "rootfs" / "missing.bin"
        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "plan",
                "--firmware-path",
                str(missing),
                "--authorization-holder",
                "fixture-owner",
                "--json-output",
            ],
        )

        assert result.exit_code != 0
        assert "firmware path not found" in result.output
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_plan_exposes_blind_flag() -> None:
    workspace = (Path("tmp") / f"cli-plan-blind-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "plan",
                "--task",
                "分析固件",
                "--authorization-holder",
                "fixture-owner",
                "--blind",
                "--json-output",
            ],
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["blind"] is True
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_plan_exposes_vendor_model_version() -> None:
    workspace = (Path("tmp") / f"cli-plan-meta-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        rootfs = _rootfs(workspace)
        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "plan",
                "--firmware-path",
                str(rootfs),
                "--authorization-holder",
                "fixture-owner",
                "--vendor",
                "D-Link",
                "--model",
                "DIR-825",
                "--version",
                "v2.10",
                "--json-output",
            ],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["vendor"] == "D-Link"
        assert payload["model"] == "DIR-825"
        assert payload["version"] == "v2.10"
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_analyze_rejects_empty_authorization_holder() -> None:
    """An empty holder must not start a run; plan already gates on it."""
    workspace = (Path("tmp") / f"cli-empty-holder-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        rootfs = _rootfs(workspace)
        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "analyze",
                str(rootfs),
                "--authorization-holder",
                "  ",
                "--run-id",
                "cli-empty-holder",
            ],
        )
        assert result.exit_code != 0
        assert "authorization-holder" in result.output
        assert not (workspace / "runs" / "cli-empty-holder").exists()
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_plan_explicit_depth_wins_over_natural_language() -> None:
    """Regression: a task text saying 完整 must not override --depth standard."""
    workspace = (Path("tmp") / f"cli-plan-depth-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        firmware = workspace / "rootfs" / "router.bin"
        firmware.parent.mkdir(parents=True, exist_ok=True)
        firmware.write_bytes(b"firmware")
        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "plan",
                "--task",
                "分析厂商为Tenda、型号AC15的固件，授权测试，完整分析。",
                "--firmware-path",
                str(firmware),
                "--depth",
                "standard",
                "--authorization-holder",
                "fixture-owner",
                "--json-output",
            ],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["depth"] == "standard"
        assert "EXTERNAL_ANALYSIS" not in payload["stages"]
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_plan_from_natural_language_and_package() -> None:
    workspace = (Path("tmp") / f"cli-plan-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        package = workspace / "task.zip"
        with zipfile.ZipFile(package, "w") as zf:
            zf.writestr("firmware/router.bin", b"firmware")
            zf.writestr("README.txt", "authorized router analysis")

        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "plan",
                "--task",
                "分析厂商为Tenda、型号AC15的固件，授权测试，完整分析。",
                "--task-package",
                str(package),
                "--authorization-holder",
                "fixture-owner",
                "--json-output",
            ],
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["status"] == "ok"
        assert payload["depth"] == "full"
        assert payload["firmware_path"].replace("\\", "/").endswith("firmware/router.bin")
        assert "EXTERNAL_ANALYSIS" in payload["stages"]
        assert "firmware/router.bin" in payload["attachments"]
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_doctor_reports_readiness() -> None:
    workspace = (Path("tmp") / f"cli-doctor-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        result = CliRunner().invoke(
            main,
            ["--config", str(config), "doctor", "--json-output"],
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["status"] in {"ok", "degraded"}
        assert payload["checks"]["schemas"]["status"] == "ok"
        assert payload["checks"]["paths"]["status"] == "ok"
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_unpack_diagnose_reports_encrypted_firmware() -> None:
    workspace = (Path("tmp") / f"cli-diagnose-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        firmware = workspace / "rootfs" / "encrypted.bin"
        firmware.parent.mkdir(parents=True, exist_ok=True)
        firmware.write_bytes(b"HEAD" + b"Salted__" + b"0" * 64)
        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "unpack-diagnose",
                str(firmware),
                "--json-output",
            ],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["status"] == "blocked_needs_decryption"
        assert payload["magic_hits"]
        assert any("OpenSSL" in item for item in payload["recommendations"])
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_explain_renders_candidate_ledger() -> None:
    workspace = (Path("tmp") / f"cli-explain-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        rootfs = _rootfs(workspace)
        run_result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "analyze",
                str(rootfs),
                "--depth",
                "standard",
                "--authorization-holder",
                "fixture-owner",
                "--run-id",
                "cli-explain",
            ],
        )
        assert run_result.exit_code == 0, run_result.output
        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "explain",
                "cli-explain",
                "--format",
                "markdown",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "漏洞证据账本" in result.output
        assert "十维评分" in result.output
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_analyze_runs_every_input_given() -> None:
    """Several positional inputs each get their own run directory."""
    workspace = (Path("tmp") / f"cli-multi-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        first = _rootfs(workspace)
        second = workspace / "rootfs2"
        shutil.copytree(first, second)
        config = _test_config(workspace, (second,))

        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "analyze",
                str(first),
                str(second),
                "--authorization-holder",
                "fixture-owner",
                "--run-id",
                "multi",
            ],
        )

        assert result.exit_code == 0, result.output
        for name in ("multi-1-rootfs", "multi-2-rootfs2"):
            state = load_json(workspace / "runs" / name / "state" / "run_state.json")
            assert state["status"] == "done"
        assert "2/2 done" in result.output
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_analyze_multiple_inputs_json_is_one_object_per_line() -> None:
    workspace = (Path("tmp") / f"cli-multi-json-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        first = _rootfs(workspace)
        second = workspace / "rootfs2"
        shutil.copytree(first, second)
        config = _test_config(workspace, (second,))

        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "analyze",
                str(first),
                str(second),
                "--authorization-holder",
                "fixture-owner",
                "--json-output",
            ],
        )

        assert result.exit_code == 0, result.output
        records = [
            json.loads(line) for line in result.output.splitlines() if line.startswith('{"status"')
        ]
        assert len(records) == 2
        assert {record["input_type"] for record in records} == {"rootfs"}
        assert all(record["status"] == "done" for record in records)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def test_cli_analyze_prints_the_failure_reason() -> None:
    """A failed stage has to say why; the reason used to stay in run_state.json."""
    workspace = (Path("tmp") / f"cli-fail-test-{uuid.uuid4().hex}").resolve()
    workspace.mkdir(parents=True)
    try:
        config = _test_config(workspace)
        firmware = workspace / "rootfs" / "junk.bin"
        firmware.parent.mkdir(parents=True, exist_ok=True)
        firmware.write_bytes(b"NOT-A-FIRMWARE" * 4)

        result = CliRunner().invoke(
            main,
            [
                "--config",
                str(config),
                "analyze",
                str(firmware),
                "--authorization-holder",
                "fixture-owner",
            ],
        )

        assert result.exit_code == 2, result.output
        assert "UNPACK" in result.output
        assert "hint" in result.output
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
