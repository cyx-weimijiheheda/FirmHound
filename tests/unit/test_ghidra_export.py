"""Ghidra export normalization and callgraph helpers (no Ghidra required)."""

from __future__ import annotations

from pathlib import Path

from fsa.utils.proc import RunResult
from tools.binary.ghidra_export import (
    apply_export,
    chain_callers,
    export_binary,
    resolve_ghidra_headless,
    summarize_functions,
)


def _export() -> dict:
    return {
        "available": True,
        "functions": {
            "0x4004f6": {
                "name": "handle_ping",
                "strings": ['"QUERY_STRING"', '"ping -c 1 %s"'],
                "basic_blocks": [],
                # getenv -> system -> fgets: fgets only consumes the output.
                "call_sites": [
                    {"addr": "0x400500", "callee": "0x400370"},
                    {"addr": "0x400520", "callee": "0x4003b0"},
                    {"addr": "0x400540", "callee": "0x400360"},
                ],
            },
            "0x400600": {
                "name": "handle_cmd",
                "strings": ['"QUERY_STRING"'],
                "basic_blocks": [],
                # fgets -> system: the source call precedes the sink call.
                "call_sites": [
                    {"addr": "0x400620", "callee": "0x400360"},
                    {"addr": "0x400640", "callee": "0x4003b0"},
                ],
            },
            "0x400360": {"name": "fgets", "strings": [], "basic_blocks": []},
            "0x400370": {"name": "getenv", "strings": [], "basic_blocks": []},
            "0x4003b0": {"name": "system", "strings": [], "basic_blocks": []},
            "0x404028": {"name": "system", "strings": [], "basic_blocks": []},
        },
        "callgraph": {
            "0x4004f6": ["0x400370", "0x4003b0", "0x400360"],
            "0x400600": ["0x400360", "0x4003b0"],
            "0x400360": [],
            "0x400370": [],
            "0x4003b0": ["0x404028"],
            "0x404028": [],
        },
    }


def test_summarize_functions_and_chain_callers() -> None:
    records = summarize_functions(_export())
    summary = {"functions": records}

    assert any(item["name"] == "handle_ping" for item in records)
    assert any(item["name"] == "system" and item["is_sink"] for item in records)
    assert any(item["name"] == "handle_ping" and item["is_source"] for item in records)

    chain = chain_callers(summary, "system")

    assert chain["status"] == "ok"
    assert chain["sink_callers"]
    caller = chain["sink_callers"][0]
    assert caller["func_name"] == "handle_ping"
    assert caller["func_addr"] == int("0x4004f6", 16)
    assert caller["sink"] == "system"
    assert caller["same_func_source"] is True
    assert chain_callers(summary, "system", source_value="QUERY_STRING")["status"] == "ok"
    assert chain_callers(summary, "system", source_value="DIAG")["status"] == "no-callers"


def test_chain_callers_requires_source_before_sink() -> None:
    records = summarize_functions(_export())
    ping = next(item for item in records if item["name"] == "handle_ping")
    assert ping["call_sites"][0] == {"addr": "0x400500", "callee": "0x400370"}

    summary = {"functions": records}
    callers = chain_callers(summary, "system", source_value="fgets")["sink_callers"]

    # handle_ping calls fgets only after system (it consumes popen/system output);
    # handle_cmd calls fgets before system and is therefore a real pairing.
    assert [item["func_name"] for item in callers] == ["handle_cmd"]


def test_apply_export_marks_summary_full() -> None:
    summary = {"path": "usr/sbin/lab_httpd"}
    apply_export(summary, _export())

    assert summary["decompile_status"] == "full"
    assert summary["decompile_backend"] == "ghidra"
    assert summary["functions"]


def test_resolve_ghidra_prefers_env(tmp_path: Path, monkeypatch) -> None:
    fake = tmp_path / "analyzeHeadless"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("GHIDRA_HEADLESS", str(fake))
    monkeypatch.setattr("tools.binary.ghidra_export.shutil.which", lambda _name: None)

    assert resolve_ghidra_headless({"decompile": {"backend": "ghidra"}}) == str(fake)


def test_auto_prefers_docker_even_when_native_exists(tmp_path: Path, monkeypatch) -> None:
    fake = tmp_path / "analyzeHeadless"
    fake.touch()
    monkeypatch.setenv("GHIDRA_HEADLESS", str(fake))
    monkeypatch.setattr("tools.binary.ghidra_export.docker_available", lambda: (True, "ok"))
    monkeypatch.setattr("tools.binary.ghidra_export.docker_image_exists", lambda _image: True)
    assert resolve_ghidra_headless({}) == "docker://firmhound/firmrec:local"


def test_explicit_docker_does_not_silently_use_native(tmp_path: Path, monkeypatch) -> None:
    fake = tmp_path / "analyzeHeadless"
    fake.touch()
    monkeypatch.setenv("GHIDRA_HEADLESS", str(fake))
    monkeypatch.setattr("tools.binary.ghidra_export.docker_available", lambda: (False, "down"))
    assert resolve_ghidra_headless({"decompile": {"backend": "docker"}}) is None


def test_docker_export_maps_paths_and_isolates_network(tmp_path: Path, monkeypatch) -> None:
    import json

    from tools.external.backends import BackendResult

    binary = tmp_path / "input" / "httpd"
    binary.parent.mkdir()
    binary.write_bytes(b"\x7fELF")
    output = tmp_path / "output" / "graph.json"
    monkeypatch.setattr("tools.binary.ghidra_export.PolicyEngine.check_path", lambda *_: None)

    def fake_docker(image, cmd, **kwargs):
        assert image == "test/ghidra:local"
        assert kwargs["entrypoint"] == "/root/ghidra/support/analyzeHeadless"
        assert kwargs["extra_args"] == ["--network", "none"]
        assert kwargs["mounts"][binary] == "/work/input/httpd:ro"
        assert kwargs["mounts"][output.parent] == "/work/output"
        assert cmd[cmd.index("-postScript") + 2] == "/work/output/graph.json"
        assert not output.exists()  # stale output must not be reused
        output.write_text(json.dumps(_export()))
        return BackendResult("ok")

    output.parent.mkdir()
    output.write_text('{"stale":true}')
    monkeypatch.setattr("tools.binary.ghidra_export.run_docker", fake_docker)
    result = export_binary(binary, output, "docker://test/ghidra:local")
    assert result["available"] is True
    assert result["export"]["functions"]


def test_docker_export_rejects_paths_outside_policy(tmp_path: Path, monkeypatch) -> None:
    def forbidden_run(*args, **kwargs):
        raise AssertionError("policy rejection must happen before Docker invocation")

    monkeypatch.setattr("tools.binary.ghidra_export.run_docker", forbidden_run)
    result = export_binary("/etc/passwd", tmp_path / "out.json", "docker://test/ghidra:local")
    assert result["available"] is False
    assert "path_whitelist" in result["limitation"]


def test_export_binary_writes_json(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "httpd"
    binary.write_bytes(b"\x7fELF")
    out_json = tmp_path / "export.json"
    ghidra = tmp_path / "analyzeHeadless"
    ghidra.write_text("#!/bin/sh\n", encoding="utf-8")
    payload = _export()

    def fake_run(command, timeout=600, env=None):
        target = Path(command[command.index("-postScript") + 2])
        import json

        target.write_text(json.dumps(payload), encoding="utf-8")
        return RunResult(
            command=" ".join(command),
            returncode=0,
            stdout="ok",
            stderr="",
            status="success",
        )

    monkeypatch.setattr("tools.binary.ghidra_export.run_command", fake_run)

    result = export_binary(binary, out_json, str(ghidra))

    assert result["status"] == "ok"
    assert result["available"] is True
    assert out_json.is_file()


def test_export_binary_missing_binary_degrades(tmp_path: Path) -> None:
    result = export_binary(
        tmp_path / "missing",
        tmp_path / "out.json",
        str(tmp_path / "analyzeHeadless"),
    )
    assert result["available"] is False
    assert result["status"] == "failed"
