"""Unit tests for the M5 analysis tools (source_sink_rules / dataflow / fp_filter)."""

from __future__ import annotations

from pathlib import Path

from fsa.reporting.evidence_store import EvidenceStore
from tools.analysis.dataflow import assemble_chain, verify_variable_usage
from tools.analysis.fp_filter import apply_fp_filters
from tools.analysis.source_sink_rules import (
    classify_sink,
    classify_source,
    classify_validation,
    match_binary,
)
from tools.audit.static import (
    _enrich_with_chain,
    _matching_surface,
    _preferred_source,
    _surface_from_importers,
)

# ---------------------------------------------------------------------------
# source_sink_rules
# ---------------------------------------------------------------------------


def test_classify_source_http_param() -> None:
    result = classify_source("websGetVar")
    assert result is not None
    assert result["type"] == "http_param"


def test_classify_source_soap() -> None:
    result = classify_source("NewDownloadURL")
    assert result is not None
    assert result["type"] == "soap_param"


def test_match_binary_uses_ghidra_function_signals() -> None:
    summary = {
        "imports": [],
        "strings_summary": {},
        "functions": [
            {"name": "system", "strings": []},
            {"name": "handle_ping", "strings": ["QUERY_STRING", "ping -c 1 %s"]},
        ],
    }
    matches = match_binary(summary)

    assert any(item["function"] == "system" for item in matches["sinks"])
    assert any(item.get("string") == "QUERY_STRING" for item in matches["sources"])


def test_classify_source_unknown() -> None:
    assert classify_source("definitely_not_a_source") is None


def test_classify_sink_command_execution() -> None:
    result = classify_sink("doSystemCmd")
    assert result is not None
    assert result["type"] == "command_execution"


def test_classify_sink_memory_safety() -> None:
    result = classify_sink("strcpy")
    assert result is not None
    assert result["type"] == "memory_safety"


def test_classify_validation_whitelist() -> None:
    assert classify_validation("strcmp") == "whitelist"


def test_match_binary_extracts_sources_and_sinks() -> None:
    summary = {
        "imports": ["system", "sprintf", "websGetVar", "strcpy"],
        "strings_summary": {"command_templates": ["%s; %s"], "dangerous_api": ["system"]},
        "functions": [{"name": "check_auth", "is_auth": True}],
        "auth_functions": [],
        "validation_functions": [],
    }
    result = match_binary(summary)
    assert any(s["type"] == "command_execution" for s in result["sinks"])
    assert any(s["type"] == "http_param" for s in result["sources"])
    assert result["auth_markers"] == ["check_auth"]


def test_preferred_source_prefers_cgi_field_over_fgets() -> None:
    summary = {
        "path": "sbin/httpd",
        "strings_summary": {"sample": ["ping_ipaddr", "get_cgi", "parse_special_char"]},
        "functions": [{"name": "get_ping_app_stat", "strings": ["ping_ipaddr"]}],
    }
    surface = {
        "handler": "ping_response.cgi",
        "route": "/ping_response.cgi",
        "page": "/tools_vct.asp",
        "param_names": ["ping_ipaddr"],
    }
    source = _preferred_source(
        [
            {"api": "fgets", "type": "socket_buffer", "name": "socket_buffer"},
            {"api": "get_cgi", "type": "http_param", "name": "http_param"},
        ],
        surface,
        summary,
    )
    assert source.get("string") == "ping_ipaddr" or source.get("api") == "get_cgi"
    assert source["type"] == "http_param"


def test_matching_surface_prefers_handler_string_hit() -> None:
    summary = {
        "path": "sbin/httpd",
        "strings_summary": {"sample": ["parse_special_char"]},
        "functions": [
            {
                "name": "FUN_00412e48",
                "strings": ["ping_ipaddr"],
                "callees": ["get_cgi", "nvram_set"],
            },
            {
                "name": "get_ping_app_stat",
                "strings": ['ping -c 1 "%s"'],
                "callees": ["parse_special_char"],
            },
            {"name": "parse_special_char", "strings": []},
        ],
    }
    page = {
        "surface_id": "surf-page",
        "binary": "sbin/httpd",
        "handler": "www/tools_vct.asp",
        "route": "/tools_vct.asp",
        "param_names": ["ping_ipaddr", "ping6_ipaddr"],
        "auth_hint": "preauth",
    }
    ping = {
        "surface_id": "surf-ping",
        "binary": "sbin/httpd",
        "handler": "ping_response.cgi",
        "route": "/ping_response.cgi",
        "page": "/tools_vct.asp",
        "param_names": ["ping_ipaddr"],
        "auth_hint": "preauth",
    }
    login = {
        "surface_id": "surf-login",
        "binary": "sbin/httpd",
        "handler": "login.cgi",
        "route": "/login.cgi",
        "param_names": ["username"],
        "auth_hint": "preauth",
    }
    save = {
        "surface_id": "surf-save",
        "binary": "sbin/httpd",
        "handler": "save_configuration.cgi",
        "route": "/save_configuration.cgi",
        "page": "/tools_system.asp",
        "param_names": ["save"],
        "auth_hint": "preauth",
    }
    chosen = _matching_surface(
        summary, [page, login, save, ping], sink={"function": "parse_special_char"}
    )
    assert chosen["surface_id"] == "surf-ping"


def test_vendor_library_inherits_importer_cgi_surface() -> None:
    httpd = {
        "path": "sbin/httpd",
        "imports": ["parse_special_char", "strcpy"],
        "functions": [
            {
                "name": "get_ping_app_stat",
                "strings": ['ping -c 1 "%s"'],
                "callees": ["parse_special_char"],
            }
        ],
    }
    lib = {
        "path": "lib/libproject.so",
        "exports": ["parse_special_char", "check_mpppoe_info"],
        "imports": ["strcpy"],
        "sinks": [{"function": "parse_special_char", "type": "memory_safety"}],
        "sources": [{"api": "parse_special_char", "type": "http_param"}],
    }
    ping = {
        "surface_id": "surf-ping",
        "binary": "sbin/httpd",
        "handler": "ping_response.cgi",
        "route": "/ping_response.cgi",
        "page": "/tools_vct.asp",
        "param_names": ["ping_ipaddr"],
        "auth_hint": "preauth",
    }
    login = {
        "surface_id": "surf-login",
        "binary": "sbin/httpd",
        "handler": "login.cgi",
        "route": "/login.cgi",
        "param_names": ["username"],
        "auth_hint": "preauth",
    }
    inherited = _surface_from_importers(
        lib,
        [login, ping],
        {"libproject": [httpd]},
        sink={"function": "strcpy"},
    )
    assert inherited["surface_id"] == "surf-ping"


def test_match_binary_uses_exported_vendor_helper() -> None:
    summary = {
        "imports": ["strcpy"],
        "exports": ["parse_special_char"],
        "strings_summary": {},
        "functions": [],
        "auth_functions": [],
        "validation_functions": [],
    }
    result = match_binary(summary)
    assert any(item.get("api") == "parse_special_char" for item in result["sources"])
    assert any(item["function"] == "strcpy" for item in result["sinks"])
    assert any(item["function"] == "parse_special_char" for item in result["sinks"])


# ---------------------------------------------------------------------------
# dataflow
# ---------------------------------------------------------------------------


def test_assemble_chain_http_template() -> None:
    chain = assemble_chain(
        {"function": "formexeCommand"},
        {"type": "http_param", "name": "cmd"},
        {"function": "system", "type": "command_execution"},
    )
    assert chain["protocol"] == "http"
    assert chain["call_chain"][0] == "request"
    assert chain["call_chain"][-1] == "shell_execute"
    assert chain["has_filter"] is False


def test_assemble_chain_with_validations_marks_filter() -> None:
    chain = assemble_chain(
        {"function": "formexeCommand"},
        {"type": "http_param", "name": "cmd"},
        {"function": "system", "type": "command_execution"},
        validations=[{"api": "strcmp", "kind": "whitelist"}],
    )
    assert chain["has_filter"] is True
    assert all(layer["filter"] for layer in chain["layers"] if layer["role"] == "transform")


def test_assemble_chain_socket_variant() -> None:
    chain = assemble_chain(
        None,
        {"type": "socket_buffer", "name": "recvfrom"},
        {"function": "strcpy", "type": "memory_safety"},
        protocol="socket",
    )
    assert chain["protocol"] == "socket"
    assert chain["call_chain"][-1] == "sink"


def test_verify_variable_usage_ok() -> None:
    functions = [
        {"name": "formexeCommand", "strings": ["cmd = websGetVar"], "is_source": True},
        {"name": "do_system", "strings": ["system(cmd)"], "is_source": False},
    ]
    result = verify_variable_usage(functions, "cmd")
    assert result["ok"] is True
    assert result["defined"] is True
    assert result["used"] is True


def test_verify_variable_usage_missing_use() -> None:
    functions = [
        {"name": "formexeCommand", "strings": ["cmd = websGetVar"], "is_source": True},
    ]
    result = verify_variable_usage(functions, "cmd")
    assert result["defined"] is True
    assert result["used"] is False
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# fp_filter
# ---------------------------------------------------------------------------


def _candidate(**overrides: object) -> dict:
    base = {
        "candidate_id": "cand-1",
        "binary_id": "httpd",
        "entry": {"function": "formexeCommand"},
        "source": {"type": "http_param", "name": "cmd"},
        "transform": [{"type": "concat", "detail": "%s; %s"}],
        "sink": {"function": "system", "type": "command_execution"},
        "user_control": "full",
        "conclusion_category": "high-confidence-candidate",
    }
    base.update(overrides)
    return base


def test_fp_filter_cli_tool_excluded() -> None:
    result = apply_fp_filters(_candidate(binary_id="busybox"), binary_path="/bin/busybox")
    assert result["excluded"] is True
    assert "cli_tool" in result["rules"]
    assert result["suggested_category"] == "false-positive"


def test_fp_filter_command_template_without_input() -> None:
    candidate = _candidate(transform=[{"type": "concat", "detail": "static only"}])
    result = apply_fp_filters(candidate)
    assert result["excluded"] is True
    assert "command_template_without_input" in result["rules"]


def test_fp_filter_internal_ipc_downgrade() -> None:
    candidate = _candidate(
        source={"type": "config_import", "name": "nvram_get"},
        user_control="none",
    )
    result = apply_fp_filters(candidate)
    assert "internal_ipc_only" in result["rules"]


def test_fp_filter_no_external_entry() -> None:
    candidate = _candidate(entry={"function": "orphan_handler"})
    surface = {"endpoints": [{"handler": "formexeCommand"}]}
    result = apply_fp_filters(candidate, attack_surface=surface)
    assert "no_reachable_external_entry" in result["rules"]


def test_fp_filter_no_rules_for_clean_candidate() -> None:
    candidate = _candidate(binary_id="httpd", entry={"function": "formexeCommand"})
    surface = {"endpoints": [{"handler": "formexeCommand"}]}
    result = apply_fp_filters(candidate, attack_surface=surface)
    assert result["excluded"] is False
    assert result["rules"] == []


def test_enrich_uses_ghidra_callgraph_when_capstone_unsupported(
    tmp_path: Path, monkeypatch
) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin" / "httpd").write_bytes(b"\x7fELF")
    run = tmp_path / "runs" / "run-ghidra-chain"
    store = EvidenceStore(run)
    summary = {
        "path": "sbin/httpd",
        "functions": [
            {
                "name": "handle_ping",
                "addr": "0x4004f6",
                "callee_addrs": ["0x4003b0"],
                "strings": ["QUERY_STRING"],
            },
            {
                "name": "system",
                "addr": "0x4003b0",
                "callee_addrs": [],
                "strings": [],
            },
        ],
    }
    candidate = {
        "candidate_id": "cand-ghidra",
        "sink": {"function": "system", "type": "command_execution"},
        "source": {"string": "QUERY_STRING", "type": "http_query"},
        "call_chain": [],
        "validation": [],
        "evidence": [],
        "counterevidence": ["call-chain-not-proven"],
    }
    monkeypatch.setattr(
        "tools.audit.static.recover_chains",
        lambda *_args, **_kwargs: {"status": "unsupported-arch", "sink_callers": []},
    )

    _enrich_with_chain(candidate, summary, str(rootfs), store, run.name)

    assert len(candidate["call_chain"]) == 2
    assert "call-chain-not-proven" not in candidate["counterevidence"]
    assert candidate["evidence"]


def test_enrich_prefers_named_caller_matching_cgi_hint(tmp_path: Path, monkeypatch) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin" / "httpd").write_bytes(b"\x7fELF")
    run = tmp_path / "runs" / "run-named-chain"
    store = EvidenceStore(run)
    summary = {
        "path": "sbin/httpd",
        "functions": [
            {
                "name": "get_ping_app_stat",
                "addr": "0x42aaf8",
                "callee_addrs": ["0x460710"],
                "callees": ["parse_special_char"],
                "strings": ['ping -c 1 "%s"'],
            },
            {
                "name": "parse_special_char",
                "addr": "0x460710",
                "callee_addrs": [],
                "strings": [],
            },
        ],
    }
    candidate = {
        "candidate_id": "cand-ping",
        "sink": {"function": "parse_special_char", "type": "memory_safety"},
        "source": {"string": "ping_ipaddr", "type": "http_param"},
        "entry": {
            "route": "/ping_response.cgi",
            "handler": "ping_response.cgi",
            "page": "/tools_vct.asp",
            "params": ["ping_ipaddr"],
        },
        "call_chain": [],
        "validation": [],
        "evidence": [],
        "counterevidence": ["call-chain-not-proven"],
    }
    monkeypatch.setattr(
        "tools.audit.static.recover_chains",
        lambda *_args, **_kwargs: {
            "status": "ok",
            "sink_callers": [
                {
                    "func_name": None,
                    "func_addr": 0x411CA4,
                    "sink": "parse_special_char",
                    "sink_addr": None,
                    "call_addr": 0x412124,
                    "same_func_source": True,
                },
                {
                    "func_name": "get_ping_app_stat",
                    "func_addr": 0x42AAF8,
                    "sink": "parse_special_char",
                    "sink_addr": None,
                    "call_addr": 0x42AB44,
                    "same_func_source": True,
                },
            ],
        },
    )

    _enrich_with_chain(candidate, summary, str(rootfs), store, run.name)

    assert candidate["call_chain"][0]["func"] == "get_ping_app_stat"
    assert candidate["call_chain"][1]["func"] == "parse_special_char"
    assert candidate["call_chain"][1]["addr"] == "0x42ab44"
    assert "call-chain-not-proven" not in candidate["counterevidence"]
