"""Call-chain recovery for ARM32 and MIPS (capstone, no Ghidra)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "fixtures"))

from elf_builder import write_mips32_pic_elf  # noqa: E402

from tools.analysis.source_sink_rules import classify_sink, classify_source
from tools.audit.audit_constants import skip_shared_object
from tools.binary.call_chain import SUPPORTED_ARCHES, recover_chains
from tools.binary.pipeline import _decompile_priority

_REPO = Path(__file__).resolve().parents[2]
_DIR825_ROOTFS = (
    _REPO
    / "tmp"
    / "dir825-firmware"
    / "DIR825B1_FW210NAb02.bin.extracted"
    / "100000"
    / "squashfs-root"
)


def test_supported_arches_include_mips() -> None:
    assert {"arm", "arm32", "mips", "mipsel"} <= SUPPORTED_ARCHES


def test_skip_shared_object_keeps_vendor_helpers() -> None:
    assert skip_shared_object("lib/libc.so.0") is True
    assert skip_shared_object("lib/libgcc_s.so.1") is True
    assert skip_shared_object("lib/libproject.so") is False
    assert skip_shared_object("sbin/httpd") is False


def test_decompile_priority_promotes_vendor_so() -> None:
    httpd = _decompile_priority({"path": "sbin/httpd", "triage_score": 0.2, "sinks": ["strcpy"]})
    vendor = _decompile_priority(
        {"path": "lib/libproject.so", "triage_score": 0.2, "sinks": ["strcpy"]}
    )
    libc = _decompile_priority({"path": "lib/libc.so.0", "triage_score": 0.2, "sinks": ["strcpy"]})
    assert httpd > vendor > libc


def test_parse_special_char_is_http_source_and_overflow_sink() -> None:
    classified = classify_source("parse_special_char")
    assert classified is not None
    assert classified["type"] == "http_param"
    sink = classify_sink("parse_special_char")
    assert sink is not None
    assert sink["type"] == "memory_safety"


def test_mips_recover_chains_synthetic_jalr(tmp_path: Path) -> None:
    elf = write_mips32_pic_elf(tmp_path / "helper.so", import_name="strcpy", func_name="helper")
    report = recover_chains(elf, sink_functions=["strcpy"])
    assert report["status"] == "ok"
    sites = [item for item in report["sink_callers"] if item["sink"] == "strcpy"]
    assert sites
    assert sites[0]["func_addr"] == 0x1000
    assert sites[0]["call_addr"] == 0x1018


def test_mips_recover_chains_on_dir825_httpd() -> None:
    httpd = _DIR825_ROOTFS / "sbin" / "httpd"
    if not httpd.is_file():
        pytest.skip("DIR-825 squashfs-root is not unpacked in this workspace")
    report = recover_chains(httpd, sink_functions=["parse_special_char", "strcpy", "sprintf"])
    assert report["status"] == "ok"
    sinks = {item["sink"] for item in report["sink_callers"]}
    assert "parse_special_char" in sinks
    ping = [
        item
        for item in report["sink_callers"]
        if item["sink"] == "parse_special_char" and item["call_addr"] == 0x42AB44
    ]
    assert ping, report["sink_callers"][:8]
    assert ping[0]["func_addr"] == 0x42AAF8


def test_mips_recover_chains_on_libproject_strcpy() -> None:
    lib = _DIR825_ROOTFS / "lib" / "libproject.so"
    if not lib.is_file():
        pytest.skip("DIR-825 squashfs-root is not unpacked in this workspace")
    report = recover_chains(lib, sink_functions=["strcpy"])
    assert report["status"] == "ok"
    strcpy_sites = [item for item in report["sink_callers"] if item["sink"] == "strcpy"]
    assert any(item.get("func_addr") == 0x1F88 for item in strcpy_sites)
    assert any(item["call_addr"] == 0x2010 for item in strcpy_sites)
    parse = next(item for item in strcpy_sites if item.get("func_addr") == 0x1F88)
    assert parse.get("func_name") == "parse_special_char"
    assert parse.get("same_func_source") is True
