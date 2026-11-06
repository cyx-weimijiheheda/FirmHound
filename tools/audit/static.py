"""Evidence-backed static vulnerability candidate generation."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from fsa.reporting.evidence_store import EvidenceStore
from fsa.schemas.loader import validate
from fsa.utils.jsonio import save_json
from tools.analysis.source_sink_rules import match_binary
from tools.audit.audit_constants import CHAIN_SINKS as _CHAIN_SINKS
from tools.audit.audit_constants import KIND_BY_API as _KIND_BY_API
from tools.audit.audit_constants import skip_shared_object as _skip_shared_object
from tools.binary.call_chain import recover_chains
from tools.binary.ghidra_export import chain_callers
from tools.pipeline_context import load_artifact, run_path, save_artifact

_chain_cache: dict[str, dict[str, Any]] = {}

_NETWORK_SOURCE_TYPES = {
    "http_param",
    "http_header",
    "http_query",
    "http_cookie",
    "soap_param",
    "socket_buffer",
    "file_upload",
}
_HTTP_SOURCE_TYPES = {
    "http_param",
    "http_header",
    "http_query",
    "http_cookie",
    "soap_param",
    "file_upload",
}
_HTTP_READER_APIS = {"get_cgi", "websGetVar", "cgi_get", "cgiGetVar"}
_GENERIC_TOKENS = {
    "html",
    "page",
    "name",
    "file",
    "http",
    "https",
    "cgi",
    "form",
    "input",
    "value",
    "type",
    "text",
    "submit",
    "hidden",
    "response",
    "return",
    "script",
    "function",
    "tools",
    "system",
    "config",
    "status",
    "index",
    "admin",
    "apply",
    "save",
    "user",
    "pass",
    "login",
    "misc",
    "host",
    "unknown",
    "transmitted",
    "memset",
    "fopen",
    "fclose",
    "fread",
    "fgets",
    "strlen",
    "strstr",
    "sprintf",
    "strcpy",
    "display",
    "stat",
    "test",
    "app",
}


def _resolve_rootfs(run_dir: str) -> str:
    payload = load_artifact(run_dir, "rootfs.json", {})
    if isinstance(payload, dict):
        return str(payload.get("rootfs_path") or "")
    return ""


def _enrich_with_chain(
    candidate: dict[str, Any],
    summary: dict[str, Any],
    rootfs: str,
    evidence_store: EvidenceStore,
    run_id: str,
    *,
    stage: str = "DECOMPILE_FALLBACK",
) -> None:
    """Attach a disassembly-backed call chain when one exists for this sink.

    Uses :mod:`tools.binary.call_chain` (capstone, ARM32 / MIPS). Only upgrades
    the candidate when a concrete enclosing function calling the sink was found
    -- otherwise the candidate keeps its honest "call-chain-not-proven" state.
    """
    sink_func = str((candidate.get("sink") or {}).get("function", ""))
    binary_path = str(summary.get("path", ""))
    if not (rootfs and binary_path and sink_func in _CHAIN_SINKS):
        return
    elf_path = Path(rootfs, binary_path)
    if not elf_path.is_file():
        return
    cache_key = str(elf_path)
    if cache_key not in _chain_cache:
        try:
            _chain_cache[cache_key] = recover_chains(elf_path, sink_functions=list(_CHAIN_SINKS))
        except Exception:  # noqa: BLE001 - degrade, never abort a run
            _chain_cache[cache_key] = {"status": "failed", "sink_callers": []}
    report = _chain_cache[cache_key]
    callers = list(report.get("sink_callers", []) or [])
    ghidra_mode = False
    source = candidate.get("source") or {}
    source_value = str(source.get("string") or source.get("api") or "") or None
    if summary.get("functions"):
        # Do not filter Ghidra callers by source_value here: DIR-825's
        # get_ping_app_stat calls parse_special_char but does not mention
        # ping_ipaddr in its own strings (the CGI field lives in FUN_00412e48).
        ghidra_report = chain_callers(summary, sink_func)
        ghidra_callers = list(ghidra_report.get("sink_callers", []) or [])
        if ghidra_callers:
            if callers:
                callers = _merge_callers(callers, ghidra_callers)
            else:
                callers = ghidra_callers
                ghidra_mode = True
    if not callers:
        return
    entry = candidate.get("entry") or {}
    hints = [
        source_value or "",
        str(entry.get("handler") or ""),
        str(entry.get("route") or ""),
        str(entry.get("page") or ""),
        *[str(item) for item in (entry.get("params") or [])],
    ]
    ranked = _rank_callers(callers, sink_func, hints)
    for caller, ghidra_hit in ranked:
        if caller.get("sink") != sink_func or caller.get("func_addr") is None:
            continue
        func_addr = caller["func_addr"]
        caller_name = str(caller.get("func_name") or f"sub_{func_addr:x}")
        sink_addr = caller.get("sink_addr")
        if sink_addr is None:
            sink_addr = caller.get("call_addr")
        if sink_addr is None:
            continue
        used_ghidra = ghidra_mode or ghidra_hit
        candidate["call_chain"] = [
            {
                "addr": hex(func_addr),
                "func": caller_name,
                "note": (
                    "Ghidra callgraph: enclosing function"
                    if used_ghidra
                    else "enclosing function calls the sink"
                ),
            },
            {
                "addr": hex(sink_addr),
                "func": sink_func,
                "note": (
                    "Ghidra callgraph: sink callee"
                    if used_ghidra
                    else "sink call site"
                ),
            },
        ]
        filters = caller.get("same_func_filters", []) or []
        if filters:
            seen_kinds: set[str] = set()
            validation = []
            for api in filters:
                kind = _KIND_BY_API.get(api, "other")
                if kind in seen_kinds:
                    continue
                seen_kinds.add(kind)
                validation.append({"api": api, "kind": kind, "same_function": True})
            candidate["validation"] = validation
        if "call-chain-not-proven" in candidate.get("counterevidence", []):
            candidate["counterevidence"] = [
                ce for ce in candidate["counterevidence"] if ce != "call-chain-not-proven"
            ]
        if used_ghidra:
            observation = (
                f"Ghidra callgraph: {caller_name} calls {sink_func} "
                f"(callee {hex(sink_addr)}) in {binary_path}; "
                f"same-function source: {caller.get('source') or caller.get('same_func_source')}"
            )
            tool = "ghidra"
            evidence_stage = "DECOMPILE"
        else:
            call_addr = caller.get("call_addr", sink_addr)
            observation = (
                f"disassembly: function {caller_name} calls {sink_func} "
                f"at 0x{call_addr:x} in {binary_path}; "
                f"same-function source-API read: {caller.get('same_func_source')}"
            )
            tool = "tools.binary.call_chain"
            evidence_stage = stage
        evidence_id = evidence_store.add(
            run_id=run_id,
            stage=evidence_stage,
            type="decompile",
            observation=observation,
            tool=tool,
            tool_version="1.0",
            source_file=binary_path,
            artifact_path=binary_path,
            fact_status="confirmed",
            supports=[candidate["candidate_id"]],
        )
        candidate["evidence"].append(evidence_id["evidence_id"])
        break


def _merge_callers(
    capstone: list[dict[str, Any]], ghidra: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Keep capstone call sites, overlaying Ghidra names at the same function."""
    named = {
        int(item["func_addr"]): item
        for item in ghidra
        if item.get("func_addr") is not None
    }
    merged: list[dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()
    for item in capstone:
        rec = dict(item)
        func_addr = rec.get("func_addr")
        if func_addr in named and not rec.get("func_name"):
            rec["func_name"] = named[func_addr].get("func_name")
            rec["ghidra"] = True
        key = (
            int(func_addr or 0),
            int(rec.get("call_addr") or rec.get("sink_addr") or 0),
        )
        seen.add(key)
        merged.append(rec)
    for item in ghidra:
        key = (int(item.get("func_addr") or 0), int(item.get("sink_addr") or 0))
        if key in seen:
            continue
        rec = dict(item)
        rec["ghidra"] = True
        merged.append(rec)
    return merged


def _rank_callers(
    callers: list[dict[str, Any]], sink_func: str, hints: list[str]
) -> list[tuple[dict[str, Any], bool]]:
    """Prefer named callers whose tokens overlap the CGI/source hints."""
    hint_tokens = _tokens(*hints)
    ranked: list[tuple[int, dict[str, Any], bool]] = []
    for caller in callers:
        if caller.get("sink") != sink_func or caller.get("func_addr") is None:
            continue
        name = str(caller.get("func_name") or "")
        overlap = _tokens(name).intersection(hint_tokens)
        score = 0
        if overlap:
            score += 8 + min(len(overlap), 3)
        if name:
            score += 4
        if caller.get("same_func_source"):
            score += 2
        if caller.get("call_addr") is not None and not caller.get("ghidra"):
            score += 3
        elif caller.get("ghidra"):
            score += 1
        ranked.append((score, caller, bool(caller.get("ghidra"))))
    ranked.sort(key=lambda item: item[0], reverse=True)
    return [(item[1], item[2]) for item in ranked]


def _candidate_id(binary_id: str, source: str, sink: str) -> str:
    raw = f"{binary_id}:{source}:{sink}"
    return f"cand-{hashlib.sha256(raw.encode()).hexdigest()[:12]}"


def _class_for_sink(sink: dict[str, Any]) -> str:
    if sink["type"] == "command_execution":
        return "command_injection"
    if sink["type"] == "memory_safety":
        return "overflow"
    if sink["type"] == "format_string":
        return "format_string"
    if sink["type"] == "filesystem":
        return "path_traversal"
    return "other"


def _tokens(*parts: str) -> set[str]:
    blob = " ".join(part for part in parts if part).lower()
    tokens = set()
    for token in re.split(r"[^a-z0-9]+", blob):
        if len(token) >= 4 and token not in _GENERIC_TOKENS:
            tokens.add(token)
    return tokens


def _function_blob(func: dict[str, Any]) -> str:
    names = [str(func.get("name") or "")]
    names.extend(str(item) for item in (func.get("strings") or []))
    return " ".join(names)


def _sink_related_functions(summary: dict[str, Any], sink_name: str) -> list[dict[str, Any]]:
    if not sink_name:
        return []
    related: list[dict[str, Any]] = []
    for func in summary.get("functions") or []:
        if not isinstance(func, dict):
            continue
        name = str(func.get("name") or "")
        callees = {str(item) for item in (func.get("callees") or [])}
        if name == sink_name or sink_name in callees:
            related.append(func)
    return related


def _http_reader_functions(summary: dict[str, Any]) -> list[dict[str, Any]]:
    readers: list[dict[str, Any]] = []
    for func in summary.get("functions") or []:
        if not isinstance(func, dict):
            continue
        callees = {str(item) for item in (func.get("callees") or [])}
        name = str(func.get("name") or "")
        if name in _HTTP_READER_APIS or callees.intersection(_HTTP_READER_APIS):
            readers.append(func)
    return readers


def _string_haystack(summary: dict[str, Any]) -> str:
    parts = [
        str(sample)
        for sample in (summary.get("strings_summary") or {}).get("sample", [])
    ]
    for func in summary.get("functions") or []:
        if not isinstance(func, dict):
            continue
        parts.append(str(func.get("name") or ""))
        parts.extend(str(item) for item in (func.get("strings") or []))
    return " ".join(parts)


def _matching_surface(
    summary: dict[str, Any],
    surfaces: list[dict[str, Any]],
    *,
    sink: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach the attack surface that *actually* belongs to this binary.

    Old behaviour matched on bare basename (``Path(surface.binary).name ==
    Path(summary.path).name``), which made candidates inherit a *different*
    binary's surface whenever two files shared a name -- and, worse, attached
    bogus ``/goform/format`` noise surfaces. New rules:

    1. exact rootfs-relative path equality between ``surface.binary`` and the
       binary summary path (covers CGI surfaces and ``daemon`` surfaces);
    2. among exact matches, prefer one whose handler / form-field token appears
       in the binary's own strings (best-effort handler attribution);
    3. then prefer ``preauth`` (unauthenticated) surfaces -- worst case is the
       honest assumption for a blind run.
    """
    binary_path = summary.get("path", "")
    exact = [
        surface
        for surface in surfaces
        if surface.get("binary") == binary_path
        or (
            surface.get("category") == "daemon"
            and surface.get("handler") == Path(binary_path).name
        )
    ]
    if not exact:
        return {}
    sink_name = str((sink or {}).get("function") or "")
    sink_funcs = _sink_related_functions(summary, sink_name)
    sink_blob = " ".join(_function_blob(func) for func in sink_funcs)
    reader_funcs = _http_reader_functions(summary)
    sink_tokens = _tokens(sink_blob)
    scored: list[tuple[int, dict[str, Any]]] = []
    for surface in exact:
        score = 0
        handler = str(surface.get("handler") or "")
        route = str(surface.get("route") or "")
        fields = [str(item) for item in (surface.get("param_names") or []) if item]
        is_cgi = str(handler).endswith(".cgi") or str(route).endswith(".cgi")
        surface_tokens = _tokens(Path(handler).stem, Path(route).stem)
        if any(field in sink_blob for field in fields):
            score += 8
        linked = False
        for func in reader_funcs:
            blob = _function_blob(func)
            hits = [field for field in fields if field in blob]
            if not hits:
                continue
            func_tokens = _tokens(blob, str(func.get("name") or ""))
            if func_tokens.intersection(sink_tokens) or func_tokens.intersection(surface_tokens):
                linked = True
                break
        if linked:
            score += 6
        overlap = surface_tokens.intersection(sink_tokens)
        if overlap:
            score += 5 + min(len(overlap), 3)
        if is_cgi:
            score += 3
        if surface.get("auth_hint") == "preauth":
            score += 1
        scored.append((score, int(is_cgi), surface))
    scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return scored[0][2]


def _preferred_source(
    matched_sources: list[dict[str, Any]],
    surface: dict[str, Any],
    summary: dict[str, Any],
) -> dict[str, Any]:
    """Prefer HTTP/CGI parameter sources over generic ``fgets``/socket reads."""
    haystack = _string_haystack(summary)
    fields = [str(item) for item in (surface.get("param_names") or []) if item]
    handler = Path(str(surface.get("handler") or "")).name
    sources = list(matched_sources)
    for field in fields:
        already = any(
            str(item.get("string") or item.get("api") or "") == field for item in sources
        )
        if already:
            continue
        if field and (field in haystack or surface):
            sources.append({"string": field, "type": "http_param", "name": "http_param"})
    if not sources:
        return {}

    def _rank(item: dict[str, Any]) -> tuple[int, int]:
        kind = str(item.get("type") or "")
        token = str(item.get("string") or item.get("api") or "")
        score = 0
        if token and token in fields:
            score += 10
        if token in {"get_cgi", "websGetVar"}:
            score += 5
        if token == "parse_special_char":
            score += 4
        if kind in _HTTP_SOURCE_TYPES:
            score += 4
        if handler and token and handler in token:
            score += 3
        if token and token in haystack and kind in _HTTP_SOURCE_TYPES:
            score += 1
        if kind == "socket_buffer":
            score -= 4
        return (score, 0 if kind in _HTTP_SOURCE_TYPES else -1)

    ranked = sorted(sources, key=_rank, reverse=True)
    http = next((item for item in ranked if item.get("type") in _NETWORK_SOURCE_TYPES), ranked[0])
    return http


def _soname(path: str) -> str:
    name = Path(path).name.lower()
    return name.split(".so", 1)[0] if ".so" in name else name


def _importer_index(summaries: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Map vendor-library stems to binaries that import their symbols."""
    index: dict[str, list[dict[str, Any]]] = {}
    libraries = [
        item
        for item in summaries
        if str(item.get("path", "")).endswith(".so")
        and not _skip_shared_object(str(item.get("path", "")))
    ]
    for library in libraries:
        exports = {
            item["name"] if isinstance(item, dict) else str(item)
            for item in (library.get("exports") or [])
            if item
        }
        if not exports:
            continue
        stem = _soname(str(library.get("path", "")))
        importers: list[dict[str, Any]] = []
        for summary in summaries:
            path = str(summary.get("path", ""))
            if path == library.get("path") or path.endswith(".so") or path.endswith(".ko"):
                continue
            imported = {str(item) for item in (summary.get("imports") or [])}
            if imported.intersection(exports):
                importers.append(summary)
        if importers:
            index[stem] = importers
    return index


def _surface_from_importers(
    summary: dict[str, Any],
    surfaces: list[dict[str, Any]],
    importer_index: dict[str, list[dict[str, Any]]],
    *,
    sink: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach a vendor .so sink to a CGI surface of a binary that imports it."""
    importers = importer_index.get(_soname(str(summary.get("path", "")))) or []
    exports = {
        item["name"] if isinstance(item, dict) else str(item)
        for item in (summary.get("exports") or [])
        if item
    }
    sink_name = str((sink or {}).get("function") or "")
    helpers = {
        str(item.get("api") or item.get("function") or "")
        for item in (summary.get("sources") or []) + (summary.get("sinks") or [])
        if isinstance(item, dict)
    }
    helpers.update(exports)
    proxy_name = sink_name if sink_name in exports else ""
    if not proxy_name:
        preferred = [
            name
            for name in ("parse_special_char", "get_cgi", "websGetVar")
            if name in helpers
        ]
        if preferred:
            proxy_name = preferred[0]
    if not proxy_name:
        for importer in importers:
            imported = {str(item) for item in (importer.get("imports") or [])}
            overlap = sorted(imported.intersection(exports))
            if overlap:
                proxy_name = overlap[0]
                break
    proxy_sink = dict(sink or {})
    if proxy_name:
        proxy_sink["function"] = proxy_name
    for importer in importers:
        surface = _matching_surface(importer, surfaces, sink=proxy_sink)
        if surface:
            return surface
    return {}


def execute_static(run_dir: str) -> dict[str, Any]:
    """Create candidates only when a real binary contains source and sink signals."""
    binary_payload = load_artifact(run_dir, "binary_summaries.json")
    if not isinstance(binary_payload, dict):
        return {"status": "failed", "reason": "binary summaries are missing"}
    surface_payload = load_artifact(run_dir, "attack_surface.json", {"surfaces": []})
    surfaces = surface_payload.get("surfaces", []) if isinstance(surface_payload, dict) else []
    run = run_path(run_dir)
    rootfs_dir = _resolve_rootfs(run_dir)
    evidence_store = EvidenceStore(run)
    candidates: list[dict[str, Any]] = []
    importer_index = _importer_index(binary_payload.get("summaries", []))

    for summary in binary_payload.get("summaries", []):
        summary_path = str(summary.get("path", ""))
        # Kernel modules (.ko) and libc/runtime shared objects are not
        # user-space entry points. Vendor helper libraries (libproject.so,
        # libshared.so, ...) *do* host overflow sinks that httpd calls, so they
        # stay in the candidate set; glibc/uClibc/libgcc still do not.
        if summary_path.endswith(".ko") or _skip_shared_object(summary_path):
            continue
        matched = match_binary(summary)
        if not matched["sources"] or not matched["sinks"]:
            continue
        for sink in matched["sinks"]:
            if summary_path.endswith(".so"):
                surface = _surface_from_importers(
                    summary, surfaces, importer_index, sink=sink
                )
            else:
                surface = _matching_surface(summary, surfaces, sink=sink)
            source = _preferred_source(matched["sources"], surface, summary)
            if not source:
                continue
            source_signal = source.get("api") or source.get("string")
            # Blind-run precision gate: a candidate needs either a mapped attack
            # surface or a network-borne source. Sinks reached only from internal
            # env/config sources with no entry point are noise; skipping them
            # keeps candidates.json focused on reachable attack surface.
            if not surface and source.get("type") not in _NETWORK_SOURCE_TYPES:
                continue
            # Filesystem sinks (open/fwrite/write_mtd/...) of an *unmapped*
            # flash/updater binary are by-design behaviour, not a reachable
            # attack surface; they used to flood candidates and outrank real
            # web command injection in the ranking.
            if sink.get("type") == "filesystem" and not surface:
                continue
            source_key = str(source.get("string") or source.get("api") or source["type"])
            candidate_id = _candidate_id(summary["binary_id"], source_key, sink["function"])
            evidence = evidence_store.add(
                run_id=run.name,
                stage="STATIC_ANALYSIS",
                type="file_observation",
                observation=(
                    f"ELF {summary['path']} contains source signal {source_signal} "
                    f"and imported sink {sink['function']}; data-flow reachability is not proven."
                ),
                tool="tools.audit.static",
                tool_version="1.0",
                source_file=summary["path"],
                artifact_path=str(run / "artifacts" / "binary_summaries.json"),
                fact_status="confirmed",
                supports=[candidate_id],
            )
            auth_hint = surface.get("auth_hint", "unknown")
            candidate: dict[str, Any] = {
                "candidate_id": candidate_id,
                "surface_id": surface.get("surface_id", "unmapped-surface"),
                "binary_id": summary["binary_id"],
                "entry": {
                    "route": surface.get("route") or surface.get("page"),
                    "handler": surface.get("handler"),
                    "page": surface.get("page"),
                    "params": surface.get("param_names") or [],
                },
                "source": source,
                "transform": [],
                "validation": matched["validations"],
                "authorization": {
                    "required": True
                    if auth_hint == "auth"
                    else False
                    if auth_hint == "preauth"
                    else None,
                    "hint": auth_hint,
                },
                "sink": sink,
                "call_chain": [],
                "user_control": "partial",
                "vuln_class_hypothesis": _class_for_sink(sink),
                "risk_score": 0,
                "risk_level": "LOW",
                "evidence": [evidence["evidence_id"]],
                "counterevidence": ["call-chain-not-proven"],
                "conclusion_category": "unknown",
                "decisive_missing_fact": "source-to-sink data-flow and call-chain reachability",
                "status": "analyzing",
            }
            validate(candidate, schema_name="candidate")
            _enrich_with_chain(
                candidate, summary, rootfs_dir, evidence_store, run.name
            )
            candidates.append(candidate)

    result = {"run_id": run.name, "candidates": candidates}
    artifact = save_artifact(run, "candidates.json", result)
    save_json(run / "candidates.json", result)
    return {
        "status": "ok",
        "candidate_count": len(candidates),
        "candidates": str(artifact),
    }
