"""Source / Sink / Validation / Authorization rule library (M5).

Solidifies the legacy command-injection five-step method and the protocol
parsing six-step method into a machine-usable rule table. Vendor-specific
wrappers (D-Link ``doSystemCmd``/``lxmldbc_system``, Tenda ``alpha_system2``,
``websGetVar``, ``getenv("QUERY_STRING")``) are encoded as dictionaries so they
are matched without hardcoding in the dataflow layer.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Sources: external input channels an attacker can influence.
# ---------------------------------------------------------------------------
SOURCE_RULES: list[dict[str, Any]] = [
    {
        "name": "http_param",
        "kind": "http_param",
        "patterns": ["websGetVar", "$_GET", "$_POST", "arg[", "ngx.var", "request.get"],
    },
    {
        "name": "http_header",
        "kind": "http_header",
        "patterns": [
            "HTTP_COOKIE",
            "HTTP_USER_AGENT",
            "SOAPAction",
            "Content-Length",
            "Authorization",
        ],
    },
    {
        "name": "http_query",
        "kind": "http_query",
        "patterns": ['getenv("QUERY_STRING")', "QUERY_STRING", "query_string"],
    },
    {
        "name": "http_cookie",
        "kind": "http_cookie",
        "patterns": ["COOKIE", "get_cookie", "cookie"],
    },
    {
        "name": "soap_param",
        "kind": "soap_param",
        "patterns": ["NewDownloadURL", "NewStatusURL", "direction=in", "soap", "SOAPAction"],
    },
    {
        "name": "socket_buffer",
        "kind": "socket_buffer",
        "patterns": ["recv", "recvfrom", "recvmsg", "read(", "fgets", "readline"],
    },
    {
        "name": "file_upload",
        "kind": "file_upload",
        "patterns": ["multipart/form-data", "upload", "write_file"],
    },
    {
        "name": "config_import",
        "kind": "config_import",
        "patterns": ["config_get", "nvram_get", "flash_get", "uci_get"],
    },
    {
        "name": "environment",
        "kind": "environment",
        "patterns": ["getenv", "environ"],
    },
]

# ---------------------------------------------------------------------------
# Sinks: four categories, each with a list of API names to match.
# ---------------------------------------------------------------------------
SINK_RULES: dict[str, dict[str, Any]] = {
    "command_execution": {
        "patterns": [
            "system", "__system", "popen", "execl", "execlp", "execle", "execv",
            "execvp", "execve", "doSystemCmd", "lxmldbc_system", "alpha_system2",
            "unlink", "sprintf_system",
        ],
    },
    "memory_safety": {
        "patterns": [
            "strcpy",
            "strcat",
            "sprintf",
            "vsprintf",
            "gets",
            "memcpy",
            "strncpy",
            "strncat",
            "sscanf",
        ],
    },
    "filesystem": {
        "patterns": ["fwrite", "write", "open", "fopen", "chmod", "chown", "rename", "symlink"],
    },
    "format_string": {
        "patterns": ["printf", "fprintf", "snprintf", "vsnprintf", "syslog"],
    },
}

# ---------------------------------------------------------------------------
# Validation: filters applied between source and sink.
# ---------------------------------------------------------------------------
VALIDATION_RULES: dict[str, list[str]] = {
    "length_check": ["strlen", "sizeof", "strnlen", "check_len"],
    "whitelist": ["strcmp", "strncmp", "in_array", "is_valid", "allowed"],
    "blacklist": ["strstr", "strchr", "strtok", "str_replace", "preg_replace", "filter"],
    "escape": ["escapeshellarg", "escapeshellcmd", "addslashes", "htmlspecialchars", "quote"],
    "path_normalize": ["realpath", "dirname", "basename", "canonicalize"],
    "type_limit": ["atoi", "strtol", "is_numeric", "isdigit"],
}


def _match(name: str, patterns: list[str]) -> bool:
    lowered = name.lower()
    return any(p.lower() in lowered for p in patterns)


def classify_source(name: str) -> dict[str, Any] | None:
    """Classify a function/string name as an input source, or ``None``."""
    for rule in SOURCE_RULES:
        if _match(name, rule["patterns"]):
            return {"type": rule["kind"], "name": rule["name"]}
    return None


def classify_sink(name: str) -> dict[str, Any] | None:
    """Classify a function name as a sink, or ``None``.

    Imported names on some toolchains carry a version suffix
    (``system@GLIBC_2.2.5``). Strip it for the candidate identity so the
    versioned and unversioned imports do not become two different candidates.
    """
    for category, rule in SINK_RULES.items():
        if _match(name, rule["patterns"]):
            return {"function": name.split("@", 1)[0], "type": category}
    return None


def classify_validation(name: str) -> str | None:
    """Classify a function name as a validation kind, or ``None``."""
    for kind, patterns in VALIDATION_RULES.items():
        if _match(name, patterns):
            return kind
    return None


def match_binary(binary_summary: dict[str, Any]) -> dict[str, Any]:
    """Extract sources / sinks / validations / auth markers from a binary summary.

    Operates on the ``binary_summary.schema.json`` shape produced by M4, using
    its ``imports``, ``strings_summary``, ``functions`` and ``auth_functions``
    fields. No ELF file access required, so it is trivially unit-testable.
    """
    imports = binary_summary.get("imports", [])
    strings = _flatten_strings(binary_summary)
    functions = binary_summary.get("functions", [])
    auth_functions = set(binary_summary.get("auth_functions", []))
    validation_functions = set(binary_summary.get("validation_functions", []))

    sources: list[dict[str, Any]] = []
    seen_sources: set[tuple[str, str]] = set()

    def add_source(item: dict[str, Any]) -> None:
        key = (str(item.get("type", "")), str(item.get("api") or item.get("string") or ""))
        if key in seen_sources:
            return
        seen_sources.add(key)
        sources.append(item)

    for name in imports:
        classified = classify_source(name)
        if classified:
            add_source({"api": name, **classified})
    for text in strings:
        classified = classify_source(text)
        if classified:
            add_source({"string": text, **classified})

    sinks: list[dict[str, Any]] = []
    seen_sinks: set[tuple[str, str]] = set()

    def add_sink(item: dict[str, Any]) -> None:
        key = (str(item.get("function", "")), str(item.get("type", "")))
        if key in seen_sinks:
            return
        seen_sinks.add(key)
        sinks.append(item)

    for name in imports:
        classified = classify_sink(name)
        if classified:
            add_sink(classified)

    validations: list[dict[str, Any]] = []
    seen_validations: set[tuple[str, str]] = set()

    def add_validation(api: str, kind: str) -> None:
        key = (api, kind)
        if key in seen_validations:
            return
        seen_validations.add(key)
        validations.append({"api": api, "kind": kind})

    for name in imports:
        kind = classify_validation(name)
        if kind:
            add_validation(name, kind)

    # Ghidra-enriched summaries carry function-level strings and imported
    # thunk names. They let a stripped/MIPS daemon expose the same source/sink
    # signals without pretending the data flow is already proven.
    for func in functions:
        if not isinstance(func, dict):
            continue
        func_name = str(func.get("name") or "")
        if func_name:
            classified = classify_sink(func_name)
            if classified:
                add_sink(classified)
            source_item = classify_source(func_name)
            if source_item:
                add_source({"api": func_name, **source_item})
            validation_kind = classify_validation(func_name)
            if validation_kind:
                add_validation(func_name, validation_kind)
        for text in func.get("strings") or []:
            source_item = classify_source(str(text))
            if source_item:
                add_source({"string": str(text), **source_item})
            validation_kind = classify_validation(str(text))
            if validation_kind:
                add_validation(str(text), validation_kind)

    auth_markers: list[str] = []
    for func in functions:
        if func.get("is_auth") or func.get("name") in auth_functions:
            auth_markers.append(func.get("name", ""))

    return {
        "sources": sources,
        "sinks": sinks,
        "validations": validations,
        "auth_markers": sorted(set(auth_markers)),
        "validation_functions": sorted(validation_functions),
    }


def _flatten_strings(binary_summary: dict[str, Any]) -> list[str]:
    """Collect strings from a binary summary's ``strings_summary``."""
    summary = binary_summary.get("strings_summary", {})
    out: list[str] = []
    for value in summary.values():
        if isinstance(value, list):
            out.extend(str(v) for v in value)
        elif isinstance(value, str):
            out.append(value)
    return out
