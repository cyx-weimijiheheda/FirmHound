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
        "patterns": [
            "websGetVar",
            "$_GET",
            "$_POST",
            "arg[",
            "ngx.var",
            "request.get",
            "get_cgi",
            "parse_special_char",
        ],
        # Lua / ngx_lua read request data through explicit API calls rather than
        # through a C buffer, so they need their own allow-list entries.
        "exact": [
            "websGetVar",
            "ngx.req.get_uri_args",
            "ngx.req.get_post_args",
            "ngx.req.read_body",
            "ngx.req.get_body_data",
            "ngx.req.get_body_file",
            "ngx.var.request_body",
            "ngx.var.uri",
            "get_cgi",
            "parse_special_char",
        ],
        "prefix_ok": ["ngx.var.arg_", "ngx.var.request_"],
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
        # ``add_AuthorizationData`` is an LDAP/ASN.1 helper, not a header read.
        "exact": [
            "HTTP_COOKIE",
            "HTTP_USER_AGENT",
            "HTTP_AUTHORIZATION",
            "HTTP_HOST",
            "HTTP_REFERER",
            "SOAPAction",
            "Content-Length",
            "Authorization",
            "User-Agent",
            "Cookie",
            "ngx.req.get_headers",
            "ngx.var.http_",
        ],
        "prefix_ok": ["ngx.var.http_"],
    },
    {
        "name": "http_query",
        "kind": "http_query",
        "patterns": ['getenv("QUERY_STRING")', "QUERY_STRING", "query_string"],
        # ``ads_dns_query_string_dcs`` is an ADS DNS lookup, not a query string.
        "exact": [
            'getenv("QUERY_STRING")',
            "QUERY_STRING",
            "query_string",
            "http.query_string",
            "ngx.req.get_uri_args",
        ],
        "prefix_ok": ["ngx.var.arg_"],
    },
    {
        "name": "http_cookie",
        "kind": "http_cookie",
        "patterns": ["COOKIE", "get_cookie", "cookie"],
        # ``ndr_pull_vfs_default_durable_cookie`` is an SMB2 durable-handle
        # parser; the HTTP header environment is the real cookie channel.
        "exact": ["COOKIE", "HTTP_COOKIE", "cookie", "get_cookie", "set_cookie"],
        "prefix_ok": ["ngx.var.cookie_"],
        # No ``_cookie`` suffix: ``ndr_pull_*_durable_cookie`` is an SMB2 handle
        # parser. A vendor wrapper must name the reader explicitly instead.
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
        # Only libc-level stream reads count. Substring matching classified
        # ``dcerpc_binding_handle_call_recv`` (an RPC completion callback) and
        # ``gensec_update_recv`` as socket input, which let 546 Samba library
        # candidates through the "network source" gate on GL.iNet MT3000 with
        # zero mapped attack surface. Suffix rules were not enough: ``_recv``
        # still matches those callbacks, so the allow-list is explicit.
        # No "reader": it is an ordinary English word and matched arbitrary
        # description strings inside vendor runtimes.
        "exact": ["recv", "recvfrom", "recvmsg", "fgets", "readline"],
        "suffix_ok": ["_fgets"],  # vendor wrappers such as ``x_fgets``
        "suffix_deny": ["_recv"],  # every ``*_recv`` is an RPC/tevent completion
    },
    {
        "name": "file_upload",
        "kind": "file_upload",
        "patterns": ["multipart/form-data", "upload", "write_file"],
        # Samba's ``ndr_print_..._UploadPrinterDriverPackage`` and
        # ``ldb_ldif_write_file`` are NDR printers and LDIF writers, not upload
        # handlers. Keep the MIME marker and real entry points only.
        # ``fwrite`` is a write *sink*, not an upload channel; it belongs to the
        # filesystem sink rules and must not seed candidates on the source side.
        "exact": ["multipart/form-data", "file_upload", "upload_file", "write_file"],
        "suffix_ok": ["_upload", "_upload_file"],
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
            # Lua reaches the shell through these; ``io.popen`` already matched on
            # the "popen" substring, ``os.execute`` did not match anything.
            # ``dofile``/``loadstring`` eval attacker-influenced Lua, which is the
            # same capability, so they share the category rather than inventing
            # one the risk scorer does not know about.
            "os.execute", "os.exec", "posix.exec", "os.spawn", "dofile", "loadstring",
        ],
        # ASUS routers route nearly every shell call through ``_eval(argv, ...)``,
        # a ``fork`` + ``execvp(argv[0], argv)`` wrapper in ``libshared.so``.
        # RT-AX58U has 19 ELFs importing it and 25 call sites in ``httpd`` alone,
        # yet it matched no pattern: the leading underscore defeats the ``execvp``
        # substring. It must be exact — ``_cpu_eval``, ``av_expr_eval`` and
        # ``CT_POLICY_EVAL_CTX_*`` all contain the ``_eval`` substring but are
        # signal/CPU helpers and an OpenSSL context type, not command execution.
        "exact": ["_eval"],
    },
    "memory_safety": {
        "patterns": [
            "strcpy",
            "strcat",
            "sprintf",
            "vsprintf",
            "gets",
            "asprintf",
            "vasprintf",
            "memcpy",
            "strncpy",
            "strncat",
            "sscanf",
            "parse_special_char",
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


def _match_source_rule(name: str, rule: dict[str, Any]) -> bool:
    """Decide whether ``name`` belongs to a source rule.

    Rules that declare ``exact``/``suffix_ok`` opt out of substring matching so
    that protocol callbacks (``..._call_recv``) are not mistaken for socket
    reads. ``prefix_ok`` covers parameterised accessors such as
    ``ngx.var.arg_<name>`` where only the family prefix is stable. Unversioned
    names are compared after stripping ``@GLIBC_*`` tails.
    """
    exact = rule.get("exact")
    if not exact:
        return _match(name, rule["patterns"])

    lowered = name.split("@", 1)[0].lower().strip()
    if lowered.endswith("("):
        lowered = lowered[:-1]
    if lowered in {item.lower() for item in exact}:
        return True
    deny = tuple(item.lower() for item in rule.get("suffix_deny") or ())
    if deny and lowered.endswith(deny):
        return False
    if any(lowered.startswith(item.lower()) for item in rule.get("prefix_ok") or ()):
        return True
    return any(lowered.endswith(item.lower()) for item in rule.get("suffix_ok") or ())


def _match(name: str, patterns: list[str]) -> bool:
    lowered = name.lower()
    return any(p.lower() in lowered for p in patterns)


def classify_source(name: str) -> dict[str, Any] | None:
    """Classify a function/string name as an input source, or ``None``."""
    for rule in SOURCE_RULES:
        if _match_source_rule(name, rule):
            return {"type": rule["kind"], "name": rule["name"]}
    return None


def classify_sink(name: str) -> dict[str, Any] | None:
    """Classify a function name as a sink, or ``None``.

    Imported names on some toolchains carry a version suffix
    (``system@GLIBC_2.2.5``). Strip it for the candidate identity so the
    versioned and unversioned imports do not become two different candidates.

    Rules may declare ``exact`` for names whose spelling is too generic for
    substring matching (``_eval`` would otherwise match ``_cpu_eval``).
    """
    bare = name.split("@", 1)[0].strip()
    for category, rule in SINK_RULES.items():
        exact = rule.get("exact")
        if exact and bare.lower() in {item.lower() for item in exact}:
            return {"function": bare, "type": category}
        if _match(bare, rule["patterns"]):
            return {"function": bare, "type": category}
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
    exports = [
        item["name"] if isinstance(item, dict) else str(item)
        for item in (binary_summary.get("exports") or [])
        if item
    ]
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

    for name in (*imports, *exports):
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

    for name in (*imports, *exports):
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
