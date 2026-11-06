"""Shared constants for static audit and the bounded agent loop."""

from __future__ import annotations

from pathlib import Path

# Sink imports worth recovering an actual call site for (ARM32 / MIPS disassembly).
CHAIN_SINKS = frozenset(
    {
        "doSystemCmd",
        "system",
        "popen",
        "execve",
        "sprintf",
        "vsprintf",
        "strcpy",
        "strncpy",
        "memcpy",
        "strcat",
        "snprintf",
        "parse_special_char",
    }
)

# API name -> verifier-recognised validation kind.
KIND_BY_API = {
    "strlen": "length_check",
    "strncmp": "whitelist",
    "strcmp": "whitelist",
    "atoi": "type_limit",
    "strtol": "type_limit",
    "strtoul": "type_limit",
    "strtok": "blacklist",
    "isalpha": "charset_check",
    "isdigit": "charset_check",
}

# Runtime/C library sonames that are never user-space vulnerability entry
# points. Vendor helpers such as libproject.so stay eligible.
SKIP_SO_STEMS = frozenset(
    {
        "ld",
        "ld-uclibc",
        "ld-linux",
        "libc",
        "libcrypt",
        "libdl",
        "libgcc",
        "libgcc_s",
        "libm",
        "libnsl",
        "libpthread",
        "libresolv",
        "librt",
        "libstdc++",
        "libutil",
        "libuclibc",
    }
)


def skip_shared_object(relative_path: str) -> bool:
    """Return True when a .so should not generate its own candidates."""
    name = Path(relative_path).name.lower()
    if not (name.endswith(".so") or ".so." in name):
        return False
    stem = name.split(".so", 1)[0]
    return stem in SKIP_SO_STEMS or stem.startswith("ld-")
