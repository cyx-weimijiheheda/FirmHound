"""Recover HTTP routes served by nginx + ``ngx_lua`` configuration.

Router firmwares increasingly implement the web tier as nginx location blocks
whose request handling lives in Lua (``content_by_lua_file``) and whose
authorization lives in another Lua file (``access_by_lua_file``). Those routes
never appear in any ELF, so a binary-only surface pass reports nothing for them.

On GL.iNet MT3000 this module is what makes ``/rpc``, ``/ws``, ``/upload``,
``/download`` and ``/handle_404`` — and the Lua files behind them — visible at
all; before it existed the entire web authorization layer was invisible.

The parser is intentionally line-based: it understands ``location`` headers,
the handful of directives that matter for reachability, and ``include`` so that
split configuration directories are followed. It does not evaluate nginx
semantics (rewrites, maps, nested locations beyond one level).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

#: ``location [=|~|~*|^~] <path> {``
_LOCATION = re.compile(r"^\s*location\s+(?:[=~^*]+\s+)?([^\s{]+)\s*\{")
#: ``<directive> <lua file>;`` for the directives that bind a Lua module to a route.
_LUA_DIRECTIVE = re.compile(
    r"^\s*(?P<directive>content_by_lua_file|access_by_lua_file|rewrite_by_lua_file"
    r"|log_by_lua_file|set_by_lua_file)\s+(?P<file>[^\s;]+)\s*;"
)
#: ``include <path with globs>;``
_INCLUDE = re.compile(r"^\s*include\s+([^\s;]+)\s*;")

#: Directives whose Lua file actually produces the response or decides access.
_HANDLER_DIRECTIVES = {"content_by_lua_file", "set_by_lua_file"}
_GATE_DIRECTIVES = {"access_by_lua_file"}


def _rootfs_relative(path_text: str) -> str | None:
    """Normalize a config path reference to a rootfs-relative path."""
    text = path_text.strip().strip("'\"")
    if not text:
        return None
    # nginx may reference ``$prefix``-relative or absolute paths; both resolve
    # inside the firmware rootfs here.
    if text.startswith("/"):
        return text.lstrip("/")
    marker = "/usr/"
    idx = text.find(marker)
    return text[idx + 1 :] if idx >= 0 else text


def _iter_conf_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for directory in ("etc/nginx", "usr/local/nginx", "etc/openresty"):
        base = root / directory
        if not base.is_dir():
            continue
        out.extend(sorted(base.rglob("*.conf")))
        out.extend(sorted(base.rglob("nginx.conf")))
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in out:
        resolved = path.resolve()
        if resolved in seen or not path.is_file():
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


def parse_nginx_lua_routes(root: Path) -> list[dict[str, Any]]:
    """Return HTTP routes bound to Lua modules under ``root``.

    Each entry carries the route, the Lua file that handles it (rootfs-relative),
    and the access-gate Lua file when one is configured, so a downstream stage
    can attribute request data to the code that actually reads it.
    """
    routes: dict[str, dict[str, Any]] = {}

    for conf in _iter_conf_files(root):
        try:
            lines = conf.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        current: dict[str, Any] | None = None
        depth = 0
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            location = _LOCATION.match(line)
            if location is not None:
                current = {
                    "route": location.group(1),
                    "handler": None,
                    "access_gate": [],
                    "config": conf.relative_to(root).as_posix(),
                }
                depth = 1
                continue

            if current is not None:
                directive = _LUA_DIRECTIVE.match(line)
                if directive is not None:
                    target = _rootfs_relative(directive.group("file"))
                    name = directive.group("directive")
                    if target and name in _HANDLER_DIRECTIVES and not current["handler"]:
                        current["handler"] = target
                    elif target and name in _GATE_DIRECTIVES:
                        current["access_gate"].append(target)

                depth += line.count("{")
                depth -= line.count("}")
                if depth <= 0:
                    route = str(current["route"])
                    # ``/`` alone is the catch-all; keep it only when a Lua
                    # handler is actually bound, otherwise it just aliases the
                    # static webroot entries already enumerated elsewhere.
                    if current["handler"] or route != "/":
                        routes.setdefault(route, current)
                    current = None

        # ``include`` directives pull in sibling files that were already scanned
        # by ``_iter_conf_files``; nothing further to resolve here.

    return [routes[key] for key in sorted(routes)]


__all__ = ["parse_nginx_lua_routes"]
