"""Build attack_surface.json by combining M3 enumeration tools."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from fsa.reporting.store_base import RunLayout
from fsa.schemas.loader import validate
from fsa.utils.jsonio import save_json
from fsa.utils.traverse import iter_rootfs_files
from tools.filesystem.inventory import inventory_rootfs
from tools.filesystem.startup_parse import parse_all_startup
from tools.web.auth_matrix import classify_auth
from tools.web.handler_extract import extract_handlers
from tools.web.upnp_parse import find_upnp_xmls, parse_upnp_xml
from tools.web.webroot_enum import enumerate_webroot, find_webroots

_WEB_DAEMON_NAMES = frozenset({"httpd", "goahead", "lighttpd", "boa", "mini_httpd", "uhttpd"})


def _surface_id() -> str:
    return f"surf-{uuid.uuid4().hex[:8]}"


def _evidence_id() -> str:
    return f"ev-{uuid.uuid4().hex[:8]}"


def build_attack_surface(
    rootfs_dir: str | Path,
    run_id: str,
    run_root: str | Path,
) -> dict[str, Any]:
    """Enumerate attack surfaces from a rootfs and write attack_surface.json.

    Args:
        rootfs_dir: Extracted rootfs directory.
        run_id: Run identifier.
        run_root: Parent directory for run artifacts.

    Returns:
        Dict matching ``attack_surface.schema.json``.
    """
    root = Path(rootfs_dir)
    if not root.exists():
        raise FileNotFoundError(f"Rootfs not found: {root}")

    layout = RunLayout(run_id, run_root)
    surfaces: list[dict[str, Any]] = []
    startup = parse_all_startup(root)
    web_binary, web_startup = _web_daemon(root, startup)

    # Webroot enumeration.
    seen_routes: set[str] = set()
    for webroot in find_webroots(root):
        enum = enumerate_webroot(webroot)
        for ep in enum["endpoints"]:
            page_route = str(ep["route"])
            posted_forms = list(ep.get("posted_forms") or [])
            if not posted_forms and ep.get("posted_cgi"):
                posted_forms = [
                    {
                        "action": ep.get("posted_cgi"),
                        "fields": list(ep.get("form_fields") or []),
                    }
                ]
            page_fields = [
                str(item)
                for form in posted_forms
                for item in (form.get("fields") or [])
                if item
            ]
            _append_web_surface(
                surfaces,
                seen_routes,
                root=root,
                web_binary=web_binary,
                web_startup=web_startup,
                route=page_route,
                handler=str(ep["file"]),
                suffix=str(ep.get("suffix") or ""),
                fields=page_fields,
                page=None,
            )
            for form in posted_forms:
                posted = str(form.get("action") or "")
                if not posted:
                    continue
                fields = [str(item) for item in (form.get("fields") or []) if item]
                _append_web_surface(
                    surfaces,
                    seen_routes,
                    root=root,
                    web_binary=web_binary,
                    web_startup=web_startup,
                    route=f"/{posted}",
                    handler=posted,
                    suffix=".cgi",
                    fields=fields,
                    page=page_route,
                )

    # Binary handler extraction for all ELF binaries.
    inv = inventory_rootfs(root)
    for elf_rel in inv["elf_paths"]:
        elf_path = root / elf_rel
        extracted = extract_handlers(elf_path)
        binary_rel = str(elf_path.relative_to(root).as_posix())
        for form in extracted["goahead_forms"]:
            if form["route"] in seen_routes:
                continue
            seen_routes.add(form["route"])
            surface_id = _surface_id()
            auth = classify_auth(form["route"], elf_path, form["handler"], None)
            surfaces.append(
                {
                    "surface_id": surface_id,
                    "category": "cgi",
                    "protocol": "http",
                    "binary": binary_rel,
                    "route": form["route"],
                    "handler": form["handler"],
                    "input_sources": ["http_param"],
                    "auth_hint": auth.hint,
                    "startup_evidence": (
                        web_startup if Path(binary_rel).name in _WEB_DAEMON_NAMES else []
                    ),
                    "reachability_hint": "LAN web admin (handler in binary)",
                    "confidence": 0.85 if extracted["goahead_registered"] else 0.6,
                    "evidence_ids": [_evidence_id()],
                }
            )
        for cgi in extracted.get("cgi_strings") or []:
            route = _normalize_cgi_route(str(cgi.get("route") or ""))
            if not route or route in seen_routes:
                continue
            seen_routes.add(route)
            surface_id = _surface_id()
            auth = classify_auth(route, elf_path, Path(route).name, None)
            surfaces.append(
                {
                    "surface_id": surface_id,
                    "category": "cgi",
                    "protocol": "http",
                    "binary": binary_rel,
                    "route": route,
                    "handler": Path(route).name,
                    "input_sources": ["http_param"],
                    "auth_hint": auth.hint,
                    "startup_evidence": (
                        web_startup if Path(binary_rel).name in _WEB_DAEMON_NAMES else []
                    ),
                    "reachability_hint": "LAN web admin (CGI string in binary)",
                    "confidence": 0.7,
                    "evidence_ids": [_evidence_id()],
                }
            )

    # UPnP surfaces.
    for xml_path in find_upnp_xmls(root):
        parsed = parse_upnp_xml(xml_path)
        for action in parsed["actions"]:
            if not action["inputs"]:
                continue
            surface_id = _surface_id()
            surfaces.append(
                {
                    "surface_id": surface_id,
                    "category": "upnp",
                    "protocol": "soap",
                    "binary": None,
                    "route": f"/upnp/{Path(xml_path).name}",
                    "handler": action["name"],
                    "input_sources": ["soap_arg"],
                    "auth_hint": "preauth",
                    "startup_evidence": [],
                    "reachability_hint": "LAN UPnP",
                    "confidence": 0.9 if action["high_impact"] else 0.7,
                    "evidence_ids": [_evidence_id()],
                }
            )

    # Startup-driven daemon surfaces.
    for name, services in startup["grouped"].items():
        if name in _WEB_DAEMON_NAMES:
            continue
        if len(services) == 0:
            continue
        surface_id = _surface_id()
        evidence = [f"{s['source_file']}:{s['line']}" for s in services[:3]]
        surfaces.append(
            {
                "surface_id": surface_id,
                "category": "daemon",
                "protocol": "unknown",
                "binary": services[0]["binary"],
                "route": None,
                "handler": name,
                "input_sources": ["socket_buf"],
                "auth_hint": "unknown",
                "startup_evidence": evidence,
                "reachability_hint": "started at boot",
                "confidence": 0.6,
                "evidence_ids": [_evidence_id()],
            }
        )

    attack_surface = {
        "run_id": run_id,
        "firmware_path": str(root.resolve()),
        "surfaces": surfaces,
    }
    validate(attack_surface, schema_name="attack_surface")
    save_json(layout.attack_surface, attack_surface)
    return attack_surface


def _append_web_surface(
    surfaces: list[dict[str, Any]],
    seen_routes: set[str],
    *,
    root: Path,
    web_binary: str | None,
    web_startup: list[str],
    route: str,
    handler: str,
    suffix: str,
    fields: list[str],
    page: str | None,
) -> None:
    if route in seen_routes:
        return
    seen_routes.add(route)
    auth = classify_auth(route, root / web_binary if web_binary else None, handler, None)
    surfaces.append(
        {
            "surface_id": _surface_id(),
            "category": "web" if suffix in {".html", ".htm"} else "cgi",
            "protocol": "http",
            "binary": web_binary,
            "route": route,
            "handler": handler,
            "input_sources": ["http_param"],
            "param_names": fields,
            "page": page,
            "auth_hint": auth.hint,
            "startup_evidence": web_startup,
            "reachability_hint": "LAN web admin",
            "confidence": max(auth.confidence, 0.7 if web_binary else auth.confidence),
            "evidence_ids": [_evidence_id()],
        }
    )


def _normalize_cgi_route(raw: str) -> str:
    text = raw.strip().split("?")[0].replace("\\", "/")
    if not text.endswith(".cgi"):
        return ""
    name = text.rsplit("/", 1)[-1]
    if not name or "*" in name:
        return ""
    return "/" + name if not text.startswith("/") else "/" + name


def _web_daemon(root: Path, startup: dict[str, Any]) -> tuple[str | None, list[str]]:
    """Bind webroot CGI pages to the httpd-class binary when one exists.

    Prefer a daemon named in startup scripts. DIR-825-class images start
    ``rc init`` instead of ``httpd`` directly; fall back to a real httpd ELF
    under ``sbin/`` / ``usr/sbin/`` so ASP/CGI pages are not left unmapped.
    """
    grouped = startup.get("grouped") or {}
    for name in _WEB_DAEMON_NAMES:
        services = grouped.get(name) or []
        if not services:
            continue
        evidence = [f"{item['source_file']}:{item['line']}" for item in services[:3]]
        located = _locate_web_binary(root, name, services[0].get("binary"))
        if located:
            return located, evidence
        return str(services[0].get("binary") or name).lstrip("/"), evidence
    for name in _WEB_DAEMON_NAMES:
        located = _locate_web_binary(root, name, None)
        if located:
            rc_hits = grouped.get("rc") or grouped.get("rcS") or []
            evidence = [f"{item['source_file']}:{item['line']}" for item in rc_hits[:3]]
            return located, evidence
    return None, []


def _locate_web_binary(root: Path, name: str, raw: Any) -> str | None:
    rels: list[str] = []
    text = str(raw or "").lstrip("./")
    if text:
        rels.append(text)
        if text.startswith("/"):
            rels.append(text.lstrip("/"))
    rels.extend((f"sbin/{name}", f"usr/sbin/{name}", f"bin/{name}"))
    for rel in rels:
        if (root / rel).is_file():
            return Path(rel).as_posix()
    for path in iter_rootfs_files(root):
        if path.name == name:
            try:
                return str(path.relative_to(root).as_posix())
            except ValueError:
                continue
    return None


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 4:
        print("Usage: python -m tools.web.build_attack_surface <rootfs> <run_id> <run_root>")
        raise SystemExit(1)
    result = build_attack_surface(sys.argv[1], sys.argv[2], sys.argv[3])
    print(json.dumps(result, indent=2))
