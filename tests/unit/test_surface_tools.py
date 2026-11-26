"""Unit tests for attack-surface enumeration tools (M3 front half)."""

from pathlib import Path

from tools.filesystem.inventory import inventory_rootfs
from tools.filesystem.startup_parse import parse_all_startup, parse_startup_script
from tools.web.webroot_enum import enumerate_webroot, find_webroots


def _elf_header() -> bytes:
    """Return a minimal valid 32-bit little-endian MIPS ELF header."""
    return (
        b"\x7fELF"
        + b"\x01\x01\x01\x00"
        + b"\x00" * 8
        + b"\x01\x00"  # e_type
        + b"\x08\x00"  # e_machine = MIPS
        + b"\x01\x00\x00\x00"
        + b"\x00\x10\x00\x00"
        + b"\x34\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x34\x00"
        + b"\x20\x00"
        + b"\x01\x00"
        + b"\x28\x00"
        + b"\x00\x00"
        + b"\x00\x00"
    )


def _make_rootfs(path: Path) -> None:
    """Create a representative fake rootfs."""
    (path / "bin").mkdir(parents=True)
    (path / "usr" / "sbin").mkdir(parents=True)
    (path / "etc" / "init.d").mkdir(parents=True)
    (path / "www" / "goform").mkdir(parents=True)
    (path / "etc" / "config").mkdir(parents=True)
    (path / "bin" / "busybox").write_bytes(_elf_header())
    (path / "usr" / "sbin" / "httpd").write_bytes(_elf_header())
    (path / "etc" / "init.d" / "rcS").write_text(
        "#!/bin/sh\n/usr/sbin/httpd -h /www\n/bin/busybox syslogd\n",
        encoding="utf-8",
    )
    (path / "www" / "goform" / "formexeCommand").write_text("cgi", encoding="utf-8")
    (path / "www" / "index.html").write_text("<html></html>", encoding="utf-8")
    (path / "www" / "style.css").write_text("body {}", encoding="utf-8")
    (path / "etc" / "config" / "system.conf").write_text("name=router", encoding="utf-8")
    (path / "etc" / "init.d" / "start.sh").write_text("#!/bin/sh\n", encoding="utf-8")


def test_inventory(tmp_path: Path) -> None:
    """inventory_rootfs correctly counts file types."""
    root = tmp_path / "rootfs"
    _make_rootfs(root)
    inv = inventory_rootfs(root)
    assert inv["elf_count"] == 2
    assert inv["script_count"] >= 1
    assert "etc/init.d/rcS" in inv["startup_script_paths"]
    assert "www" in inv["webroots"] or any("www" in w for w in inv["webroots"])


def test_startup_parse(tmp_path: Path) -> None:
    """parse_startup_script extracts service invocations."""
    script = tmp_path / "rcS"
    script.write_text(
        "#!/bin/sh\n/usr/sbin/httpd -h /www\n/bin/busybox syslogd\n",
        encoding="utf-8",
    )
    services = parse_startup_script(script)
    binaries = {s["binary"] for s in services}
    assert "/usr/sbin/httpd" in binaries
    assert "/bin/busybox" in binaries


def test_parse_all_startup(tmp_path: Path) -> None:
    """parse_all_startup groups services by binary name."""
    root = tmp_path / "rootfs"
    _make_rootfs(root)
    parsed = parse_all_startup(root)
    assert parsed["service_count"] >= 2
    assert "httpd" in parsed["grouped"]
    assert any("/www" in s["args"] for s in parsed["grouped"]["httpd"])


def test_webroot_enum(tmp_path: Path) -> None:
    """enumerate_webroot finds CGI endpoints and skips static assets."""
    webroot = tmp_path / "www"
    (webroot / "goform").mkdir(parents=True)
    (webroot / "goform" / "formexeCommand").write_text("cgi", encoding="utf-8")
    (webroot / "index.html").write_text("html", encoding="utf-8")
    (webroot / "style.css").write_text("css", encoding="utf-8")
    (webroot / "tools_vct.asp").write_text(
        '<form method="post" action="ping_response.cgi">'
        '<input type="text" name="ping_ipaddr" maxlength="63">'
        '<input name="ping" id="ping" type="submit" value="Ping">'
        "</form>"
        '<form method="post" action="ping6_response.cgi">'
        '<input type="text" name="ping6_ipaddr">'
        '<input type="submit" name="ping2" id="ping2">'
        "</form>",
        encoding="utf-8",
    )
    result = enumerate_webroot(webroot)
    routes = {e["route"] for e in result["endpoints"]}
    assert "/goform/formexeCommand" in routes
    assert "/index.html" in routes
    assert result["static_asset_count"] == 1
    ping = next(item for item in result["endpoints"] if item["route"] == "/tools_vct.asp")
    assert ping["posted_cgi"] == "ping_response.cgi"
    assert "ping_ipaddr" in ping["form_fields"]
    actions = [item["action"] for item in ping["posted_forms"]]
    assert actions == ["ping_response.cgi", "ping6_response.cgi"]
    ping6 = next(item for item in ping["posted_forms"] if item["action"] == "ping6_response.cgi")
    assert "ping6_ipaddr" in ping6["fields"]
    assert "ping_ipaddr" not in ping6["fields"]
    assert "ping" not in ping["form_fields"]
    assert "ping2" not in ping6["fields"]


def test_find_webroots(tmp_path: Path) -> None:
    """find_webroots locates webroot directories."""
    root = tmp_path / "rootfs"
    (root / "www").mkdir(parents=True)
    (root / "usr" / "htdocs").mkdir(parents=True)
    webroots = find_webroots(root)
    names = {w.name for w in webroots}
    assert "www" in names
    assert "htdocs" in names


def test_static_assets_are_not_request_surfaces() -> None:
    """Locale bundles and icons must not be counted as CGI entry points.

    Regression: every webroot suffix other than .html/.htm was labelled ``cgi``,
    so GL.iNet MT3000 reported 336 ``i18n/*.json`` "CGI" surfaces behind the one
    real ``cgi-bin/glc`` script and that inflated count drove binary triage.
    """
    from tools.web.build_attack_surface import _surface_category

    for suffix in (".json", ".js", ".css", ".png", ".svg", ".woff2", ".map", ".gz"):
        assert _surface_category(suffix) is None, suffix

    for suffix in (".html", ".htm"):
        assert _surface_category(suffix) == "web", suffix

    for suffix in (".cgi", ".fcgi", ".php", ".pl"):
        assert _surface_category(suffix) == "cgi", suffix


def test_rpc_callbacks_are_not_socket_sources() -> None:
    """A name containing "recv" is not necessarily a socket read.

    Regression: Samba's ``dcerpc_binding_handle_call_recv`` and
    ``gensec_update_recv`` matched the ``recv`` substring rule, so 546 library
    candidates on GL.iNet MT3000 passed the "network source" gate with no mapped
    attack surface at all.
    """
    from tools.analysis.source_sink_rules import classify_source

    for callback in (
        "dcerpc_binding_handle_call_recv",
        "gensec_update_recv",
        "ndr_pull_netr_DsRGetDCNameEx2",
    ):
        assert classify_source(callback) is None, callback

    for reader in ("recv", "recvfrom", "recvmsg", "fgets", "readline"):
        classified = classify_source(reader)
        assert classified is not None and classified["type"] == "socket_buffer", reader

    # Vendor wrappers around a real read stay classified.
    assert classify_source("x_fgets")["type"] == "socket_buffer"


def test_protocol_parsers_are_not_http_sources() -> None:
    """Substring rules must not turn protocol helpers into HTTP input channels.

    Every name below matched a substring pattern (``upload``, ``cookie``,
    ``Authorization``, ``query_string``, ``recv``) while being an NDR printer,
    SMB2 handle parser, LDAP helper or tevent callback. On GL.iNet MT3000 they
    produced ~500 library candidates with no reachable entry point.
    """
    from tools.analysis.source_sink_rules import classify_source

    for parser in (
        "dcerpc_winreg_QueryInfoKey_recv",
        "open_socket_out_recv",
        "read_smb_recv",
        "_tstream_npa_accept_existing_recv",
        "SMB_VFS_FSYNC_RECV",
        "ndr_print_winspool_AsyncUploadPrinterDriverPackage",
        "ndr_pull_vfs_default_durable_cookie",
        "ldb_ldif_write_file",
        "add_AuthorizationData",
        "ads_dns_query_string_dcs",
    ):
        assert classify_source(parser) is None, parser

    # Real channels keep working.
    assert classify_source("QUERY_STRING")["type"] == "http_query"
    assert classify_source("HTTP_COOKIE")["type"] == "http_header"
    assert classify_source("get_cookie")["type"] == "http_cookie"
    assert classify_source("multipart/form-data")["type"] == "file_upload"
    assert classify_source("websGetVar")["type"] == "http_param"
