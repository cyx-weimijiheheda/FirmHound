"""M8 L1: QEMU user-mode load check (architecture/loader/basic boot).

Runs the harmless ``busybox echo QEMU_OK`` baseline self-check under
``qemu-<arch>`` / ``qemu-<arch>-static`` to prove the binary can be loaded for
the target architecture. On a host whose architecture matches the target
(e.g. the x86_64 lab fixture), a static native busybox is used instead.
Missing loaders degrade to a ``skipped`` result with an explicit limitation —
never a crash.
"""

from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path
from typing import Any

from fsa.utils.proc import run_command

_HOST_ARCH_ALIASES = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "i386": "i386",
    "i686": "i386",
    "armv7l": "arm",
    "armv6l": "arm",
}

# Architecture -> candidate QEMU user-mode binary names.
ARCH_QEMU: dict[str, list[str]] = {
    "mipsel": ["qemu-mipsel-static", "qemu-mipsel"],
    "mips": ["qemu-mips-static", "qemu-mips"],
    "arm": ["qemu-arm-static", "qemu-arm"],
    "aarch64": ["qemu-aarch64-static", "qemu-aarch64"],
    "x86_64": ["qemu-x86_64-static", "qemu-x86_64"],
    "i386": ["qemu-i386-static", "qemu-i386"],
    "powerpc": ["qemu-ppc-static", "qemu-ppc"],
}

_QEMU_OK = "QEMU_OK"


def detect_qemu(arch: str) -> str | None:
    """Return the first available QEMU user-mode binary for ``arch``, or None."""
    for name in ARCH_QEMU.get(arch, []):
        if shutil.which(name):
            return name
    return None


def _native_busybox(rootfs: str | Path, busybox: str) -> Path | None:
    local = Path(rootfs) / busybox
    if local.is_file():
        return local
    configured = os.environ.get("BUSYBOX_BIN", "")
    if configured and Path(configured).is_file():
        return Path(configured)
    found = shutil.which("busybox")
    return Path(found) if found else None


def _native_load(
    rootfs: str | Path,
    busybox: str,
    timeout: float,
) -> dict[str, Any] | None:
    local = _native_busybox(rootfs, busybox)
    if local is None:
        return None
    result = run_command([str(local), "echo", _QEMU_OK], timeout=timeout)
    load_ok = result.status == "success" and _QEMU_OK in result.stdout
    out: dict[str, Any] = {
        "status": "success" if load_ok else "failed",
        "qemu": None,
        "loader": "native",
        "busybox": str(local),
        "load_ok": load_ok,
        "command": result.command,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }
    if Path(rootfs, busybox).resolve() != local.resolve():
        out["limitation"] = (
            "native host busybox used; this proves local load, not "
            "target-architecture emulation"
        )
    return out


def run_l1_load_check(
    rootfs: str | Path,
    arch: str,
    *,
    busybox: str = "bin/busybox",
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Run the L1 load check for a target binary under QEMU user mode.

    On a host whose architecture matches the target, a native busybox is used
    when the rootfs does not contain one (or when QEMU is unavailable).

    Args:
        rootfs: Extracted root filesystem directory.
        arch: Canonical architecture (e.g. ``mips`` / ``mipsel`` / ``arm``).
        busybox: Relative path to busybox inside the rootfs.
        timeout: Max runtime in seconds.

    Returns:
        A dict with ``status`` (``success``/``skipped``/``failed``), ``qemu``
        (binary name or None), ``load_ok`` (bool or None), and the command
        output. A missing loader yields ``skipped`` with ``limitation``.
    """
    host_arch = _HOST_ARCH_ALIASES.get(platform.machine().lower())
    target_busybox = Path(rootfs) / busybox
    if host_arch == arch and not target_busybox.is_file():
        native = _native_load(rootfs, busybox, timeout)
        if native is not None:
            return native

    qemu = detect_qemu(arch)
    if qemu is None:
        if host_arch == arch:
            native = _native_load(rootfs, busybox, timeout)
            if native is not None:
                return native
        return {
            "status": "skipped",
            "qemu": None,
            "load_ok": None,
            "limitation": f"no QEMU user-mode binary for architecture {arch!r}",
        }

    # The '-static' variant needs no -L; the dynamic one needs the rootfs as
    # the sysroot. Using -L with a static binary is harmless, so keep it simple.
    cmd = [qemu, "-L", str(rootfs), str(Path(rootfs) / busybox), "echo", _QEMU_OK]
    result = run_command(cmd, timeout=timeout)
    load_ok = result.status == "success" and _QEMU_OK in result.stdout

    out: dict[str, Any] = {
        "status": "success" if load_ok else "failed",
        "qemu": qemu,
        "load_ok": load_ok,
        "command": result.command,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }
    # A /dev/mem exit is a known-harmless QEMU behaviour, not a load failure.
    if not load_ok and "dev/mem" in result.stderr:
        out["limitation"] = "binary exited at /dev/mem (expected QEMU behaviour)"
    return out
