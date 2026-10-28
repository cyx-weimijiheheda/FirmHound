"""Firmware unpacking dispatcher.

Routes a firmware image to the right extraction strategy based on signatures
and falls back to carving when needed.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from fsa.safety.policy_engine import PolicyEngine
from fsa.utils.proc import run_command

OPENSSL_SALTED_MAGIC = b"Salted__"

# Map from binwalk description keyword to extraction strategy.
#
# SquashFS is one strategy, not two: the compression variant is not knowable
# from the keyword alone (binwalk reports "SquashFS file system", the legacy
# 3.x table says "Squashfs filesystem", and the compression field is a
# separate column), so the tool chain simply tries the tools in order of
# quality. unsquashfs 4.6+ handles lzma, sasquatch covers the vendor-patched
# variants it cannot, and 7z is the last resort. Splitting this on a
# "lzma" keyword used to send standard images down a path with no usable
# extractor at all.
STRATEGIES: list[dict[str, Any]] = [
    {
        "name": "squashfs",
        "keywords": ["squashfs"],
        "tools": [
            ["unsquashfs", "-d", "{out}", "{fw}"],
            ["sasquatch", "-d", "{out}", "{fw}"],
            ["7z", "x", "-o{out}", "{fw}"],
        ],
    },
    {
        "name": "ubi",
        "keywords": ["ubi"],
        "tools": [["ubireader_extract_images", "-o", "{out}", "{fw}"]],
    },
    {
        "name": "jffs2",
        "keywords": ["jffs2"],
        "tools": [["jefferson", "-d", "{out}", "{fw}"]],
    },
    {
        "name": "cpio",
        "keywords": ["cpio"],
        "tools": [["cpio", "-idmv", "-D", "{out}"]],
    },
    {
        "name": "gzip",
        "keywords": ["gzip"],
        "tools": [["gzip", "-dc", "{fw}"]],
    },
]


def _normalize_tool_args(args: list[str], fw: Path, out: Path) -> list[str]:
    """Replace {fw}/{out} placeholders in command arguments."""
    return [arg.replace("{fw}", str(fw)).replace("{out}", str(out)) for arg in args]


def _dir_has_entries(path: Path) -> bool:
    return path.is_dir() and any(path.iterdir())


def _prepare_output_dir(binary: str, out: Path) -> None:
    """Prepare extractor output path according to tool behavior."""
    if binary in {"unsquashfs", "sasquatch"}:
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.is_dir() and not _dir_has_entries(out):
            out.rmdir()
        return
    out.mkdir(parents=True, exist_ok=True)


def _check_extractors() -> dict[str, bool]:
    """Check which external extractors are available on PATH."""
    names = [
        "unsquashfs",
        "sasquatch",
        "7z",
        "ubireader_extract_images",
        "jefferson",
        "cpio",
        "binwalk",
    ]
    return {name: shutil.which(name) is not None for name in names}


def _detect_strategy(signatures: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Choose extraction strategy based on binwalk signatures."""
    descriptions = " ".join(sig.get("description", "").lower() for sig in signatures)
    for strategy in STRATEGIES:
        if all(kw.lower() in descriptions for kw in strategy["keywords"]):
            return strategy
    return None


def _extract_with_strategy(
    fw: Path,
    out: Path,
    strategy: dict[str, Any],
) -> dict[str, Any]:
    """Try each tool chain in the strategy until one succeeds."""
    available = _check_extractors()
    attempts: list[dict[str, Any]] = []
    for tool_chain in strategy["tools"]:
        cmd = _normalize_tool_args(tool_chain, fw, out)
        binary = cmd[0]
        if binary not in ("dd", "gzip") and not available.get(binary):
            attempts.append(
                {"command": " ".join(cmd), "status": "skipped", "reason": "tool not found"}
            )
            continue

        _prepare_output_dir(binary, out)
        result = run_command(cmd, timeout=300)
        status = result.status
        populated = binary in {"unsquashfs", "sasquatch"} and _dir_has_entries(out)
        degraded = False
        degraded_reason: str | None = None
        if binary in {"unsquashfs", "sasquatch"}:
            if status == "success" and not populated:
                status = "failed"
                degraded_reason = "extractor reported success but produced no files"
            elif status == "failed" and populated:
                # unsquashfs/sasquatch commonly exit non-zero after extracting
                # everything when running unprivileged and unable to recreate
                # device nodes or special files. The tree is still usable.
                status = "success"
                degraded = True
                degraded_reason = (
                    "extractor exited non-zero but produced files; "
                    "device-node/symlink creation errors are non-fatal"
                )
            # A timeout may mean a truncated tree; keep it failed so the carve
            # path can try again instead of silently accepting partial data.
        attempt: dict[str, Any] = {
            "command": result.command,
            "status": status,
            "returncode": result.returncode,
            "stderr_tail": result.stderr[-500:],
        }
        if degraded:
            attempt["degraded"] = True
            attempt["degraded_reason"] = degraded_reason
        attempts.append(attempt)
        if status == "success":
            payload: dict[str, Any] = {
                "status": "success",
                "method": strategy["name"],
                "attempts": attempts,
            }
            if any(item.get("degraded") for item in attempts):
                payload["degraded"] = True
                payload["degraded_reason"] = degraded_reason
            return payload
    return {"status": "failed", "method": strategy["name"], "attempts": attempts}


CARVE_TARGETS: list[dict[str, Any]] = [
    {
        "magic": b"hsqs",
        "kind": "squashfs",
        "strategies": ["squashfs"],
        "max_hits": 16,
    },
    {
        "magic": b"sqsh",
        "kind": "squashfs",
        "strategies": ["squashfs"],
        "max_hits": 16,
    },
    {
        "magic": b"UBI#",
        "kind": "ubi",
        "strategies": ["ubi"],
        "max_hits": 8,
    },
    {
        "magic": b"\x1f\x8b",
        "kind": "gzip",
        "strategies": [],
        "max_hits": 8,
    },
]


def _iter_magic_offsets(data: bytes, magic: bytes, *, max_hits: int) -> list[int]:
    """Return bounded offsets for a byte signature without quadratic scanning."""
    offsets: list[int] = []
    start = 0
    while len(offsets) < max_hits:
        found = data.find(magic, start)
        if found < 0:
            break
        offsets.append(found)
        start = found + 1
    return offsets


def _strategy_by_name(name: str) -> dict[str, Any] | None:
    for strategy in STRATEGIES:
        if strategy["name"] == name:
            return strategy
    return None


def _try_extract_carved_slice(
    slice_path: Path,
    out: Path,
    *,
    kind: str,
    offset: int,
    strategy_names: list[str],
) -> dict[str, Any] | None:
    """Try filesystem extractors on a carved inner image."""
    extraction_attempts: list[dict[str, Any]] = []
    for name in strategy_names:
        strategy = _strategy_by_name(name)
        if strategy is None:
            continue
        extract_dir = out / f"carved_{kind}_{offset}_{name}"
        result = _extract_with_strategy(slice_path, extract_dir, strategy)
        extraction_attempts.append(
            {
                "strategy": name,
                "status": result["status"],
                "output_dir": str(extract_dir),
                "attempts": result.get("attempts", []),
            }
        )
        if result["status"] == "success":
            return {
                "status": "success",
                "extracted_to": str(extract_dir),
                "strategy": name,
                "attempts": extraction_attempts,
            }
    if extraction_attempts:
        return {"status": "failed", "attempts": extraction_attempts}
    return None


def _encrypted_signatures(signatures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return binwalk signatures that indicate an encrypted payload."""
    encrypted: list[dict[str, Any]] = []
    for sig in signatures:
        description = sig.get("description", "").lower()
        if "openssl encryption" in description or "encrypted" in description:
            encrypted.append(sig)
    return encrypted


def _record_encrypted_payloads(
    fw: Path,
    out: Path,
    signatures: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Persist encrypted payload slices for manual or configured decryption."""
    encrypted = _encrypted_signatures(signatures)
    if not encrypted:
        return None
    out.mkdir(parents=True, exist_ok=True)
    attempts: list[dict[str, Any]] = []
    with fw.open("rb") as fh:
        data = fh.read()
    for sig in encrypted:
        offset = int(sig.get("offset", 0))
        if offset < 0 or offset >= len(data):
            continue
        payload = data[offset:]
        marker = payload[: len(OPENSSL_SALTED_MAGIC)]
        slice_path = out / f"encrypted_openssl_{offset}.bin"
        with slice_path.open("wb") as wh:
            wh.write(payload)
        attempts.append(
            {
                "offset": offset,
                "offset_hex": sig.get("offset_hex"),
                "description": sig.get("description"),
                "slice": str(slice_path),
                "format": "openssl-salted" if marker == OPENSSL_SALTED_MAGIC else "unknown",
                "status": "needs_decryption_material",
            }
        )
    if not attempts:
        return None
    return {
        "status": "degraded",
        "method": "encrypted_payload_detection",
        "reason": (
            "OpenSSL-style encrypted firmware payload detected; provide the vendor "
            "decryption password/key through configured .env material or decrypt "
            "the recorded slice before filesystem extraction."
        ),
        "attempts": attempts,
    }


def _carve_fallback(
    fw: Path,
    out: Path,
    *,
    skip_kinds: set[str] | None = None,
    skip_zero_kinds: set[str] | None = None,
) -> dict[str, Any]:
    """Fallback: scan for embedded filesystems, carve slices, then extract them.

    Some vendor images hide a normal SquashFS/UBI payload behind TRX/uImage/custom
    headers. Binwalk can identify those offsets, but when full-image extraction
    fails we still need to recover the filesystem by carving from the inner magic
    and retrying the proper extractor on that slice.

    ``skip_zero_kinds`` avoids carving offset 0 for a kind whose whole-file
    extraction was already attempted; the slice would be byte-identical and
    would create a second rootfs candidate. Stop after the first successful
    extraction because one usable rootfs is enough for the pipeline.
    """
    out.mkdir(parents=True, exist_ok=True)
    attempts: list[dict[str, Any]] = []
    skip_zero_kinds = set(skip_zero_kinds or ())

    with fw.open("rb") as fh:
        data = fh.read()

    carved_any = False
    for target in CARVE_TARGETS:
        magic = target["magic"]
        kind = target["kind"]
        if skip_kinds and kind in skip_kinds:
            continue
        offsets = _iter_magic_offsets(data, magic, max_hits=target["max_hits"])
        for offset in offsets:
            if offset == 0 and kind in skip_zero_kinds:
                attempts.append(
                    {
                        "offset": offset,
                        "kind": kind,
                        "status": "skipped",
                        "reason": "whole-file extraction with this kind was already attempted",
                    }
                )
                continue
            slice_path = out / f"carved_{kind}_{offset}.bin"
            with slice_path.open("wb") as wh:
                wh.write(data[offset:])
            carved_any = True
            attempt: dict[str, Any] = {
                "offset": offset,
                "kind": kind,
                "slice": str(slice_path),
                "status": "carved",
            }
            extraction = _try_extract_carved_slice(
                slice_path,
                out,
                kind=kind,
                offset=offset,
                strategy_names=target["strategies"],
            )
            if extraction is not None:
                attempt["extraction"] = extraction
                if extraction["status"] == "success":
                    attempt["status"] = "extracted"
                    attempts.append(attempt)
                    return {
                        "status": "success",
                        "method": "carve_fallback",
                        "attempts": attempts,
                        "stopped_after_first": True,
                    }
            attempts.append(attempt)

    return {
        "status": "partial" if carved_any else "failed",
        "method": "carve_fallback",
        "attempts": attempts,
    }


def unpack(
    firmware_path: str | Path,
    output_dir: str | Path,
    *,
    policy: PolicyEngine | None = None,
) -> dict[str, Any]:
    """Unpack a firmware image into ``output_dir``.

    Args:
        firmware_path: Path to the firmware file.
        output_dir: Directory where extracted contents should be placed.
        policy: Optional safety policy engine to validate paths.

    Returns:
        Dict with ``status``, ``method``, ``output_dir``, and ``attempts``.
    """
    fw = Path(firmware_path).resolve()
    out = Path(output_dir).resolve()

    if policy is not None:
        policy.check_path(out)

    if not fw.exists():
        raise FileNotFoundError(f"Firmware not found: {fw}")

    # Collect binwalk signatures to choose strategy when binwalk is available.
    from tools.firmware.collect_info import _binwalk_signatures

    signatures = _binwalk_signatures(fw)
    encrypted = _record_encrypted_payloads(fw, out, signatures)
    strategy = _detect_strategy(signatures)

    if strategy and any(shutil.which(cmd[0]) for cmd in strategy["tools"]):
        result = _extract_with_strategy(fw, out, strategy)
    else:
        result = {
            "status": "failed",
            "method": strategy["name"] if strategy else None,
            "attempts": [],
            "reason": "no matching strategy or extractors unavailable",
        }
    if encrypted is not None:
        result["encrypted"] = encrypted

    if result["status"] != "success":
        skip_zero_kinds: set[str] = set()
        if strategy and result.get("attempts"):
            full_kind = str(strategy.get("name", ""))
            if full_kind in {item["kind"] for item in CARVE_TARGETS}:
                skip_zero_kinds.add(full_kind)
        carve = _carve_fallback(
            fw,
            out,
            skip_kinds={"gzip"} if encrypted is not None else None,
            skip_zero_kinds=skip_zero_kinds,
        )
        result["fallback"] = carve
        if carve["status"] in {"success", "partial"}:
            result["status"] = carve["status"]

    result["extraction_degraded"] = bool(result.get("degraded", False))
    result["output_dir"] = str(out)
    result["binwalk_signatures"] = signatures
    return result


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 3:
        print("Usage: python -m tools.firmware.unpack <firmware> <output_dir>")
        raise SystemExit(1)
    result = unpack(sys.argv[1], sys.argv[2])
    print(json.dumps(result, indent=2))
