"""Build a small intentionally vulnerable firmware fixture for local testing."""

from __future__ import annotations

import argparse
import json
import shutil
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "tests" / "fixtures" / "lab_firmware" / "lab_httpd.c"
DESCRIPTION = ROOT / "tests" / "fixtures" / "lab_firmware" / "README.md"


def run_checked(command: list[str], *, cwd: Path | None = None) -> None:
    """Run a local build command and raise a useful error on failure."""
    result = subprocess.run(command, cwd=cwd, check=False, text=True)
    if result.returncode != 0:
        raise SystemExit(f"build command failed ({result.returncode}): {' '.join(command)}")


def write_text(path: Path, content: str, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def build(output_dir: Path) -> dict[str, str | int | list[dict[str, str]]]:
    """Build the rootfs and, when available, a SquashFS firmware image."""
    output_dir = output_dir.resolve()
    samples_root = (ROOT / "firmware_samples").resolve()
    if not output_dir.is_relative_to(samples_root):
        raise SystemExit(f"output directory must stay under {samples_root}")
    rootfs = output_dir / "rootfs"
    if rootfs.exists():
        shutil.rmtree(rootfs)
    rootfs.mkdir(parents=True)

    binary = rootfs / "usr" / "sbin" / "lab_httpd"
    source_copy = rootfs / "usr" / "src" / "lab_httpd.c"
    binary.parent.mkdir(parents=True, exist_ok=True)
    run_checked(
        [
            "gcc",
            "-O0",
            "-g",
            "-fno-stack-protector",
            "-fno-omit-frame-pointer",
            "-no-pie",
            str(SOURCE),
            "-o",
            str(binary),
        ]
    )
    source_copy.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SOURCE, source_copy)

    write_text(
        rootfs / "etc" / "init.d" / "rcS",
        "#!/bin/sh\n/usr/sbin/lab_httpd all &\n",
        executable=True,
    )
    write_text(
        rootfs / "www" / "cgi-bin" / "ping.cgi",
        "#!/bin/sh\n# Intentional fixture: shell input reaches eval.\n"
        "eval \"ping -c 1 $QUERY_STRING\"\n",
        executable=True,
    )
    write_text(
        rootfs / "www" / "cgi-bin" / "download.cgi",
        "#!/bin/sh\n# Intentional fixture: no path allow-list.\n"
        "cat \"/tmp/downloads/$DOWNLOAD_NAME\"\n",
        executable=True,
    )
    write_text(rootfs / "etc" / "passwd", "root:x:0:0:root:/root:/bin/sh\n")
    write_text(rootfs / "www" / "index.html", "<html><title>FirmHound Lab</title></html>\n")
    (rootfs / "usr" / "share").mkdir(parents=True, exist_ok=True)
    shutil.copy2(DESCRIPTION, rootfs / "usr" / "share" / "firmhound-lab.md")

    findings = [
        {"id": "lab-cmdi-1", "class": "command_injection", "sink": "system",
         "source": "QUERY_STRING"},
        {"id": "lab-overflow-1", "class": "overflow", "sink": "strcpy", "source": "DIAG"},
        {"id": "lab-format-1", "class": "format_string", "sink": "printf", "source": "LOG_FORMAT"},
        {"id": "lab-path-1", "class": "path_traversal", "sink": "fopen", "source": "DOWNLOAD_NAME"},
        {"id": "lab-overflow-2", "class": "overflow", "sink": "strcpy",
         "source": "COPY_VALUE"},
        {"id": "lab-cmdi-2", "class": "command_injection", "sink": "eval",
         "source": "QUERY_STRING"},
    ]
    metadata = {
        "name": "firmhound-lab-firmware",
        "version": "0.1.0",
        "purpose": "local regression and analyzer integration fixture",
        "architecture": "x86_64",
        "rootfs": "rootfs",
        "source": "tests/fixtures/lab_firmware/lab_httpd.c",
        "expected_findings": findings,
        "safety": "intentionally vulnerable; offline only; no network listener",
    }
    (output_dir / "lab_firmware.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    image = output_dir.parent / "firmhound-lab-0.1.0.squashfs"
    mksquashfs = shutil.which("mksquashfs")
    if mksquashfs:
        run_checked([mksquashfs, str(rootfs), str(image), "-noappend", "-quiet"])

    return {
        "rootfs": str(rootfs),
        "image": str(image) if image.exists() else "",
        "findings": len(findings),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default=str(ROOT / "firmware_samples" / "firmhound-lab-0.1.0"),
        help="directory for the generated rootfs and metadata",
    )
    args = parser.parse_args()
    result = build(Path(args.output_dir))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
