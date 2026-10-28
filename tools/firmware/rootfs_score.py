"""Score candidate rootfs directories extracted from a firmware image.

The highest-scoring directory is selected, but all candidates are returned so
that downstream modules can handle ambiguous cases.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

MARKERS: dict[str, int] = {
    "has_bin": 1,
    "has_sbin": 1,
    "has_etc": 1,
    "has_lib": 1,
    "has_usr": 1,
    "has_web": 1,
    "has_initd": 1,
    "has_busybox": 1,
    "has_httpd": 2,
}


def _safe_exists(path: Path) -> bool:
    """Return whether a path exists without following broken/inaccessible links."""
    try:
        return path.exists() or path.is_symlink()
    except OSError:
        try:
            return path.is_symlink()
        except OSError:
            return False


def _safe_is_dir(path: Path) -> bool:
    """Directory check that tolerates firmware symlinks not resolvable on Windows."""
    try:
        return path.is_dir()
    except OSError:
        return False


def _safe_any_child(path: Path) -> bool:
    """Check whether a directory has children without letting bad links abort."""
    try:
        return _safe_is_dir(path) and any(path.iterdir())
    except OSError:
        return False


def _first_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if _safe_exists(path):
            return path
    return None


def _is_within(path: Path, parent: Path) -> bool:
    """Return True when ``path`` lives below ``parent``."""
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _related_paths(first: Path, second: Path) -> bool:
    """Return True when one path is the other or lives below it."""
    return _is_within(first, second) or _is_within(second, first)


def _score_directory(path: Path) -> dict[str, Any]:
    """Return score details for a single candidate directory."""
    score = 0
    markers: list[str] = []

    checks = [
        ("has_bin", [path / "bin"]),
        ("has_sbin", [path / "sbin"]),
        ("has_etc", [path / "etc", path / "etc_ro"]),
        ("has_lib", [path / "lib"]),
        ("has_usr", [path / "usr"]),
        ("has_busybox", [path / "bin" / "busybox"]),
        ("has_initd", [path / "etc" / "init.d", path / "etc_ro" / "init.d"]),
    ]

    for marker, targets in checks:
        target = _first_existing(targets)
        if target is None:
            continue
        if marker == "has_initd":
            # init.d must be non-empty to count.
            if _safe_any_child(target):
                score += MARKERS[marker]
                markers.append(marker)
        else:
            score += MARKERS[marker]
            markers.append(marker)

    # Web root markers
    web_dirs = [
        path / "www",
        path / "htdocs",
        path / "web",
        path / "usr" / "www",
        path / "webroot",
        path / "webroot_ro",
    ]
    if any(_safe_is_dir(d) for d in web_dirs):
        score += MARKERS["has_web"]
        markers.append("has_web")

    # HTTP daemon markers
    httpd_bins = [
        path / "usr" / "sbin" / "httpd",
        path / "bin" / "httpd",
        path / "usr" / "bin" / "goahead",
        path / "usr" / "sbin" / "goahead",
        path / "bin" / "goahead",
    ]
    if any(_safe_exists(b) for b in httpd_bins):
        score += MARKERS["has_httpd"]
        markers.append("has_httpd")

    return {
        "path": str(path.resolve()),
        "score": score,
        "markers": markers,
    }


def score_rootfs_candidates(extracted_dir: str | Path) -> dict[str, Any]:
    """Score all candidate rootfs directories under ``extracted_dir``.

    A directory is considered a candidate if it contains at least one of
    ``bin``, ``sbin``, ``etc``, ``lib``, or ``usr``.

    Returns:
        Dict with ``candidates`` (sorted by score desc), ``best``,
        ``extraction_confidence``, and ``threshold_met``.
    """
    root = Path(extracted_dir)
    if not root.exists():
        raise FileNotFoundError(f"Extracted directory not found: {root}")

    candidates: list[dict[str, Any]] = []
    for child in root.iterdir():
        if not child.is_dir():
            continue
        # Treat the root itself as a candidate if it has typical top-level dirs.
        has_top_level = any(
            _safe_is_dir(root / name) for name in ("bin", "sbin", "etc", "etc_ro", "lib", "usr")
        )
        if has_top_level and root not in [Path(c["path"]) for c in candidates]:
            candidates.append(_score_directory(root))
        if any(
            _safe_is_dir(child / name)
            for name in ("bin", "sbin", "etc", "etc_ro", "lib", "usr")
        ):
            candidates.append(_score_directory(child))

    # Deduplicate by path.
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for c in candidates:
        if c["path"] not in seen:
            seen.add(c["path"])
            unique.append(c)

    # A staging directory and a carved child can both look like a rootfs. Keep
    # only one representative of an ancestor/descendant pair: higher score
    # first, then the more specific (deeper) path.
    unique.sort(
        key=lambda item: (
            -int(item["score"]),
            -len(Path(item["path"]).parts),
            item["path"],
        )
    )
    kept: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    for candidate in unique:
        path = Path(candidate["path"])
        related = next(
            (item for item in kept if _related_paths(path, Path(item["path"]))),
            None,
        )
        if related is not None:
            suppressed.append(
                {
                    "path": candidate["path"],
                    "score": candidate["score"],
                    "reason": f"related to selected rootfs {related['path']}",
                }
            )
            continue
        kept.append(candidate)
    unique = kept
    # A staging root is suppressed in favour of its carved child, but unrelated
    # subdirectories such as out/usr can still look like weak candidates. Drop
    # low-score candidates that live inside a suppressed staging root; real
    # rootfs candidates score >= 5 and are preserved.
    if suppressed:
        suppressed_paths = [Path(item["path"]) for item in suppressed]
        retained: list[dict[str, Any]] = []
        for candidate in unique:
            path = Path(candidate["path"])
            inside_staging = any(
                path != staging and _is_within(path, staging)
                for staging in suppressed_paths
            )
            if inside_staging and int(candidate["score"]) < 5:
                suppressed.append(
                    {
                        "path": candidate["path"],
                        "score": candidate["score"],
                        "reason": "low-score directory inside a suppressed staging root",
                    }
                )
                continue
            retained.append(candidate)
        unique = retained
    best = unique[0] if unique else None
    confidence = 0.0
    if best:
        if best["score"] >= 7:
            confidence = 1.0
        elif best["score"] >= 5:
            confidence = 0.7
        else:
            confidence = 0.3

    return {
        "candidates": unique,
        "suppressed_candidates": suppressed,
        "best": best,
        "extraction_confidence": confidence,
        "threshold_met": best is not None and best["score"] >= 5,
    }


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m tools.firmware.rootfs_score <extracted_dir>")
        raise SystemExit(1)
    print(json.dumps(score_rootfs_candidates(sys.argv[1]), indent=2))
