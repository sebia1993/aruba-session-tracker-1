"""Shared Windows bundle path and component-selection rules."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import PurePosixPath

NATIVE_SUFFIXES = frozenset({".dll", ".exe", ".pyd"})


def safe_bundle_path(value: str, *, field: str) -> PurePosixPath:
    """Return a canonical relative bundle path or glob."""

    if "\\" in value:
        raise ValueError(f"component manifest {field} must use forward slashes: {value}")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe component manifest {field}: {value}")
    return path


def bundle_pattern_matches(path: str, pattern: str) -> bool:
    """Match Windows bundle paths with one case-insensitive POSIX-glob rule."""

    safe_bundle_path(path, field="bundle path")
    safe_bundle_path(pattern, field="glob")
    return PurePosixPath(path.casefold()).full_match(pattern.casefold())


def canonical_bundle_paths(paths: Iterable[str]) -> dict[str, str]:
    """Index paths case-insensitively and reject Windows-name collisions."""

    indexed: dict[str, str] = {}
    for value in paths:
        normalized = safe_bundle_path(value, field="bundle path").as_posix()
        folded = normalized.casefold()
        previous = indexed.setdefault(folded, normalized)
        if previous != normalized:
            raise ValueError(
                f"bundle contains case-insensitive path collision: {previous} / {normalized}"
            )
    return indexed


def select_component_paths(
    all_paths: Iterable[str],
    *,
    files: Iterable[str],
    globs: Iterable[str],
    exclude_globs: Iterable[str],
    field: str,
) -> set[str]:
    """Resolve exact paths and globs against the same case-insensitive index."""

    indexed = canonical_bundle_paths(all_paths)
    selected: set[str] = set()
    for value in files:
        relative = safe_bundle_path(value, field=f"{field}.files").as_posix()
        actual = indexed.get(relative.casefold())
        if actual is None:
            raise ValueError(f"declared bundle file is missing: {relative}")
        selected.add(actual)
    patterns = tuple(safe_bundle_path(value, field=f"{field}.globs").as_posix() for value in globs)
    excluded = tuple(
        safe_bundle_path(value, field=f"{field}.exclude_globs").as_posix()
        for value in exclude_globs
    )
    selected.update(
        actual
        for actual in indexed.values()
        if any(bundle_pattern_matches(actual, pattern) for pattern in patterns)
    )
    selected.difference_update(
        actual
        for actual in tuple(selected)
        if any(bundle_pattern_matches(actual, pattern) for pattern in excluded)
    )
    return selected


def native_bundle_paths(paths: Iterable[str]) -> set[str]:
    """Return every Windows executable/native library path, case-insensitively."""

    indexed = canonical_bundle_paths(paths)
    return {
        actual
        for actual in indexed.values()
        if PurePosixPath(actual).suffix.casefold() in NATIVE_SUFFIXES
    }


def paths_matching_patterns(paths: Iterable[str], patterns: Iterable[str]) -> set[str]:
    """Return paths matching any shared case-insensitive bundle glob."""

    indexed = canonical_bundle_paths(paths)
    checked = tuple(safe_bundle_path(value, field="policy glob").as_posix() for value in patterns)
    return {
        actual
        for actual in indexed.values()
        if any(bundle_pattern_matches(actual, pattern) for pattern in checked)
    }
