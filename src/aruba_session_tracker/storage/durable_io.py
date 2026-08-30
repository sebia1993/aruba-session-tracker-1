"""Small cross-platform durability helpers for atomic file publication."""

from __future__ import annotations

import hashlib
import os
import stat
import time
from collections.abc import Callable
from pathlib import Path

ReplaceCallable = Callable[[Path, Path], object]
_HASH_CHUNK_SIZE = 1024 * 1024
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def replace_with_retry(
    source: Path,
    destination: Path,
    *,
    replace: ReplaceCallable = os.replace,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
) -> None:
    """Replace ``destination`` with bounded retries for Windows sharing locks.

    Antivirus and indexing processes can briefly hold a just-written file on
    Windows.  Retrying only the known sharing/access failures avoids hiding
    path, permission, or integrity defects.
    """

    source = Path(os.path.abspath(source))
    destination = Path(os.path.abspath(destination))
    # Always fingerprint the actual staged bytes before the first publication
    # attempt.  Trusting a caller-supplied digest without comparing it here
    # would allow a same-sized corrupted staging file to be published.
    source_state = _file_state(source, with_hash=True)
    source_sha = source_state.sha256 if expected_sha256 is None else expected_sha256
    if source_sha is None:  # pragma: no cover - defensive invariant
        raise OSError("atomic replace source fingerprint is unavailable")
    source_size = source_state.size if expected_size is None else expected_size
    if source_state.size != source_size or source_state.sha256 != source_sha:
        raise OSError("atomic replace source fingerprint differs from expected content")
    source_parent = _directory_state(source.parent)
    destination_parent = _directory_state(destination.parent)
    destination_state = (
        _file_state(destination, with_hash=True) if os.path.lexists(destination) else None
    )
    delays = (0.0, 0.05, 0.1, 0.2, 0.4)
    for attempt, delay in enumerate(delays):
        if delay:
            time.sleep(delay)
        # Revalidate every identity and fingerprint immediately before every
        # replace call, including the first.  This closes the gap between the
        # initial capture and publication as well as every retry delay.
        _validate_directory_state(source.parent, source_parent)
        _validate_directory_state(destination.parent, destination_parent)
        _validate_file_state(
            source,
            source_state,
            expected_sha256=source_sha,
            expected_size=source_size,
        )
        _validate_destination_state(destination, destination_state)
        try:
            if _can_use_windows_write_through(replace):
                _move_file_ex_write_through(source, destination)
            else:
                replace(source, destination)
            return
        except OSError as error:
            if attempt == len(delays) - 1 or not _retryable_replace_error(error):
                raise


def _retryable_replace_error(error: OSError) -> bool:
    if os.name != "nt":
        return False
    winerror = getattr(error, "winerror", None)
    return winerror in {5, 32, 33} or (winerror is None and isinstance(error, PermissionError))


class _FileState:
    __slots__ = ("device", "inode", "modified_ns", "sha256", "size")

    def __init__(
        self,
        *,
        device: int,
        inode: int,
        modified_ns: int,
        sha256: str | None,
        size: int,
    ) -> None:
        self.device = device
        self.inode = inode
        self.modified_ns = modified_ns
        self.sha256 = sha256
        self.size = size


class _DirectoryState:
    __slots__ = ("device", "inode")

    def __init__(self, *, device: int, inode: int) -> None:
        self.device = device
        self.inode = inode


def _directory_state(path: Path) -> _DirectoryState:
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or _is_reparse(info):
        raise OSError("atomic replace parent is not a plain directory")
    return _DirectoryState(device=int(info.st_dev), inode=int(info.st_ino))


def _validate_directory_state(path: Path, expected: _DirectoryState) -> None:
    current = _directory_state(path)
    if (current.device, current.inode) != (expected.device, expected.inode):
        raise OSError("atomic replace parent identity changed during retry")


def _file_state(path: Path, *, with_hash: bool) -> _FileState:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or _is_reparse(info):
        raise OSError("atomic replace path is not a plain regular file")
    digest = _hash_file(path) if with_hash else None
    after = os.lstat(path)
    before_identity = (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
    )
    after_identity = (
        int(after.st_dev),
        int(after.st_ino),
        int(after.st_size),
        int(after.st_mtime_ns),
    )
    if before_identity != after_identity or _is_reparse(after):
        raise OSError("atomic replace file changed while fingerprinting")
    return _FileState(
        device=int(info.st_dev),
        inode=int(info.st_ino),
        modified_ns=int(info.st_mtime_ns),
        sha256=digest,
        size=int(info.st_size),
    )


def _validate_file_state(
    path: Path,
    expected: _FileState,
    *,
    expected_sha256: str,
    expected_size: int,
) -> None:
    current = _file_state(path, with_hash=True)
    if (
        current.device,
        current.inode,
        current.modified_ns,
        current.size,
        current.sha256,
    ) != (
        expected.device,
        expected.inode,
        expected.modified_ns,
        expected_size,
        expected_sha256,
    ):
        raise OSError("atomic replace source identity or fingerprint changed during retry")


def _validate_destination_state(path: Path, expected: _FileState | None) -> None:
    if expected is None:
        if os.path.lexists(path):
            raise OSError("atomic replace destination appeared during retry")
        return
    if not os.path.lexists(path):
        raise OSError("atomic replace destination disappeared during retry")
    assert expected.sha256 is not None
    _validate_file_state(
        path,
        expected,
        expected_sha256=expected.sha256,
        expected_size=expected.size,
    )


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_HASH_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT)


def _can_use_windows_write_through(replace: ReplaceCallable) -> bool:
    return (
        os.name == "nt"
        and getattr(replace, "__module__", None) == "nt"
        and getattr(replace, "__name__", None) == "replace"
    )


def _move_file_ex_write_through(source: Path, destination: Path) -> None:
    import ctypes

    move_file_ex = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
    move_file_ex.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
    move_file_ex.restype = ctypes.c_int
    replace_existing = 0x1
    write_through = 0x8
    if not move_file_ex(
        _extended_windows_path(source),
        _extended_windows_path(destination),
        replace_existing | write_through,
    ):
        raise ctypes.WinError(ctypes.get_last_error())


def _extended_windows_path(path: Path) -> str:
    absolute = str(Path(os.path.abspath(path))).replace("/", "\\")
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute.removeprefix("\\\\")
    return "\\\\?\\" + absolute
