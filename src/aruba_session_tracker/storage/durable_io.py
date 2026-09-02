"""Small cross-platform durability helpers for atomic file publication."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import time
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

import aruba_session_tracker.storage.windows_file_metadata as windows_file_metadata

ReplaceCallable = Callable[[Path, Path], object]
_HASH_CHUNK_SIZE = 1024 * 1024
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
WINDOWS_FILE_RETRY_DELAYS = (0.0, 0.05, 0.1, 0.2, 0.4)
_TRANSIENT_WINDOWS_FILE_ERRORS = frozenset({5, 32, 33})


def replace_with_retry(
    source: Path,
    destination: Path,
    *,
    replace: ReplaceCallable = os.replace,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
    use_native_windows_identity: bool = False,
) -> None:
    """Replace ``destination`` with bounded retries for Windows sharing locks.

    Antivirus and indexing processes can briefly hold a just-written file on
    Windows.  Retrying only the known sharing/access failures avoids hiding
    path, permission, or integrity defects.

    Native 128-bit identity is opt-in for application-managed files. External
    FAT/exFAT destinations keep the CRT-compatible path because ``FileIdInfo``
    is not available on every Windows filesystem.
    """

    source = Path(os.path.abspath(source))
    destination = Path(os.path.abspath(destination))
    # Always fingerprint the actual staged bytes before the first publication
    # attempt.  Trusting a caller-supplied digest without comparing it here
    # would allow a same-sized corrupted staging file to be published.
    source_state = _capture_hashed_file_state(
        source,
        use_native_windows_identity=use_native_windows_identity,
    )
    source_sha = source_state.sha256 if expected_sha256 is None else expected_sha256
    if source_sha is None:  # pragma: no cover - defensive invariant
        raise OSError("atomic replace source fingerprint is unavailable")
    source_size = source_state.size if expected_size is None else expected_size
    if source_state.size != source_size or source_state.sha256 != source_sha:
        raise OSError("atomic replace source fingerprint differs from expected content")
    source_parent = _directory_state(source.parent)
    destination_parent = _directory_state(destination.parent)
    destination_state = (
        _capture_hashed_file_state(
            destination,
            use_native_windows_identity=use_native_windows_identity,
        )
        if os.path.lexists(destination)
        else None
    )
    for attempt, delay in enumerate(WINDOWS_FILE_RETRY_DELAYS):
        if delay:
            time.sleep(delay)
        try:
            # Revalidate every identity and fingerprint immediately before
            # every replace call, including the first. Transient Windows file
            # locks may affect these opens as well as the replace itself, but
            # the identity captured above stays fixed across every retry.
            _validate_directory_state(source.parent, source_parent)
            _validate_directory_state(destination.parent, destination_parent)
            _validate_file_state(
                source,
                source_state,
                expected_sha256=source_sha,
                expected_size=source_size,
                use_native_windows_identity=use_native_windows_identity,
            )
            _validate_destination_state(
                destination,
                destination_state,
                use_native_windows_identity=use_native_windows_identity,
            )
            if _can_use_windows_write_through(replace):
                _move_file_ex_write_through(source, destination)
            else:
                replace(source, destination)
            return
        except OSError as error:
            if attempt == len(WINDOWS_FILE_RETRY_DELAYS) - 1 or not (
                is_retryable_windows_file_operation_error(error)
            ):
                raise


def is_transient_windows_file_error(error: BaseException) -> bool:
    """Return whether Windows identified a bounded sharing/access collision."""

    return os.name == "nt" and getattr(error, "winerror", None) in (_TRANSIENT_WINDOWS_FILE_ERRORS)


def is_retryable_windows_file_operation_error(error: BaseException) -> bool:
    """Return whether one Windows file operation merits a bounded retry.

    CPython's Windows CRT-backed file operations can report a short-lived
    access denial only as ``PermissionError(errno.EACCES)`` without a Win32
    error code.  Accept that narrow representation for retry purposes, while
    keeping :func:`is_transient_windows_file_error` Win32-only so persistent
    errno-only permission failures retain their STORAGE_PATH classification.
    """

    if os.name != "nt":
        return False
    winerror = getattr(error, "winerror", None)
    if winerror is not None:
        return winerror in _TRANSIENT_WINDOWS_FILE_ERRORS
    return isinstance(error, PermissionError) and error.errno == errno.EACCES


def retry_windows_file_operation[ResultT](
    operation: Callable[[], ResultT],
    *,
    delays: tuple[float, ...] = WINDOWS_FILE_RETRY_DELAYS,
) -> ResultT:
    """Retry narrow Windows file-access collisions; fail closed otherwise."""

    if not delays:
        raise ValueError("at least one retry delay is required")
    for attempt, delay in enumerate(delays):
        if delay:
            time.sleep(delay)
        try:
            return operation()
        except OSError as error:
            if attempt == len(delays) - 1 or not (is_retryable_windows_file_operation_error(error)):
                raise
    raise AssertionError("Windows file retry loop did not return")  # pragma: no cover


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


def _file_state(
    path: Path,
    *,
    with_hash: bool,
    use_native_windows_identity: bool = False,
) -> _FileState:
    if use_native_windows_identity and windows_file_metadata.available():
        return _windows_file_state(path, with_hash=with_hash)
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


def _windows_file_state(path: Path, *, with_hash: bool) -> _FileState:
    if not with_hash:
        info = windows_file_metadata.from_path(path)
        _validate_windows_plain_file(info)
        return _file_state_from_windows(info, sha256=None)

    with path.open("rb") as stream:
        opened = windows_file_metadata.from_descriptor(stream.fileno())
        _validate_windows_plain_file(opened)
        digest, bytes_read = _hash_stream(stream)
        opened_after = windows_file_metadata.from_descriptor(stream.fileno())
    through_path = windows_file_metadata.from_path(path)
    _validate_windows_plain_file(opened_after)
    _validate_windows_plain_file(through_path)
    expected_state = _windows_file_state_key(opened)
    if (
        bytes_read != opened.file_size
        or _windows_file_state_key(opened_after) != expected_state
        or _windows_file_state_key(through_path) != expected_state
    ):
        raise OSError("atomic replace file changed while fingerprinting")
    return _file_state_from_windows(opened, sha256=digest)


def _validate_windows_plain_file(info: windows_file_metadata.WindowsFileMetadata) -> None:
    if info.identity == (0, 0):
        raise OSError("atomic replace file identity is unavailable")
    if not info.is_disk_file or info.is_reparse_point:
        raise OSError("atomic replace path is not a plain regular file")
    if info.number_of_links != 1:
        raise OSError("atomic replace path must have exactly one hard link")


def _windows_file_state_key(
    info: windows_file_metadata.WindowsFileMetadata,
) -> tuple[int, int, int, int]:
    return (*info.identity, info.modified_ns, info.file_size)


def _file_state_from_windows(
    info: windows_file_metadata.WindowsFileMetadata,
    *,
    sha256: str | None,
) -> _FileState:
    return _FileState(
        device=info.volume_serial_number,
        inode=info.file_index,
        modified_ns=info.modified_ns,
        sha256=sha256,
        size=info.file_size,
    )


def _capture_hashed_file_state(
    path: Path,
    *,
    use_native_windows_identity: bool = False,
) -> _FileState:
    """Fingerprint one fixed file identity across transient Windows opens."""

    initial = retry_windows_file_operation(
        lambda: _file_state(
            path,
            with_hash=False,
            use_native_windows_identity=use_native_windows_identity,
        )
    )

    def capture() -> _FileState:
        current = _file_state(
            path,
            with_hash=True,
            use_native_windows_identity=use_native_windows_identity,
        )
        if (
            current.device,
            current.inode,
            current.modified_ns,
            current.size,
        ) != (
            initial.device,
            initial.inode,
            initial.modified_ns,
            initial.size,
        ):
            raise OSError("atomic replace file identity changed while fingerprinting")
        return current

    return retry_windows_file_operation(capture)


def _validate_file_state(
    path: Path,
    expected: _FileState,
    *,
    expected_sha256: str,
    expected_size: int,
    use_native_windows_identity: bool = False,
) -> None:
    current = _file_state(
        path,
        with_hash=True,
        use_native_windows_identity=use_native_windows_identity,
    )
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


def _validate_destination_state(
    path: Path,
    expected: _FileState | None,
    *,
    use_native_windows_identity: bool = False,
) -> None:
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
        use_native_windows_identity=use_native_windows_identity,
    )


def _hash_file(path: Path) -> str:
    with path.open("rb") as stream:
        digest, _size = _hash_stream(stream)
    return digest


def _hash_stream(stream: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while chunk := stream.read(_HASH_CHUNK_SIZE):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


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
