"""Native Windows metadata for identity-sensitive file handles.

Python's Windows ``stat`` implementation can expose different inode values for
path and descriptor queries on some filesystems. Managed-file safety checks need
both queries to use the same native identity source, so this module reads
128-bit ``FileIdInfo`` plus ``BY_HANDLE_FILE_INFORMATION`` for each handle.
"""

from __future__ import annotations

import ctypes
import errno
import os
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ID_INFO_CLASS = 18
_FILE_READ_ATTRIBUTES = 0x0080
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_FILE_TYPE_DISK = 0x0001
_OPEN_EXISTING = 3
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = (
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    )


class _FileId128(ctypes.Structure):
    _fields_ = (("Identifier", ctypes.c_ubyte * 16),)


class _FileIdInformation(ctypes.Structure):
    _fields_ = (
        ("VolumeSerialNumber", ctypes.c_ulonglong),
        ("FileId", _FileId128),
    )


@dataclass(frozen=True, slots=True)
class WindowsFileMetadata:
    """Security-relevant metadata returned for one native file handle."""

    volume_serial_number: int
    file_index: int
    number_of_links: int
    file_attributes: int
    file_size: int
    modified_ns: int = 0
    file_type: int = _FILE_TYPE_DISK

    @property
    def identity(self) -> tuple[int, int]:
        return self.volume_serial_number, self.file_index

    @property
    def is_directory(self) -> bool:
        return bool(self.file_attributes & _FILE_ATTRIBUTE_DIRECTORY)

    @property
    def is_reparse_point(self) -> bool:
        return bool(self.file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT)

    @property
    def is_disk_file(self) -> bool:
        return self.file_type == _FILE_TYPE_DISK and not self.is_directory


def available() -> bool:
    """Return whether native Windows file metadata can be queried."""

    return os.name == "nt"


def from_descriptor(descriptor: int) -> WindowsFileMetadata:
    """Read metadata for an already-open CRT file descriptor."""

    if not available():
        raise OSError(errno.ENOSYS, "native Windows file metadata is unavailable")
    import msvcrt

    get_osfhandle: Any = _required_attribute(msvcrt, "get_osfhandle")
    handle = int(get_osfhandle(descriptor))
    if handle == -1:
        raise OSError(errno.EBADF, "invalid Windows file descriptor")
    return _from_handle(handle)


def from_path(path: Path) -> WindowsFileMetadata:
    """Open *path* itself, without traversing its final reparse point."""

    if not available():
        raise OSError(errno.ENOSYS, "native Windows file metadata is unavailable")
    kernel32 = _kernel32()
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        _extended_path(path),
        _FILE_READ_ATTRIBUTES,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise _win_error()
    try:
        return _from_handle(int(handle))
    finally:
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        if not close_handle(handle):
            raise _win_error()


def _from_handle(handle: int) -> WindowsFileMetadata:
    kernel32 = _kernel32()
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    )
    get_information.restype = wintypes.BOOL
    information = _ByHandleFileInformation()
    if not get_information(wintypes.HANDLE(handle), ctypes.byref(information)):
        raise _win_error()

    get_extended_information = kernel32.GetFileInformationByHandleEx
    get_extended_information.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    get_extended_information.restype = wintypes.BOOL
    identity_information = _FileIdInformation()
    if not get_extended_information(
        wintypes.HANDLE(handle),
        _FILE_ID_INFO_CLASS,
        ctypes.byref(identity_information),
        ctypes.sizeof(identity_information),
    ):
        # The target is Windows 11. Falling back to the legacy 64-bit file
        # index would make distinct ReFS files potentially indistinguishable,
        # so an unavailable 128-bit identity must fail closed.
        raise _win_error()

    get_file_type = kernel32.GetFileType
    get_file_type.argtypes = (wintypes.HANDLE,)
    get_file_type.restype = wintypes.DWORD
    set_last_error: Any = _required_attribute(ctypes, "set_last_error")
    get_last_error: Any = _required_attribute(ctypes, "get_last_error")
    set_last_error(0)
    file_type = int(get_file_type(wintypes.HANDLE(handle)))
    if file_type == 0:
        last_error = int(get_last_error())
        if last_error:
            raise _win_error(last_error)

    return WindowsFileMetadata(
        volume_serial_number=int(identity_information.VolumeSerialNumber),
        file_index=int.from_bytes(bytes(identity_information.FileId.Identifier), "little"),
        number_of_links=int(information.nNumberOfLinks),
        file_attributes=int(information.dwFileAttributes),
        file_size=(int(information.nFileSizeHigh) << 32) | int(information.nFileSizeLow),
        modified_ns=_filetime_ns(information.ftLastWriteTime),
        file_type=file_type,
    )


def _filetime_ns(value: wintypes.FILETIME) -> int:
    """Convert a Windows FILETIME to Unix-epoch nanoseconds."""

    ticks_100ns = (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)
    return (ticks_100ns - 116_444_736_000_000_000) * 100


def _kernel32() -> Any:
    win_dll: Any = _required_attribute(ctypes, "WinDLL")
    return win_dll("kernel32", use_last_error=True)


def _win_error(code: int | None = None) -> OSError:
    get_last_error: Any = _required_attribute(ctypes, "get_last_error")
    win_error: Any = _required_attribute(ctypes, "WinError")
    return cast(OSError, win_error(int(get_last_error()) if code is None else code))


def _required_attribute(module: object, name: str) -> Any:
    return getattr(module, name)


def _extended_path(path: Path) -> str:
    absolute = str(Path(os.path.abspath(path))).replace("/", "\\")
    if absolute.startswith("\\\\?\\"):
        return absolute
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute.removeprefix("\\\\")
    return "\\\\?\\" + absolute


__all__ = ["WindowsFileMetadata", "available", "from_descriptor", "from_path"]
