"""Windows per-session single-instance guard with deterministic cleanup."""

from __future__ import annotations

import ctypes
import hashlib
import os
import threading
from ctypes import wintypes

_ERROR_ALREADY_EXISTS = 183


class SingleInstanceGuard:
    """Own a Windows named mutex for one interactive user session."""

    def __init__(self, identity: str = "ArubaSessionTracker") -> None:
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
        self._name = f"Local\\ArubaSessionTracker-{digest}"
        self._handle: int | None = None
        self._lock = threading.Lock()

    @property
    def acquired(self) -> bool:
        with self._lock:
            return self._handle is not None

    def acquire(self) -> bool:
        with self._lock:
            if self._handle is not None:
                return True
            if os.name != "nt":
                self._handle = -1
                return True
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
            kernel32.CreateMutexW.restype = wintypes.HANDLE
            handle = kernel32.CreateMutexW(None, True, self._name)
            if not handle:
                raise OSError(ctypes.get_last_error(), "CreateMutexW failed")
            last_error = ctypes.get_last_error()
            if last_error == _ERROR_ALREADY_EXISTS:
                kernel32.CloseHandle(handle)
                return False
            self._handle = int(handle)
            return True

    def release(self) -> None:
        with self._lock:
            handle = self._handle
            self._handle = None
        if handle is None or handle == -1 or os.name != "nt":
            return
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
        kernel32.ReleaseMutex.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.ReleaseMutex(wintypes.HANDLE(handle))
        kernel32.CloseHandle(wintypes.HANDLE(handle))

    def __enter__(self) -> SingleInstanceGuard:
        if not self.acquire():
            raise RuntimeError("application instance already exists")
        return self

    def __exit__(self, *_args: object) -> None:
        self.release()


__all__ = ["SingleInstanceGuard"]
