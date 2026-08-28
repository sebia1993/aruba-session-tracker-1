"""Strict, atomic persistence for non-secret application settings."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from aruba_session_tracker.models import AppConfig
from aruba_session_tracker.paths import (
    DirectoryIdentity,
    UnsafeManagedPath,
    ensure_managed_directory,
    reject_link_or_reparse,
    reject_managed_file_link,
    verify_managed_directory,
)

_MAX_CONFIG_BYTES = 1024 * 1024
_TOP_LEVEL_KEYS = frozenset(
    {
        "mm_primary",
        "mm_standby",
        "managed_devices",
        "session_interval_seconds",
        "location_interval_seconds",
        "close_after_misses",
    }
)
_DEVICE_KEYS = frozenset({"name", "host", "port", "enabled"})
_SECRET_KEY_FRAGMENTS = (
    "credential",
    "enablepassword",
    "enablesecret",
    "password",
    "passwd",
    "privatekey",
    "secret",
    "token",
    "username",
)


class ConfigError(ValueError):
    """The settings file is unsafe, malformed, or cannot be persisted."""


class ConfigRepository:
    """Load and atomically save :class:`AppConfig` at an explicit path.

    The schema intentionally has no credential fields. Unknown keys are rejected
    instead of being silently ignored so a password can never be accidentally
    accepted into the persisted settings document.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(os.path.abspath(Path(path)))
        self._parent_identity: DirectoryIdentity | None = None
        if os.path.lexists(self.path.parent):
            self._verify_parent(create=False)

    def load(self, default: AppConfig | None = None) -> AppConfig | None:
        """Return stored settings, or ``default`` when the file does not exist."""

        if not os.path.lexists(self.path):
            return default
        try:
            self._verify_parent(create=False)
            before = reject_link_or_reparse(self.path)
            if not stat.S_ISREG(before.st_mode):
                raise ConfigError("설정 경로가 일반 파일이 아닙니다.")
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.path, flags)
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or int(opened.st_dev) != int(before.st_dev)
                    or int(opened.st_ino) != int(before.st_ino)
                ):
                    raise ConfigError("설정 파일이 읽는 동안 변경되었습니다.")
                data = stream.read(_MAX_CONFIG_BYTES + 1)
            if len(data) > _MAX_CONFIG_BYTES:
                raise ConfigError("설정 파일이 허용 크기(1 MiB)를 초과했습니다.")
            text = data.decode("utf-8")
            value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
            _validate_document(value)
            return AppConfig.from_dict(value)
        except ConfigError:
            raise
        except UnsafeManagedPath as error:
            raise ConfigError(str(error)) from error
        except (json.JSONDecodeError, KeyError, OSError, TypeError, ValueError) as error:
            raise ConfigError(f"설정 파일을 읽을 수 없습니다: {error}") from error

    def save(self, config: AppConfig) -> None:
        """Persist settings with same-directory write, fsync, and atomic replace."""

        if not isinstance(config, AppConfig):
            raise TypeError("config는 AppConfig 인스턴스여야 합니다.")
        document = config.to_dict()
        _validate_document(document)
        payload = json.dumps(document, ensure_ascii=False, indent=2) + "\n"

        try:
            parent = self._verify_parent(create=True)
            reject_managed_file_link(self.path)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.", suffix=".tmp", dir=parent
            )
            temporary_path = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._verify_parent(create=False)
                reject_managed_file_link(self.path)
                os.replace(temporary_path, self.path)
                self._verify_parent(create=False)
                reject_managed_file_link(self.path)
                _sync_directory(parent)
            finally:
                temporary_path.unlink(missing_ok=True)
        except ConfigError:
            raise
        except UnsafeManagedPath as error:
            raise ConfigError(str(error)) from error
        except OSError as error:
            raise ConfigError(f"설정 파일을 저장할 수 없습니다: {error}") from error

    def _verify_parent(self, *, create: bool) -> Path:
        parent = self.path.parent
        try:
            if self._parent_identity is None:
                if not os.path.lexists(parent) and not create:
                    raise ConfigError("설정 파일의 상위 경로가 없습니다.")
                absolute, identity = ensure_managed_directory(parent)
                self._parent_identity = identity
                if absolute != parent:
                    self.path = absolute / self.path.name
                    parent = absolute
            else:
                verify_managed_directory(parent, self._parent_identity)
        except UnsafeManagedPath as error:
            raise ConfigError(str(error)) from error
        return parent


def _sync_directory(path: Path) -> None:
    """Persist the rename metadata where directory fsync is supported."""

    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ConfigError(f"설정에 중복된 키가 있습니다: {key}")
        value[key] = item
    return value


def _validate_document(value: object) -> None:
    if not isinstance(value, dict):
        raise ConfigError("설정의 최상위 값은 객체여야 합니다.")
    _reject_secret_keys(value)
    _require_exact_keys(
        value,
        _TOP_LEVEL_KEYS,
        "최상위 설정",
        required={"mm_primary", "mm_standby", "managed_devices"},
    )
    for key in ("mm_primary", "mm_standby"):
        device = value.get(key)
        if not isinstance(device, dict):
            raise ConfigError(f"{key}는 장비 객체여야 합니다.")
        _require_exact_keys(device, _DEVICE_KEYS, key, required={"name", "host"})
    devices = value.get("managed_devices")
    if not isinstance(devices, list):
        raise ConfigError("managed_devices는 배열이어야 합니다.")
    for index, device in enumerate(devices):
        if not isinstance(device, dict):
            raise ConfigError(f"managed_devices[{index}]는 장비 객체여야 합니다.")
        _require_exact_keys(
            device,
            _DEVICE_KEYS,
            f"managed_devices[{index}]",
            required={"name", "host"},
        )


def _require_exact_keys(
    value: Mapping[str, object],
    allowed: frozenset[str],
    label: str,
    *,
    required: set[str] | None = None,
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ConfigError(f"{label}에 허용되지 않은 키가 있습니다: {', '.join(unknown)}")
    missing = sorted((required or set()) - set(value))
    if missing:
        raise ConfigError(f"{label}에 필수 키가 없습니다: {', '.join(missing)}")


def _reject_secret_keys(value: object, path: str = "config") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = "".join(
                character for character in str(key).casefold() if character.isalnum()
            )
            if any(fragment in normalized for fragment in _SECRET_KEY_FRAGMENTS):
                raise ConfigError(f"비밀값 또는 계정 필드는 저장할 수 없습니다: {path}.{key}")
            _reject_secret_keys(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_secret_keys(item, f"{path}[{index}]")
