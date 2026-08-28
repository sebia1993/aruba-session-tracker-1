from __future__ import annotations

import json
from pathlib import Path

import pytest

from aruba_session_tracker.config import ConfigError, ConfigRepository
from aruba_session_tracker.models import AppConfig, DeviceTarget


def _config() -> AppConfig:
    return AppConfig(
        mm_primary=DeviceTarget("주-MM", "192.0.2.10"),
        mm_standby=DeviceTarget("대기-MM", "192.0.2.11"),
        managed_devices=(DeviceTarget("MD-01", "198.51.100.21"),),
    )


def test_missing_config_returns_explicit_default(tmp_path: Path) -> None:
    default = _config()
    repository = ConfigRepository(tmp_path / "config.json")

    assert repository.load() is None
    assert repository.load(default) is default


def test_round_trip_uses_utf8_and_leaves_no_temporary_file(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "config.json"
    repository = ConfigRepository(path)

    repository.save(_config())

    assert repository.load() == _config()
    assert "주-MM" in path.read_text(encoding="utf-8")
    assert list(path.parent.glob(".config.json.*.tmp")) == []


@pytest.mark.parametrize(
    "secret_key",
    ["password", "username", "enable_secret", "api_token", "private-key"],
)
def test_load_rejects_secret_or_credential_keys(tmp_path: Path, secret_key: str) -> None:
    document = _config().to_dict()
    document[secret_key] = "must-not-persist"
    path = tmp_path / "config.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ConfigError, match="저장할 수 없습니다"):
        ConfigRepository(path).load()


def test_load_rejects_unknown_and_duplicate_keys(tmp_path: Path) -> None:
    document = _config().to_dict()
    document["future_setting"] = True
    unknown_path = tmp_path / "unknown.json"
    unknown_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ConfigError, match="허용되지 않은 키"):
        ConfigRepository(unknown_path).load()

    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_text('{"mm_primary": {}, "mm_primary": {}}', encoding="utf-8")
    with pytest.raises(ConfigError, match="중복된 키"):
        ConfigRepository(duplicate_path).load()


def test_failed_atomic_replace_preserves_previous_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.json"
    path.write_text("previous\n", encoding="utf-8")
    repository = ConfigRepository(path)

    def fail_replace(_source: object, _destination: object) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr("aruba_session_tracker.config.os.replace", fail_replace)

    with pytest.raises(ConfigError, match="저장할 수 없습니다"):
        repository.save(_config())

    assert path.read_text(encoding="utf-8") == "previous\n"
    assert list(tmp_path.glob(".config.json.*.tmp")) == []


def test_oversized_or_non_object_config_is_rejected(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(ConfigError, match="1 MiB"):
        ConfigRepository(oversized).load()

    non_object = tmp_path / "array.json"
    non_object.write_text("[]", encoding="utf-8")
    with pytest.raises(ConfigError, match="최상위"):
        ConfigRepository(non_object).load()


@pytest.mark.parametrize(
    ("path", "bad_value"),
    [
        (("managed_devices", 0, "enabled"), "false"),
        (("managed_devices", 0, "port"), "22"),
        (("mm_primary", "enabled"), "false"),
        (("mm_primary", "port"), 22.0),
        (("session_interval_seconds",), "5"),
        (("location_interval_seconds",), 30.0),
        (("close_after_misses",), True),
    ],
)
def test_load_rejects_coercible_but_wrong_value_types(
    tmp_path: Path,
    path: tuple[object, ...],
    bad_value: object,
) -> None:
    document = _config().to_dict()
    target: object = document
    for segment in path[:-1]:
        if isinstance(segment, int):
            assert isinstance(target, list)
            target = target[segment]
        else:
            assert isinstance(target, dict)
            target = target[segment]
    assert isinstance(target, dict)
    target[str(path[-1])] = bad_value
    config_path = tmp_path / "wrong-type.json"
    config_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ConfigError):
        ConfigRepository(config_path).load()
