from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path

import pytest

import aruba_session_tracker.storage.durable_io as durable_io_module
import aruba_session_tracker.storage.session_store as session_store_module
import aruba_session_tracker.storage.windows_file_metadata as windows_file_metadata
from aruba_session_tracker.models import StorageFailureKind
from aruba_session_tracker.storage import StorageError


def _metadata(
    *,
    volume: int = 17,
    file_index: int = 23,
    links: int = 1,
    attributes: int = 0,
    size: int = 1,
    modified_ns: int = 100,
) -> windows_file_metadata.WindowsFileMetadata:
    return windows_file_metadata.WindowsFileMetadata(
        volume_serial_number=volume,
        file_index=file_index,
        number_of_links=links,
        file_attributes=attributes,
        file_size=size,
        modified_ns=modified_ns,
    )


def test_native_metadata_properties_use_windows_handle_fields() -> None:
    file_id_128 = (1 << 100) | 202
    regular = _metadata(volume=101, file_index=file_id_128, size=303)
    reparse_directory = _metadata(attributes=0x10 | 0x400)

    assert regular.identity == (101, file_id_128)
    assert regular.file_size == 303
    assert regular.modified_ns == 100
    assert regular.is_disk_file is True
    assert regular.is_reparse_point is False
    assert reparse_directory.is_directory is True
    assert reparse_directory.is_reparse_point is True
    assert reparse_directory.is_disk_file is False


def test_windows_atomic_file_state_uses_native_identity_and_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "manifest.tmp"
    content = b"trusted manifest"
    path.write_bytes(content)
    native = _metadata(
        volume=700,
        file_index=(1 << 100) | 800,
        size=len(content),
        modified_ns=900,
    )
    monkeypatch.setattr(windows_file_metadata, "available", lambda: True)
    monkeypatch.setattr(windows_file_metadata, "from_path", lambda _path: native)
    monkeypatch.setattr(windows_file_metadata, "from_descriptor", lambda _descriptor: native)

    state = durable_io_module._file_state(
        path,
        with_hash=True,
        use_native_windows_identity=True,
    )

    assert (state.device, state.inode) == native.identity
    assert state.modified_ns == native.modified_ns
    assert state.size == len(content)
    assert state.sha256 == hashlib.sha256(content).hexdigest()


def test_windows_atomic_file_state_rejects_native_identity_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "manifest.tmp"
    path.write_bytes(b"trusted manifest")
    opened = _metadata(volume=1, file_index=2, size=16)
    changed = _metadata(volume=1, file_index=3, size=16)
    descriptor_calls = 0

    def descriptor_metadata(_descriptor: int) -> windows_file_metadata.WindowsFileMetadata:
        nonlocal descriptor_calls
        descriptor_calls += 1
        return opened if descriptor_calls == 1 else changed

    monkeypatch.setattr(windows_file_metadata, "available", lambda: True)
    monkeypatch.setattr(windows_file_metadata, "from_path", lambda _path: opened)
    monkeypatch.setattr(windows_file_metadata, "from_descriptor", descriptor_metadata)

    with pytest.raises(OSError, match="changed while fingerprinting"):
        durable_io_module._file_state(
            path,
            with_hash=True,
            use_native_windows_identity=True,
        )


def test_atomic_replace_default_keeps_crt_metadata_for_external_filesystems(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "external-fat-stage.tmp"
    destination = tmp_path / "external-fat-report.csv"
    content = b"external report"
    source.write_bytes(content)
    monkeypatch.setattr(windows_file_metadata, "available", lambda: True)
    monkeypatch.setattr(
        windows_file_metadata,
        "from_path",
        lambda _path: pytest.fail("default atomic replace must not require FileIdInfo"),
    )
    monkeypatch.setattr(
        windows_file_metadata,
        "from_descriptor",
        lambda _descriptor: pytest.fail("default atomic replace must not require FileIdInfo"),
    )

    durable_io_module.replace_with_retry(source, destination)

    assert destination.read_bytes() == content


def test_result_fingerprint_default_keeps_crt_metadata_for_external_filesystems(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "external-fat-report.csv"
    content = b"external report"
    path.write_bytes(content)
    monkeypatch.setattr(windows_file_metadata, "available", lambda: True)
    monkeypatch.setattr(
        windows_file_metadata,
        "from_path",
        lambda _path: pytest.fail("default fingerprint must not require FileIdInfo"),
    )
    monkeypatch.setattr(
        windows_file_metadata,
        "from_descriptor",
        lambda _descriptor: pytest.fail("default fingerprint must not require FileIdInfo"),
    )

    digest, size = session_store_module._file_fingerprint(path)

    assert digest == hashlib.sha256(content).hexdigest()
    assert size == len(content)


def test_windows_result_fingerprint_ignores_incompatible_crt_file_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "raw-stage.txt"
    content = b"trusted raw result"
    path.write_bytes(content)
    native = _metadata(
        volume=41,
        file_index=(1 << 96) | 42,
        size=len(content),
        modified_ns=43,
    )
    monkeypatch.setattr(windows_file_metadata, "available", lambda: True)
    monkeypatch.setattr(windows_file_metadata, "from_path", lambda _path: native)
    monkeypatch.setattr(windows_file_metadata, "from_descriptor", lambda _descriptor: native)
    monkeypatch.setattr(
        session_store_module,
        "_plain_regular_file_info",
        lambda _path: pytest.fail("Windows fingerprint must not use CRT path stat identity"),
    )

    digest, size = session_store_module._file_fingerprint(
        path,
        use_native_windows_identity=True,
    )

    assert digest == hashlib.sha256(content).hexdigest()
    assert size == len(content)


def test_windows_result_fingerprint_rejects_native_path_descriptor_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "raw-stage.txt"
    content = b"trusted raw result"
    path.write_bytes(content)
    through_path = _metadata(volume=51, file_index=52, size=len(content))
    opened = _metadata(volume=51, file_index=53, size=len(content))
    monkeypatch.setattr(windows_file_metadata, "available", lambda: True)
    monkeypatch.setattr(windows_file_metadata, "from_path", lambda _path: through_path)
    monkeypatch.setattr(windows_file_metadata, "from_descriptor", lambda _descriptor: opened)

    with pytest.raises(StorageError, match="열기 전에 변경") as caught:
        session_store_module._file_fingerprint(
            path,
            use_native_windows_identity=True,
        )

    assert caught.value.failure_kind is StorageFailureKind.STORAGE_PATH


@pytest.mark.parametrize(
    ("native", "message"),
    (
        (_metadata(links=2), "hardlink"),
        (_metadata(attributes=0x400), "비-reparse"),
        (_metadata(volume=0, file_index=0), "고유 ID"),
    ),
)
def test_windows_result_fingerprint_rejects_unsafe_native_metadata(
    native: windows_file_metadata.WindowsFileMetadata,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "raw-stage.txt"
    path.write_bytes(b"trusted raw result")
    monkeypatch.setattr(windows_file_metadata, "available", lambda: True)
    monkeypatch.setattr(windows_file_metadata, "from_path", lambda _path: native)

    with pytest.raises(StorageError, match=message) as caught:
        session_store_module._file_fingerprint(
            path,
            use_native_windows_identity=True,
        )

    assert caught.value.failure_kind is StorageFailureKind.STORAGE_PATH


def test_lease_info_uses_native_metadata_for_both_descriptor_and_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "lease.lock"
    path.write_bytes(b"0")
    native = _metadata(volume=700, file_index=800)
    descriptor_calls: list[int] = []
    path_calls: list[Path] = []
    monkeypatch.setattr(windows_file_metadata, "available", lambda: True)
    monkeypatch.setattr(
        windows_file_metadata,
        "from_descriptor",
        lambda descriptor: descriptor_calls.append(descriptor) or native,
    )
    monkeypatch.setattr(
        windows_file_metadata,
        "from_path",
        lambda current: path_calls.append(current) or native,
    )

    with path.open("r+b", buffering=0) as stream:
        descriptor_info = session_store_module._lease_file_info_from_descriptor(stream.fileno())
    path_info = session_store_module._checked_lease_path_info(path)

    assert descriptor_calls
    assert path_calls == [path]
    assert (descriptor_info.device, descriptor_info.inode) == (700, 800)
    assert descriptor_info == path_info


def test_new_lease_path_probe_retries_temporary_file_not_found(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "lease.lock"
    attempts = 0

    def temporarily_hidden(_path: Path) -> windows_file_metadata.WindowsFileMetadata:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise FileNotFoundError(errno.ENOENT, "fixture path not visible yet")
        return _metadata()

    monkeypatch.setattr(windows_file_metadata, "available", lambda: True)
    monkeypatch.setattr(windows_file_metadata, "from_path", temporarily_hidden)
    monkeypatch.setattr(session_store_module.time, "sleep", lambda _delay: None)

    info = session_store_module._checked_lease_path_info(path)

    assert attempts == 3
    assert (info.device, info.inode) == (17, 23)


def test_new_lease_path_probe_retries_errno_only_eacces_then_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "lease.lock"
    attempts = 0

    def temporarily_blocked(_path: Path) -> windows_file_metadata.WindowsFileMetadata:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise PermissionError(errno.EACCES, "fixture path access collision")
        return _metadata()

    monkeypatch.setattr(windows_file_metadata, "available", lambda: True)
    monkeypatch.setattr(windows_file_metadata, "from_path", temporarily_blocked)
    monkeypatch.setattr(session_store_module.time, "sleep", lambda _delay: None)

    session_store_module._checked_lease_path_info(path)

    assert attempts == 2


def test_persistent_errno_only_eacces_remains_storage_path_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "lease.lock"
    attempts = 0

    def blocked(_path: Path) -> windows_file_metadata.WindowsFileMetadata:
        nonlocal attempts
        attempts += 1
        raise PermissionError(errno.EACCES, "fixture persistent path denial")

    monkeypatch.setattr(windows_file_metadata, "available", lambda: True)
    monkeypatch.setattr(windows_file_metadata, "from_path", blocked)
    monkeypatch.setattr(session_store_module.time, "sleep", lambda _delay: None)

    with pytest.raises(StorageError) as caught:
        session_store_module._checked_lease_path_info(path)

    assert attempts == len(session_store_module._LEASE_FILE_RETRY_DELAYS)
    assert caught.value.failure_kind is StorageFailureKind.STORAGE_PATH


@pytest.mark.parametrize(
    ("native", "message"),
    (
        (_metadata(links=2), "hardlink"),
        (_metadata(attributes=0x400), "비-reparse"),
        (_metadata(volume=0, file_index=0), "고유 ID"),
    ),
)
def test_unsafe_native_lease_metadata_fails_closed_without_retry(
    native: windows_file_metadata.WindowsFileMetadata,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "lease.lock"
    attempts = 0

    def unsafe(_path: Path) -> windows_file_metadata.WindowsFileMetadata:
        nonlocal attempts
        attempts += 1
        return native

    monkeypatch.setattr(windows_file_metadata, "available", lambda: True)
    monkeypatch.setattr(windows_file_metadata, "from_path", unsafe)

    with pytest.raises(StorageError, match=message) as caught:
        session_store_module._checked_lease_path_info(path)

    assert attempts == 1
    assert caught.value.failure_kind is StorageFailureKind.STORAGE_PATH


def test_native_identity_change_fails_closed() -> None:
    opened = session_store_module._lease_file_info_from_windows(_metadata(volume=30, file_index=40))
    replaced = session_store_module._lease_file_info_from_windows(
        _metadata(volume=30, file_index=41)
    )

    with pytest.raises(StorageError, match="다른 파일") as caught:
        session_store_module._require_same_file_identity(opened, replaced)

    assert caught.value.failure_kind is StorageFailureKind.STORAGE_PATH


def test_release_does_not_remove_a_replacement_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "lease.lock"
    path.write_bytes(b"replacement")
    stream = path.open("r+b", buffering=0)
    lease = session_store_module._RunLease(path, stream, device=1, inode=2)
    monkeypatch.setattr(windows_file_metadata, "available", lambda: True)
    monkeypatch.setattr(
        windows_file_metadata,
        "from_path",
        lambda _path: _metadata(volume=1, file_index=3, size=len(b"replacement")),
    )

    session_store_module._release_run_lease(lease, remove=True)

    assert stream.closed
    assert path.read_bytes() == b"replacement"


@pytest.mark.windows
def test_windows_native_descriptor_and_path_metadata_match(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("native Windows handle metadata applies only on Windows")
    path = tmp_path / "lease.lock"
    path.write_bytes(b"0")
    descriptor = os.open(path, os.O_RDWR | getattr(os, "O_BINARY", 0))
    try:
        opened = windows_file_metadata.from_descriptor(descriptor)
        through_path = windows_file_metadata.from_path(path)
    finally:
        os.close(descriptor)

    assert opened.identity != (0, 0)
    assert opened.identity == through_path.identity
    assert opened.number_of_links == through_path.number_of_links == 1
    assert opened.modified_ns == through_path.modified_ns
    assert opened.is_disk_file is True
    assert opened.is_reparse_point is False
    assert session_store_module._file_fingerprint(
        path,
        use_native_windows_identity=True,
    ) == (
        hashlib.sha256(b"0").hexdigest(),
        1,
    )
