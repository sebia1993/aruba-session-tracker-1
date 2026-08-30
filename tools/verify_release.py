"""Verify exact, private-data-free Windows release assets and optional EXE smoke."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import zipfile
from contextlib import AbstractContextManager, suppress
from pathlib import Path, PurePosixPath
from types import TracebackType
from typing import Self

import paramiko

PRODUCT = "ArubaSessionTracker"
REQUIRED_BUNDLE_FILES = {
    "ArubaSessionTracker.exe",
    "BUILD_INFO.json",
    "CHANGELOG.md",
    "LICENSE",
    "licenses/LGPL-3.0-only.txt",
    "README.md",
    "requirements-runtime.lock",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.txt",
    "sbom.cdx.json",
}
FORBIDDEN_NAMES = {
    ".env",
    "config.json",
    "known_hosts",
}
FORBIDDEN_DIRECTORY_NAMES = {"exports", "raw"}
FORBIDDEN_SUFFIXES = {
    ".csv",
    ".db",
    ".html",
    ".key",
    ".log",
    ".p12",
    ".pem",
    ".pfx",
    ".ppk",
    ".sqlite",
    ".sqlite3",
}
_LOCK_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s\\]+)")
_LOCK_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})\b")
_SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bghp_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
)
_MAX_ZIP_MEMBER_BYTES = 512 * 1024 * 1024
_MAX_ZIP_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
_SCAN_CHUNK_BYTES = 1024 * 1024
_SCAN_OVERLAP_BYTES = 256
_LOOPBACK = "127.0.0.1"
_LOOPBACK_PROMPT = "fixture-mm#"
_GLOBAL_SOURCE_OUTPUT = """Global Users
------------
IP Address      MAC                Name           Current switch Role         Auth   AP name
--------------- ------------------ -------------- -------------- ------------ ------ -------------
192.0.2.10      00:00:5e:00:53:01  test-user      127.0.0.1      employee     dot1x  fixture-ap
Total entries = 1
"""
_GLOBAL_DESTINATION_OUTPUT = """Global Users
------------
IP Address      MAC                Name           Current switch Role         Auth   AP name
--------------- ------------------ -------------- -------------- ------------ ------ -------------
Total entries = 0
"""
_DATAPATH_OUTPUT = (
    "Datapath Session Table Entries\n"
    "------------------------------\n"
    "Source IP or MAC  Destination IP  Prot SPort DPort Cntr Prio ToS Age "
    "Destination TAge Packets Bytes Flags CPU ID\n"
    "----------------  --------------  ---- ----- ----- ---- ---- --- --- "
    "----------- ---- ------- ----- ----- ------\n"
    "192.0.2.10        203.0.113.20    6    54321 443   0/0  0    0   12  "
    "local       0    10      2048  FCI   1\n"
    "Entries: 1\n"
)


class ReleaseVerificationError(ValueError):
    pass


class _PasswordServer(paramiko.ServerInterface):  # type: ignore[misc]
    def __init__(self, owner: _PackagedLoopbackSshServer) -> None:
        self._owner = owner
        self.shell_requested = threading.Event()

    def check_auth_password(self, username: str, password: str) -> int:
        accepted = username == self._owner.username and password == self._owner.password
        with self._owner.lock:
            self._owner.auth_results.append(accepted)
        return paramiko.AUTH_SUCCESSFUL if accepted else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        del username
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        del chanid
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        del channel, term, width, height, pixelwidth, pixelheight, modes
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        del channel
        self.shell_requested.set()
        return True


class _PackagedLoopbackSshServer(AbstractContextManager["_PackagedLoopbackSshServer"]):
    """Bounded SSH fixture that refuses every non-loopback peer."""

    def __init__(self) -> None:
        self.username = "fixture-operator"
        self.password = self.username[::-1]
        self.host_key = paramiko.RSAKey.generate(1024)
        self.command_outputs = {
            "no paging": "",
            'show global-user-table list ip "192.0.2.10"': _GLOBAL_SOURCE_OUTPUT,
            'show global-user-table list ip "203.0.113.20"': _GLOBAL_DESTINATION_OUTPUT,
            "show datapath session table 192.0.2.10": _DATAPATH_OUTPUT,
        }
        self.auth_results: list[bool] = []
        self.commands: list[str] = []
        self.failures: list[str] = []
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((_LOOPBACK, 0))
        self._listener.listen(8)
        self._listener.settimeout(0.2)
        self.port = int(self._listener.getsockname()[1])
        self._threads: list[threading.Thread] = []
        self._transports: set[paramiko.Transport] = set()
        self._accept_thread = threading.Thread(
            target=self._accept_connections,
            name=f"release-loopback-ssh-accept-{self.port}",
            daemon=True,
        )

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(self.host_key.asbytes()).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")

    def __enter__(self) -> Self:
        self._accept_thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def close(self) -> None:
        self._stop.set()
        with suppress(OSError):
            self._listener.close()
        with self.lock:
            active = tuple(self._transports)
        for transport in active:
            transport.close()
        self._accept_thread.join(timeout=3)
        deadline = time.monotonic() + 5
        for worker in tuple(self._threads):
            worker.join(timeout=max(0.0, deadline - time.monotonic()))
        leaked = [worker.name for worker in self._threads if worker.is_alive()]
        if self._accept_thread.is_alive() or leaked:
            raise ReleaseVerificationError(f"packaged loopback SSH fixture leaked: {leaked}")
        if self.failures:
            raise ReleaseVerificationError(
                f"packaged loopback SSH fixture failed at sanitized stages: {self.failures}"
            )

    def _accept_connections(self) -> None:
        while not self._stop.is_set():
            try:
                client, peer = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self._stop.is_set():
                    self.failures.append("LISTENER")
                return
            if peer[0] != _LOOPBACK:
                client.close()
                self.failures.append("NON_LOOPBACK_PEER")
                continue
            worker = threading.Thread(
                target=self._handle_client,
                args=(client,),
                name=f"release-loopback-ssh-client-{len(self._threads) + 1}",
                daemon=True,
            )
            self._threads.append(worker)
            worker.start()

    def _handle_client(self, client: socket.socket) -> None:
        transport: paramiko.Transport | None = None
        channel: paramiko.Channel | None = None
        try:
            client.settimeout(3)
            transport = paramiko.Transport(client)
            with self.lock:
                self._transports.add(transport)
            transport.add_server_key(self.host_key)
            server = _PasswordServer(self)
            transport.start_server(server=server)
            channel = transport.accept(timeout=2)
            if channel is None:
                return
            if not server.shell_requested.wait(timeout=2):
                raise TimeoutError
            channel.settimeout(0.2)
            channel.sendall(_LOOPBACK_PROMPT.encode("ascii"))
            self._serve_shell(channel)
        except (EOFError, OSError, paramiko.SSHException):
            if not self._stop.is_set() and transport is not None and transport.is_active():
                self.failures.append("ACTIVE_TRANSPORT")
        except BaseException:
            self.failures.append("SERVER_WORKER")
        finally:
            if channel is not None:
                with suppress(Exception):
                    channel.close()
            if transport is not None:
                with suppress(Exception):
                    transport.close()
                with self.lock:
                    self._transports.discard(transport)
            with suppress(OSError):
                client.close()

    def _serve_shell(self, channel: paramiko.Channel) -> None:
        buffer = bytearray()
        while not self._stop.is_set() and not channel.closed:
            try:
                data = channel.recv(4096)
            except TimeoutError:
                continue
            if not data:
                return
            buffer.extend(data)
            while True:
                terminators = [index for value in (10, 13) if (index := buffer.find(value)) >= 0]
                if not terminators:
                    break
                index = min(terminators)
                command = bytes(buffer[:index]).decode("utf-8", errors="strict").strip()
                del buffer[: index + 1]
                while buffer and buffer[0] in (10, 13):
                    del buffer[0]
                if not command:
                    channel.sendall(_LOOPBACK_PROMPT.encode("ascii"))
                    continue
                with self.lock:
                    self.commands.append(command)
                if command == "exit":
                    return
                output = self.command_outputs.get(command, "% Invalid input")
                response = f"{command}\r\n"
                if output:
                    response += f"{output}\r\n"
                response += _LOOPBACK_PROMPT
                channel.sendall(response.encode("utf-8"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _verify_sidecar(zip_path: Path, sidecar_path: Path) -> None:
    text = sidecar_path.read_text(encoding="utf-8")
    pattern = re.compile(r"\A(?P<hash>[0-9a-fA-F]{64})  " + re.escape(zip_path.name) + r"\r?\n?\Z")
    match = pattern.fullmatch(text)
    if match is None or match.group("hash").casefold() != _sha256(zip_path):
        raise ReleaseVerificationError("ZIP does not match its exact SHA-256 sidecar")


def _safe_member(info: zipfile.ZipInfo) -> PurePosixPath:
    normalized = info.filename.replace("\\", "/")
    member = PurePosixPath(normalized)
    if member.is_absolute() or ".." in member.parts or not member.parts:
        raise ReleaseVerificationError(f"unsafe ZIP member path: {info.filename}")
    unix_mode = info.external_attr >> 16
    if stat.S_ISLNK(unix_mode):
        raise ReleaseVerificationError(f"ZIP must not contain symbolic links: {info.filename}")
    if info.flag_bits & 0x1:
        raise ReleaseVerificationError(f"ZIP must not contain encrypted members: {info.filename}")
    if info.file_size > _MAX_ZIP_MEMBER_BYTES:
        raise ReleaseVerificationError(f"ZIP member is unexpectedly large: {info.filename}")
    lower_parts = tuple(part.casefold() for part in member.parts)
    if member.name.casefold() in FORBIDDEN_NAMES:
        raise ReleaseVerificationError(f"runtime/private file found in ZIP: {info.filename}")
    if set(lower_parts[:-1]) & FORBIDDEN_DIRECTORY_NAMES:
        raise ReleaseVerificationError(f"raw/export directory found in ZIP: {info.filename}")
    if PurePosixPath(member.name).suffix.casefold() in FORBIDDEN_SUFFIXES:
        raise ReleaseVerificationError(f"private/runtime suffix found in ZIP: {info.filename}")
    if member.name.casefold().endswith(("-journal", "-shm", "-wal")):
        raise ReleaseVerificationError(f"SQLite sidecar found in ZIP: {info.filename}")
    if any(token in member.name.casefold() for token in ("password", "secret", "token")):
        raise ReleaseVerificationError(f"secret-like filename found in ZIP: {info.filename}")
    if re.fullmatch(r"icu(?:uc|dt\d+)\.dll", member.name, re.IGNORECASE):
        raise ReleaseVerificationError(
            f"incompatible build-host ICU must not be bundled on Windows 11: {info.filename}"
        )
    return member


def _scan_archive_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> None:
    tail = b""
    first = True
    with archive.open(info) as stream:
        while chunk := stream.read(_SCAN_CHUNK_BYTES):
            if first:
                first = False
                if chunk.startswith(b"SQLite format 3\x00"):
                    raise ReleaseVerificationError(
                        f"SQLite database content found in ZIP: {info.filename}"
                    )
                # Text credentials remain detectable regardless of filename
                # or size. Native libraries may legitimately embed parser
                # marker constants and are separately controlled by the lock.
                if b"\x00" in chunk[:8192]:
                    return
            combined = tail + chunk
            if any(pattern.search(combined) for pattern in _SECRET_PATTERNS):
                raise ReleaseVerificationError(
                    f"private material pattern found in ZIP: {info.filename}"
                )
            tail = combined[-_SCAN_OVERLAP_BYTES:]


def _normalized_package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _locked_components(path: Path) -> dict[str, tuple[str, set[str]]]:
    expected: dict[str, tuple[str, set[str]]] = {}
    pending = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or (line.startswith("--") and not pending):
            continue
        continued = line.endswith("\\")
        pending += (line[:-1] if continued else line) + " "
        if continued:
            continue
        requirement = pending.strip()
        pending = ""
        match = _LOCK_REQUIREMENT.match(requirement)
        hashes = {value.casefold() for value in _LOCK_HASH.findall(requirement)}
        if match is None or not hashes:
            raise ReleaseVerificationError("runtime lock has an unpinned or unhashed component")
        name = _normalized_package_name(match.group(1))
        if name in expected:
            raise ReleaseVerificationError(f"runtime lock has duplicate component: {name}")
        expected[name] = (match.group(2), hashes)
    if pending:
        raise ReleaseVerificationError("runtime lock has an unterminated requirement")
    if not expected:
        raise ReleaseVerificationError("runtime lock contains no pinned components")
    return expected


def _component_hashes(component: dict[str, object]) -> set[str]:
    values: set[str] = set()
    candidates: list[object] = [component.get("hashes")]
    references = component.get("externalReferences")
    if isinstance(references, list):
        candidates.extend(
            reference.get("hashes") for reference in references if isinstance(reference, dict)
        )
    for candidate in candidates:
        if not isinstance(candidate, list):
            continue
        for item in candidate:
            if (
                isinstance(item, dict)
                and item.get("alg") == "SHA-256"
                and isinstance(item.get("content"), str)
            ):
                values.add(str(item["content"]).casefold())
    return values


def _direct_dependency_names(pyproject_path: Path) -> set[str]:
    document = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for requirement in document["project"]["dependencies"]:
        match = _LOCK_REQUIREMENT.fullmatch(requirement)
        if match is None:
            raise ReleaseVerificationError(
                f"pyproject runtime dependency is not exactly pinned: {requirement}"
            )
        names.add(_normalized_package_name(match.group(1)))
    return names


def _verify_sbom(
    path: Path,
    version: str,
    runtime_lock: Path,
    pyproject_path: Path,
) -> None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        raise ReleaseVerificationError(f"SBOM is not valid UTF-8 JSON: {error}") from error
    if document.get("bomFormat") != "CycloneDX":
        raise ReleaseVerificationError("SBOM is not CycloneDX")
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        raise ReleaseVerificationError("SBOM metadata is missing")
    component = metadata.get("component")
    if not isinstance(component, dict) or component.get("version") != version:
        raise ReleaseVerificationError("SBOM application version does not match")
    components = document.get("components")
    if not isinstance(components, list):
        raise ReleaseVerificationError("SBOM components are missing")
    actual = {
        _normalized_package_name(name): item
        for item in components
        if isinstance(item, dict) and isinstance((name := item.get("name")), str)
    }
    expected = _locked_components(runtime_lock)
    missing = sorted(expected.keys() - actual.keys())
    if missing:
        raise ReleaseVerificationError(
            f"SBOM is missing locked runtime components: {', '.join(missing)}"
        )
    for name, (locked_version, locked_hashes) in expected.items():
        item = actual[name]
        if item.get("version") != locked_version:
            raise ReleaseVerificationError(f"SBOM version does not match runtime lock: {name}")
        if not locked_hashes.issubset(_component_hashes(item)):
            raise ReleaseVerificationError(f"SBOM hash does not match runtime lock: {name}")

    root_ref = component.get("bom-ref")
    if not isinstance(root_ref, str) or not root_ref:
        raise ReleaseVerificationError("SBOM root component has no bom-ref")
    component_refs = {
        _normalized_package_name(name): reference
        for item in components
        if isinstance(item, dict)
        and isinstance((name := item.get("name")), str)
        and isinstance((reference := item.get("bom-ref")), str)
    }
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list):
        raise ReleaseVerificationError("SBOM dependency graph is missing")
    entries = {
        reference: item
        for item in dependencies
        if isinstance(item, dict) and isinstance((reference := item.get("ref")), str)
    }
    if not set(component_refs.values()).issubset(entries):
        raise ReleaseVerificationError("SBOM dependency graph omits runtime components")
    root_dependency = entries.get(root_ref)
    if not isinstance(root_dependency, dict) or not isinstance(
        root_dependency.get("dependsOn"), list
    ):
        raise ReleaseVerificationError("SBOM root dependency graph is incomplete")
    direct_names = _direct_dependency_names(pyproject_path)
    missing_direct = sorted(direct_names - component_refs.keys())
    if missing_direct:
        raise ReleaseVerificationError(
            f"SBOM is missing direct dependencies: {', '.join(missing_direct)}"
        )
    expected_direct_refs = {component_refs[name] for name in direct_names}
    if not expected_direct_refs.issubset(set(root_dependency["dependsOn"])):
        raise ReleaseVerificationError("SBOM root is not linked to every direct dependency")


def verify_release(
    *,
    zip_path: Path,
    sidecar_path: Path,
    sbom_path: Path,
    runtime_lock: Path,
    pyproject_path: Path,
    version: str,
    expected_commit: str | None = None,
    allow_dirty: bool = False,
) -> None:
    expected_zip_name = f"{PRODUCT}_v{version}_windows_x64.zip"
    expected_sbom_name = f"{PRODUCT}_v{version}_sbom.cdx.json"
    if zip_path.name != expected_zip_name or sidecar_path.name != f"{expected_zip_name}.sha256":
        raise ReleaseVerificationError("release ZIP or sidecar filename is not canonical")
    if sbom_path.name != expected_sbom_name:
        raise ReleaseVerificationError("release SBOM filename is not canonical")
    _verify_sidecar(zip_path, sidecar_path)
    _verify_sbom(sbom_path, version, runtime_lock, pyproject_path)

    with zipfile.ZipFile(zip_path) as archive:
        files: dict[PurePosixPath, zipfile.ZipInfo] = {}
        seen_names: set[str] = set()
        total_uncompressed_bytes = 0
        for info in archive.infolist():
            member = _safe_member(info)
            total_uncompressed_bytes += info.file_size
            if total_uncompressed_bytes > _MAX_ZIP_TOTAL_BYTES:
                raise ReleaseVerificationError("ZIP uncompressed size exceeds the release limit")
            canonical = member.as_posix().casefold()
            if canonical in seen_names:
                raise ReleaseVerificationError(f"duplicate ZIP member: {info.filename}")
            seen_names.add(canonical)
            if not info.is_dir():
                files[member] = info
                _scan_archive_member(archive, info)

        roots = {member.parts[0] for member in files}
        if roots != {PRODUCT}:
            raise ReleaseVerificationError("ZIP must have one canonical top-level product folder")
        relative_names = {PurePosixPath(*member.parts[1:]).as_posix() for member in files}
        missing = sorted(REQUIRED_BUNDLE_FILES - relative_names)
        if missing:
            raise ReleaseVerificationError(
                f"required bundle files are missing: {', '.join(missing)}"
            )
        if not any(name.casefold().endswith("/platforms/qwindows.dll") for name in relative_names):
            raise ReleaseVerificationError("Qt Windows platform plugin is missing from the bundle")
        licensed_components = {
            parts[1]
            for name in relative_names
            if len(parts := PurePosixPath(name).parts) >= 3 and parts[0] == "licenses"
        }
        missing_licenses = sorted(_locked_components(runtime_lock).keys() - licensed_components)
        if missing_licenses:
            raise ReleaseVerificationError(
                f"runtime license evidence is missing: {', '.join(missing_licenses)}"
            )
        if "pyinstaller" not in licensed_components:
            raise ReleaseVerificationError("PyInstaller bootloader license evidence is missing")

        build_member = PurePosixPath(PRODUCT) / "BUILD_INFO.json"
        build_info = json.loads(archive.read(files[build_member]).decode("utf-8"))
        if build_info.get("product") != PRODUCT or build_info.get("version") != version:
            raise ReleaseVerificationError("BUILD_INFO product/version does not match")
        if build_info.get("architecture") != "windows-x64":
            raise ReleaseVerificationError("BUILD_INFO architecture is not windows-x64")
        if bool(build_info.get("dirtyTree")) and not allow_dirty:
            raise ReleaseVerificationError("release build provenance reports a dirty source tree")
        build_commit = build_info.get("commit")
        if expected_commit is not None:
            if re.fullmatch(r"[0-9a-fA-F]{40}", expected_commit) is None:
                raise ReleaseVerificationError("expected commit is not a full Git commit SHA")
            if not isinstance(build_commit, str) or not hmac.compare_digest(
                build_commit.casefold(), expected_commit.casefold()
            ):
                raise ReleaseVerificationError("BUILD_INFO commit does not match expected commit")
        elif not allow_dirty:
            raise ReleaseVerificationError("clean release verification requires expected commit")
        if build_info.get("authenticodeSigned") is not False:
            raise ReleaseVerificationError("unsigned package must report authenticodeSigned=false")
        if build_info.get("liveDeviceValidated") is not False:
            raise ReleaseVerificationError("fixture build must report liveDeviceValidated=false")

        bundled_sbom = json.loads(
            archive.read(files[PurePosixPath(PRODUCT) / "sbom.cdx.json"]).decode("utf-8")
        )
        external_sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
        if bundled_sbom != external_sbom:
            raise ReleaseVerificationError("bundled and external SBOM documents differ")


def smoke_executable(zip_path: Path) -> None:
    if os.name != "nt":
        raise ReleaseVerificationError("EXE smoke verification requires Windows")
    with tempfile.TemporaryDirectory(prefix="aruba-session-tracker-smoke-") as temporary:
        root = Path(temporary)
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(root)
        executable = root / PRODUCT / f"{PRODUCT}.exe"
        logic_environment = _packaged_environment()
        logic_environment["QT_QPA_PLATFORM"] = "offscreen"
        try:
            result = subprocess.run(  # noqa: S603
                [executable, "--smoke-test"],
                check=False,
                capture_output=True,
                timeout=20,
                env=logic_environment,
            )
        except subprocess.TimeoutExpired as error:
            raise ReleaseVerificationError("packaged EXE logic smoke timed out") from error
        if result.returncode != 0:
            raise ReleaseVerificationError(
                f"packaged EXE smoke failed with exit code {result.returncode}"
            )

        loopback_local_app_data = root / "loopback-smoke" / "LocalAppData"
        loopback_local_app_data.mkdir(parents=True)
        loopback_environment = logic_environment.copy()
        loopback_environment["LOCALAPPDATA"] = str(loopback_local_app_data)
        with _PackagedLoopbackSshServer() as server:
            for mode in ("success", "auth-failure"):
                try:
                    loopback_result = subprocess.run(  # noqa: S603
                        [
                            executable,
                            "--loopback-ssh-smoke",
                            mode,
                            "--loopback-ssh-port",
                            str(server.port),
                            "--loopback-ssh-fingerprint",
                            server.fingerprint,
                        ],
                        check=False,
                        capture_output=True,
                        timeout=60,
                        env=loopback_environment,
                    )
                except subprocess.TimeoutExpired as error:
                    raise ReleaseVerificationError(
                        f"packaged loopback SSH {mode} smoke timed out"
                    ) from error
                expected_marker = (
                    f"ARUBA_SESSION_TRACKER_LOOPBACK_SSH_{mode.upper().replace('-', '_')}_OK"
                ).encode("ascii")
                if loopback_result.returncode != 0 or expected_marker not in loopback_result.stdout:
                    raise ReleaseVerificationError(
                        f"packaged loopback SSH {mode} smoke failed with exit code "
                        f"{loopback_result.returncode}"
                    )
            required_commands = {
                'show global-user-table list ip "192.0.2.10"',
                'show global-user-table list ip "203.0.113.20"',
                "show datapath session table 192.0.2.10",
            }
            if not required_commands.issubset(server.commands):
                raise ReleaseVerificationError(
                    "packaged loopback SSH success smoke skipped the MM/MD command path"
                )
            if True not in server.auth_results or False not in server.auth_results:
                raise ReleaseVerificationError(
                    "packaged loopback SSH smoke did not cover success and authentication failure"
                )

        korean_local_app_data = root / "한국어 경로" / "LocalAppData"
        korean_local_app_data.mkdir(parents=True)
        report_path = root / "한국어 경로" / "보고서" / "세션 결과.html"
        try:
            report_result = subprocess.run(  # noqa: S603
                [executable, "--report-smoke-test", report_path],
                check=False,
                capture_output=True,
                timeout=30,
                env=logic_environment,
            )
        except subprocess.TimeoutExpired as error:
            raise ReleaseVerificationError("packaged HTML report smoke timed out") from error
        if report_result.returncode != 0 or not report_path.is_file():
            raise ReleaseVerificationError(
                "packaged HTML report smoke failed in a Korean output path "
                f"with exit code {report_result.returncode}"
            )
        _verify_packaged_report_text(report_path.read_text(encoding="utf-8"))

        gui_environment = _packaged_environment()
        gui_environment.pop("QT_QPA_PLATFORM", None)
        gui_environment["LOCALAPPDATA"] = str(korean_local_app_data)
        try:
            gui_result = subprocess.run(  # noqa: S603
                [executable, "--gui-smoke-test"],
                check=False,
                capture_output=True,
                timeout=30,
                env=gui_environment,
            )
        except subprocess.TimeoutExpired as error:
            raise ReleaseVerificationError("packaged native Qt GUI smoke timed out") from error
        if gui_result.returncode != 0:
            raise ReleaseVerificationError(
                "packaged native Qt GUI smoke failed in a Korean LocalAppData path "
                f"with exit code {gui_result.returncode}"
            )


def _verify_packaged_report_text(report_text: str) -> None:
    required_report_markers = (
        "세션 추적 결과",
        "결과 필터",
        "최신 세션 결과",
        "전체 추적 이력",
        "조회 출발지",
        "프로토콜별 최신 세션",
        "장비별 최신 세션",
        "KST",
        "한국어-MD",
        'id="result-filter"',
        'id="filter-ip"',
        'id="filter-protocol"',
        'id="filter-port"',
        'class="report-row"',
        'class="flow-panel"',
        "script-src 'sha256-",
        '<details class="history-toggle">',
        '<div class="details-body" id="observation-history-body">',
        ".history-toggle + .details-body { display:block !important; }",
    )
    forbidden_report_markers = (
        "PACKAGE-RAW-CANARY",
        "PACKAGE-DIAGNOSTIC-CANARY",
        "PARSE_PARTIAL",
        "report-smoke",
        "Troubleshooting",
        "CLI와 Quick Reference",
        "세션별 수치 변화",
        "패킷",
        "바이트",
        "XMLHttpRequest",
        "WebSocket",
        "navigator.clipboard",
        "localStorage",
        "sessionStorage",
        "eval(",
    )
    section_positions = tuple(
        report_text.find(marker) for marker in ("결과 필터", "최신 세션 결과", "전체 추적 이력")
    )
    if (
        "<!doctype html>" not in report_text.casefold()
        or any(marker not in report_text for marker in required_report_markers)
        or any(marker in report_text for marker in forbidden_report_markers)
        or section_positions != tuple(sorted(section_positions))
        or not _report_filter_script_is_hash_authorized(report_text)
        or "<details open" in report_text
        or "https://" in report_text.casefold()
        or "http://" in report_text.casefold()
    ):
        raise ReleaseVerificationError("packaged HTML report is not standalone and complete")


def _report_filter_script_is_hash_authorized(report_text: str) -> bool:
    scripts = re.findall(r"<script>(.*?)</script>", report_text, flags=re.IGNORECASE | re.DOTALL)
    if len(scripts) != 1:
        return False
    digest = base64.b64encode(hashlib.sha256(scripts[0].encode("utf-8")).digest()).decode("ascii")
    return f"script-src 'sha256-{digest}'" in report_text


def _packaged_environment() -> dict[str, str]:
    """Return a Windows smoke environment with no development Python on PATH."""

    environment = os.environ.copy()
    for name in ("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV", "CONDA_PREFIX"):
        environment.pop(name, None)
    system_root = environment.get("SystemRoot", r"C:\Windows")
    environment["PATH"] = os.pathsep.join((str(Path(system_root) / "System32"), system_root))
    return environment


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", type=Path, required=True)
    parser.add_argument("--sha256", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--runtime-lock", type=Path, required=True)
    parser.add_argument("--pyproject", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--expected-commit")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    verify_release(
        zip_path=args.zip,
        sidecar_path=args.sha256,
        sbom_path=args.sbom,
        runtime_lock=args.runtime_lock,
        pyproject_path=args.pyproject,
        version=args.version,
        expected_commit=args.expected_commit,
        allow_dirty=args.allow_dirty,
    )
    if args.smoke:
        smoke_executable(args.zip)
    print(f"Release package verification passed: {args.zip.name}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ReleaseVerificationError, zipfile.BadZipFile) as error:
        print(f"release-verify: {error}", file=sys.stderr)
        sys.exit(1)
