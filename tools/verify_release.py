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
from typing import Self, cast
from urllib.parse import quote

import paramiko

try:
    from tools.check_packaging_environment import INJECTION_VARIABLES
    from tools.component_manifest import (
        canonical_bundle_paths,
        native_bundle_paths,
        paths_matching_patterns,
        safe_bundle_path,
        select_component_paths,
    )
except ModuleNotFoundError:
    from check_packaging_environment import (  # type: ignore[no-redef, import-not-found]
        INJECTION_VARIABLES,
    )
    from component_manifest import (  # type: ignore[no-redef, import-not-found]
        canonical_bundle_paths,
        native_bundle_paths,
        paths_matching_patterns,
        safe_bundle_path,
        select_component_paths,
    )

PRODUCT = "ArubaSessionTracker"
REQUIRED_BUNDLE_FILES = {
    "ArubaSessionTracker.exe",
    "BUILD_INFO.json",
    "CHANGELOG.md",
    "LICENSE",
    "licenses/cpython/LICENSE.txt",
    "licenses/LGPL-3.0-only.txt",
    "licenses/openssl/LICENSE.txt",
    "licenses/openssl/NOTICE.txt",
    "licenses/pyserial/SUPPLEMENTAL__pyserial-BSD-3-Clause.txt",
    "OPEN_SOURCE_SOURCE_OFFER.txt",
    "README.md",
    "requirements-runtime.lock",
    "SECURITY.md",
    "THIRD_PARTY_COMPONENTS.json",
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
_COMPONENT_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]*$")
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
_WINDOWS_RESERVED_STEMS = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}
_WINDOWS_ILLEGAL_NAME_CHARS = frozenset('<>:"|?*')
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
        return int(paramiko.AUTH_SUCCESSFUL if accepted else paramiko.AUTH_FAILED)

    def get_allowed_auths(self, username: str) -> str:
        del username
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        del chanid
        return int(
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
    for part in member.parts:
        reserved_stem = part.split(".", 1)[0].casefold()
        if (
            part.endswith((" ", "."))
            or any(character in _WINDOWS_ILLEGAL_NAME_CHARS for character in part)
            or any(ord(character) < 32 for character in part)
            or reserved_stem in _WINDOWS_RESERVED_STEMS
        ):
            raise ReleaseVerificationError(
                f"ZIP member has an unsafe Windows path alias: {info.filename}"
            )
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
) -> dict[str, object]:
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
    return cast(dict[str, object], document)


def _manifest_strings(value: object, *, field: str, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ReleaseVerificationError(f"component manifest {field} must be an array of strings")
    result = tuple(value)
    if not allow_empty and not result:
        raise ReleaseVerificationError(f"component manifest {field} must not be empty")
    return result


def _render_component_value(value: str, versions: dict[str, str]) -> str:
    try:
        rendered = value.format_map(versions)
    except KeyError as error:
        raise ReleaseVerificationError(
            f"unknown component manifest placeholder: {error.args[0]}"
        ) from error
    if "{" in rendered or "}" in rendered:
        raise ReleaseVerificationError(f"unresolved component manifest template: {value}")
    return rendered


def _safe_bundle_relative(value: str, *, field: str) -> PurePosixPath:
    try:
        return safe_bundle_path(value, field=field)
    except ValueError as error:
        raise ReleaseVerificationError(str(error)) from error


def _archive_relative_member(
    files: dict[PurePosixPath, zipfile.ZipInfo], relative: str
) -> zipfile.ZipInfo:
    member = PurePosixPath(PRODUCT) / _safe_bundle_relative(relative, field="bundle path")
    try:
        return files[member]
    except KeyError as error:
        raise ReleaseVerificationError(f"declared bundle file is missing: {relative}") from error


def _archive_sha256(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    with archive.open(info) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inventory_sha256(entries: list[dict[str, str]]) -> str:
    return hashlib.sha256(
        json.dumps(entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _load_component_contract(path: Path) -> dict[str, object]:
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ReleaseVerificationError(
            f"component manifest is not valid UTF-8 TOML: {error}"
        ) from error
    if document.get("schema_version") != 1:
        raise ReleaseVerificationError("component manifest schema_version must be 1")
    if document.get("resolved_manifest") != "THIRD_PARTY_COMPONENTS.json":
        raise ReleaseVerificationError("component manifest resolved_manifest is not canonical")
    if not isinstance(document.get("policy"), dict) or not isinstance(
        document.get("components"), list
    ):
        raise ReleaseVerificationError("component manifest policy or components are missing")
    return document


def _properties(component: dict[str, object]) -> dict[str, str]:
    values = component.get("properties")
    if not isinstance(values, list):
        return {}
    return {
        str(item["name"]): str(item["value"])
        for item in values
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and isinstance(item.get("value"), str)
    }


def _verify_source_offer(
    text: str,
    runtime_components: dict[str, tuple[str, set[str]]],
    *,
    canonical_text: str | None = None,
) -> None:
    if canonical_text is not None and text != canonical_text:
        raise ReleaseVerificationError(
            "LGPL source offer differs from the reviewed repository text"
        )
    expected = (
        f"PySide6-Essentials {runtime_components['pyside6-essentials'][0]}",
        f"Shiboken6 {runtime_components['shiboken6'][0]}",
        f"Qt {runtime_components['pyside6-essentials'][0]} runtime",
        f"Paramiko {runtime_components['paramiko'][0]}",
        "https://github.com/sebia1993/aruba-session-tracker-1/issues/new",
        'title "LGPL source request"',
        "at least three years",
        "no-charge",
        "BUILD_INFO.json",
        "Automated package verification confirms only",
        "future availability",
    )
    if any(value not in text for value in expected):
        raise ReleaseVerificationError("LGPL source offer is incomplete or version-stale")
    if re.search(r"\b(?:TODO|TBD)\b|<[^>]*(?:email|contact)[^>]*>", text, re.IGNORECASE):
        raise ReleaseVerificationError("LGPL source offer contains a placeholder")


def _metadata_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ": " not in line:
            continue
        name, value = line.split(": ", 1)
        if name in fields:
            raise ReleaseVerificationError(f"duplicate license metadata field: {name}")
        fields[name] = value
    return fields


def _verify_license_evidence(
    *,
    archive: zipfile.ZipFile,
    files: dict[PurePosixPath, zipfile.ZipInfo],
    relative_names: set[str],
    runtime_components: dict[str, tuple[str, set[str]]],
    component_manifest_path: Path,
    contract: dict[str, object],
    resolved: dict[str, object],
    sbom_root: dict[str, object],
) -> None:
    cpython = archive.read(_archive_relative_member(files, "licenses/cpython/LICENSE.txt")).decode(
        "utf-8"
    )
    if "PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2" not in cpython:
        raise ReleaseVerificationError("CPython distribution license evidence is incomplete")
    openssl_license = archive.read(
        _archive_relative_member(files, "licenses/openssl/LICENSE.txt")
    ).decode("utf-8")
    openssl_notice = archive.read(
        _archive_relative_member(files, "licenses/openssl/NOTICE.txt")
    ).decode("utf-8")
    if "Apache License" not in openssl_license or "Version 2.0" not in openssl_license:
        raise ReleaseVerificationError("OpenSSL Apache-2.0 license evidence is incomplete")
    if "OpenSSL Project Authors" not in openssl_notice:
        raise ReleaseVerificationError("OpenSSL copyright notice is incomplete")

    raw_fallbacks = contract.get("license_fallbacks", [])
    if not isinstance(raw_fallbacks, list):
        raise ReleaseVerificationError("component manifest license_fallbacks are invalid")
    expected_fallbacks: list[dict[str, str]] = []
    fallback_packages: set[str] = set()
    for raw in raw_fallbacks:
        if not isinstance(raw, dict):
            raise ReleaseVerificationError("component manifest license fallback is invalid")
        package = raw.get("package")
        version = raw.get("version")
        source_file = raw.get("source_file")
        source_url = raw.get("source_url")
        digest = raw.get("sha256")
        if not all(
            isinstance(value, str) and value
            for value in (package, version, source_file, source_url, digest)
        ):
            raise ReleaseVerificationError("component manifest license fallback is incomplete")
        assert isinstance(package, str)
        assert isinstance(version, str)
        assert isinstance(source_file, str)
        assert isinstance(source_url, str)
        assert isinstance(digest, str)
        normalized = _normalized_package_name(package)
        locked = runtime_components.get(normalized)
        if (
            normalized in fallback_packages
            or locked is None
            or locked[0] != version
            or not source_url.startswith("https://")
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise ReleaseVerificationError(f"license fallback contract differs: {normalized}")
        fallback_packages.add(normalized)
        source_name = _safe_bundle_relative(source_file, field="license_fallbacks.source_file").name
        bundle_path = f"licenses/{normalized}/SUPPLEMENTAL__{source_name}"
        actual_hash = _archive_sha256(archive, _archive_relative_member(files, bundle_path))
        if not hmac.compare_digest(actual_hash, digest):
            raise ReleaseVerificationError(f"license fallback bundle hash differs: {normalized}")
        if normalized == "pyserial":
            fallback_source = component_manifest_path.parent / "licenses/pyserial-BSD-3-Clause.txt"
            expected_fallback_hash = hashlib.sha256(fallback_source.read_bytes()).hexdigest()
            fallback_bytes = archive.read(_archive_relative_member(files, bundle_path))
            if (
                expected_fallback_hash
                != "f91cb9813de6a5b142b8f7f2dede630b5134160aedaeaf55f4d6a7e2593ca3f3"
                or hashlib.sha256(fallback_bytes).hexdigest() != expected_fallback_hash
                or b"SPDX-License-Identifier:    BSD-3-Clause" not in fallback_bytes
            ):
                raise ReleaseVerificationError("pyserial BSD-3-Clause fallback evidence differs")
        expected_fallbacks.append(
            {
                "bundle_path": bundle_path,
                "package": normalized,
                "sha256": digest,
                "source_url": source_url,
                "version": version,
            }
        )
    if resolved.get("license_fallbacks") != expected_fallbacks:
        raise ReleaseVerificationError("resolved license fallbacks differ from source contract")

    for name, (version, _hashes) in runtime_components.items():
        prefix = f"licenses/{name}/"
        metadata_path = f"{prefix}PACKAGE-METADATA.txt"
        try:
            metadata_text = archive.read(_archive_relative_member(files, metadata_path)).decode(
                "utf-8"
            )
        except UnicodeDecodeError as error:
            raise ReleaseVerificationError(
                f"runtime license metadata is not UTF-8: {name}"
            ) from error
        metadata = _metadata_fields(metadata_text)
        try:
            wheel_count = int(metadata["Wheel-License-Files-Copied"])
            supplemental_count = int(metadata["Supplemental-License-Files-Copied"])
            total_count = int(metadata["License-Evidence-Files-Copied"])
        except (KeyError, ValueError) as error:
            raise ReleaseVerificationError(
                f"runtime license evidence counts are invalid: {name}"
            ) from error
        evidence_paths = sorted(
            value for value in relative_names if value.startswith(prefix) and value != metadata_path
        )
        if (
            _normalized_package_name(metadata.get("Package", "")) != name
            or metadata.get("Version") != version
            or wheel_count < 0
            or supplemental_count < 0
            or total_count != wheel_count + supplemental_count
            or total_count == 0
            or len(evidence_paths) != total_count
            or (wheel_count == 0 and name not in fallback_packages)
        ):
            raise ReleaseVerificationError(f"runtime license evidence is incomplete: {name}")

    evidence_paths = sorted(
        value
        for value in relative_names
        if value.startswith("licenses/")
        or value in {"OPEN_SOURCE_SOURCE_OFFER.txt", "THIRD_PARTY_NOTICES.txt"}
    )
    evidence_entries = [
        {
            "path": relative,
            "sha256": _archive_sha256(archive, _archive_relative_member(files, relative)),
        }
        for relative in evidence_paths
    ]
    inventory_hash = _inventory_sha256(evidence_entries)
    if (
        resolved.get("license_evidence") != evidence_entries
        or resolved.get("license_evidence_inventory_sha256") != inventory_hash
    ):
        raise ReleaseVerificationError("resolved license evidence inventory differs")
    root_properties = _properties(sbom_root)
    if (
        root_properties.get("aruba-session-tracker:license-evidence-inventory-sha256")
        != inventory_hash
        or root_properties.get("aruba-session-tracker:resolved-manifest")
        != "THIRD_PARTY_COMPONENTS.json"
    ):
        raise ReleaseVerificationError("SBOM root does not bind the license evidence inventory")


def _verify_native_components(
    *,
    archive: zipfile.ZipFile,
    files: dict[PurePosixPath, zipfile.ZipInfo],
    relative_names: set[str],
    sbom_document: dict[str, object],
    build_info: dict[str, object],
    component_manifest_path: Path,
    runtime_lock: Path,
    build_lock: Path,
) -> None:
    contract = _load_component_contract(component_manifest_path)
    policy = contract["policy"]
    raw_components = contract["components"]
    assert isinstance(policy, dict) and isinstance(raw_components, list)

    python_version = build_info.get("python")
    openssl_version = build_info.get("openssl")
    cryptography_openssl_version = build_info.get("cryptographyOpenssl")
    libyaml_version = build_info.get("libyaml")
    pyinstaller_version = build_info.get("pyinstaller")
    qt_version = build_info.get("qt")
    sqlite_version = build_info.get("sqlite")
    if any(
        not isinstance(value, str) or _VERSION.fullmatch(value) is None
        for value in (
            python_version,
            openssl_version,
            cryptography_openssl_version,
            libyaml_version,
            pyinstaller_version,
            qt_version,
            sqlite_version,
        )
    ):
        raise ReleaseVerificationError("BUILD_INFO native component versions are missing")
    assert isinstance(python_version, str)
    assert isinstance(openssl_version, str)
    assert isinstance(cryptography_openssl_version, str)
    assert isinstance(libyaml_version, str)
    assert isinstance(pyinstaller_version, str)
    assert isinstance(qt_version, str)
    assert isinstance(sqlite_version, str)

    build_components = _locked_components(build_lock)
    expected_pyinstaller = build_components.get("pyinstaller")
    if expected_pyinstaller is None or expected_pyinstaller[0] != pyinstaller_version:
        raise ReleaseVerificationError("PyInstaller native component version is not build-locked")
    runtime_components = _locked_components(runtime_lock)
    pyside_version = runtime_components.get("pyside6-essentials")
    shiboken_version = runtime_components.get("shiboken6")
    if (
        pyside_version is None
        or shiboken_version is None
        or pyside_version[0] != shiboken_version[0]
        or pyside_version[0] != qt_version
    ):
        raise ReleaseVerificationError(
            "locked PySide6/Shiboken versions do not match BUILD_INFO Qt"
        )
    versions = {
        "cryptography_openssl_version": cryptography_openssl_version,
        "libyaml_version": libyaml_version,
        "openssl_version": openssl_version,
        "pyinstaller_version": pyinstaller_version,
        "python_version": python_version,
        "qt_version": qt_version,
        "sqlite_version": sqlite_version,
        **{
            f"{name.replace('-', '_')}_version": version
            for name, (version, _hashes) in runtime_components.items()
        },
    }

    required = _manifest_strings(
        policy.get("required_bundle_files"), field="policy.required_bundle_files", allow_empty=True
    )
    forbidden_globs = _manifest_strings(
        policy.get("forbidden_bundle_globs"),
        field="policy.forbidden_bundle_globs",
        allow_empty=True,
    )
    try:
        indexed_paths = canonical_bundle_paths(relative_names)
        forbidden_present = sorted(paths_matching_patterns(relative_names, forbidden_globs))
    except ValueError as error:
        raise ReleaseVerificationError(str(error)) from error
    if any(value.casefold() not in indexed_paths for value in required):
        raise ReleaseVerificationError("required native bundle policy file is missing")
    if forbidden_present:
        raise ReleaseVerificationError(
            f"forbidden native bundle file is present: {forbidden_present[0]}"
        )

    resolved_info = _archive_relative_member(files, "THIRD_PARTY_COMPONENTS.json")
    try:
        resolved = json.loads(archive.read(resolved_info).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseVerificationError(
            "resolved component manifest is not valid UTF-8 JSON"
        ) from error
    if resolved.get("schema_version") != 1 or resolved.get("policy") != {
        "forbidden_bundle_globs": list(forbidden_globs),
        "required_bundle_files": list(required),
    }:
        raise ReleaseVerificationError("resolved component manifest policy differs from source")
    resolved_components = resolved.get("components")
    if not isinstance(resolved_components, list):
        raise ReleaseVerificationError("resolved component manifest components are missing")
    actual_by_id = {
        item.get("id"): item
        for item in resolved_components
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    if len(actual_by_id) != len(resolved_components):
        raise ReleaseVerificationError("resolved component manifest has duplicate or invalid ids")

    sbom_components = sbom_document.get("components")
    metadata = sbom_document.get("metadata")
    dependencies = sbom_document.get("dependencies")
    if (
        not isinstance(sbom_components, list)
        or not isinstance(metadata, dict)
        or not isinstance(dependencies, list)
    ):
        raise ReleaseVerificationError("SBOM native component structure is incomplete")
    sbom_by_ref = {
        item.get("bom-ref"): item
        for item in sbom_components
        if isinstance(item, dict) and isinstance(item.get("bom-ref"), str)
    }
    root = metadata.get("component")
    if not isinstance(root, dict) or not isinstance(root.get("bom-ref"), str):
        raise ReleaseVerificationError("SBOM root component is missing")
    root_ref = root["bom-ref"]
    root_dependencies = next(
        (
            item.get("dependsOn")
            for item in dependencies
            if isinstance(item, dict) and item.get("ref") == root_ref
        ),
        None,
    )
    if not isinstance(root_dependencies, list):
        raise ReleaseVerificationError("SBOM root native dependency graph is incomplete")

    declared_ids: set[str] = set()
    expected_ids: set[str] = set()
    assigned_files: set[str] = set()
    for raw in raw_components:
        if not isinstance(raw, dict):
            raise ReleaseVerificationError("component manifest entry is invalid")
        component_id = raw.get("id")
        optional = raw.get("optional", False)
        if (
            not isinstance(component_id, str)
            or _COMPONENT_ID.fullmatch(component_id) is None
            or not isinstance(optional, bool)
        ):
            raise ReleaseVerificationError("component manifest entry is invalid")
        if component_id in declared_ids:
            raise ReleaseVerificationError(f"duplicate component manifest id: {component_id}")
        declared_ids.add(component_id)
        raw_version = raw.get("version")
        if not isinstance(raw_version, str):
            raise ReleaseVerificationError(f"native component version is missing: {component_id}")
        version = _render_component_value(raw_version, versions)

        exact_files = tuple(
            _render_component_value(value, versions)
            for value in _manifest_strings(
                raw.get("files", []), field=f"{component_id}.files", allow_empty=True
            )
        )
        globs = tuple(
            _render_component_value(value, versions)
            for value in _manifest_strings(
                raw.get("globs", []), field=f"{component_id}.globs", allow_empty=True
            )
        )
        exclude_globs = tuple(
            _render_component_value(value, versions)
            for value in _manifest_strings(
                raw.get("exclude_globs", []),
                field=f"{component_id}.exclude_globs",
                allow_empty=True,
            )
        )
        try:
            expected_files = select_component_paths(
                relative_names,
                files=exact_files,
                globs=globs,
                exclude_globs=exclude_globs,
                field=component_id,
            )
        except ValueError as error:
            raise ReleaseVerificationError(str(error)) from error
        if not expected_files:
            if optional:
                continue
            raise ReleaseVerificationError(
                f"native component matched no bundle files: {component_id}"
            )
        expected_ids.add(component_id)
        actual = actual_by_id.get(component_id)
        if not isinstance(actual, dict):
            raise ReleaseVerificationError(f"resolved native component is missing: {component_id}")
        expected_ref = f"native:{component_id}@{version}"
        expected_scalar = {
            "bom_ref": expected_ref,
            "id": component_id,
            "license_id": raw.get("license_id"),
            "license_name": raw.get("license_name"),
            "name": raw.get("name"),
            "type": raw.get("type"),
            "version": version,
        }
        if any(actual.get(key) != value for key, value in expected_scalar.items()):
            raise ReleaseVerificationError(
                f"resolved native component metadata differs: {component_id}"
            )
        if (isinstance(actual.get("license_id"), str)) == (
            isinstance(actual.get("license_name"), str)
        ):
            raise ReleaseVerificationError(
                f"resolved native component license is invalid: {component_id}"
            )

        license_paths = [
            _render_component_value(value, versions)
            for value in _manifest_strings(
                raw.get("license_files"), field=f"{component_id}.license_files"
            )
        ]
        license_entries = [
            {
                "path": relative,
                "sha256": _archive_sha256(archive, _archive_relative_member(files, relative)),
            }
            for relative in license_paths
        ]
        source_urls = [
            _render_component_value(value, versions)
            for value in _manifest_strings(
                raw.get("source_urls"), field=f"{component_id}.source_urls"
            )
        ]
        if any(not value.startswith("https://") for value in source_urls):
            raise ReleaseVerificationError(
                f"native component source URL is not HTTPS: {component_id}"
            )
        if (
            actual.get("license_files") != license_entries
            or actual.get("source_urls") != source_urls
        ):
            raise ReleaseVerificationError(
                f"resolved native component evidence differs: {component_id}"
            )

        raw_file_entries = actual.get("files")
        if not isinstance(raw_file_entries, list):
            raise ReleaseVerificationError(
                f"native component file inventory is missing: {component_id}"
            )
        actual_files: dict[str, str] = {}
        for entry in raw_file_entries:
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("path"), str)
                or not isinstance(entry.get("sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is None
                or entry["path"] in actual_files
            ):
                raise ReleaseVerificationError(
                    f"native component file entry is invalid: {component_id}"
                )
            actual_files[entry["path"]] = entry["sha256"]
        if set(actual_files) != expected_files:
            raise ReleaseVerificationError(f"native component file set differs: {component_id}")
        overlap = assigned_files & expected_files
        if overlap:
            raise ReleaseVerificationError(
                f"native bundle file belongs to multiple components: {sorted(overlap)[0]}"
            )
        assigned_files.update(expected_files)
        for relative, expected_hash in actual_files.items():
            actual_hash = _archive_sha256(archive, _archive_relative_member(files, relative))
            if not hmac.compare_digest(actual_hash, expected_hash):
                raise ReleaseVerificationError(f"native component file hash differs: {relative}")
        canonical_files = [
            {"path": relative, "sha256": actual_files[relative]}
            for relative in sorted(actual_files)
        ]
        inventory_hash = _inventory_sha256(canonical_files)
        if actual.get("inventory_sha256") != inventory_hash:
            raise ReleaseVerificationError(
                f"native component inventory hash differs: {component_id}"
            )

        sbom_component = sbom_by_ref.get(expected_ref)
        if not isinstance(sbom_component, dict):
            raise ReleaseVerificationError(f"SBOM native component is missing: {component_id}")
        if (
            sbom_component.get("name") != raw.get("name")
            or sbom_component.get("type") != raw.get("type")
            or sbom_component.get("version") != version
        ):
            raise ReleaseVerificationError(
                f"SBOM native component metadata differs: {component_id}"
            )
        expected_license = (
            {"id": raw["license_id"]}
            if isinstance(raw.get("license_id"), str)
            else {"name": raw["license_name"]}
        )
        if sbom_component.get("licenses") != [{"license": expected_license}]:
            raise ReleaseVerificationError(f"SBOM native component license differs: {component_id}")
        expected_references = [
            *({"type": "distribution", "url": source_url} for source_url in source_urls),
            *(
                {
                    "hashes": [{"alg": "SHA-256", "content": entry["sha256"]}],
                    "type": "license",
                    "url": (f"urn:aruba-session-tracker:bundle:{quote(entry['path'], safe='')}"),
                }
                for entry in license_entries
            ),
        ]
        if sbom_component.get("externalReferences") != expected_references:
            raise ReleaseVerificationError(
                f"SBOM native component source references differ: {component_id}"
            )
        properties = _properties(sbom_component)
        if properties != {
            "aruba-session-tracker:component-id": component_id,
            "aruba-session-tracker:inventory-sha256": inventory_hash,
            "aruba-session-tracker:resolved-manifest": "THIRD_PARTY_COMPONENTS.json",
        }:
            raise ReleaseVerificationError(
                f"SBOM native component properties differ: {component_id}"
            )
        if expected_ref not in root_dependencies:
            raise ReleaseVerificationError(f"SBOM root omits native component: {component_id}")

    try:
        unassigned_native = sorted(native_bundle_paths(relative_names) - assigned_files)
    except ValueError as error:
        raise ReleaseVerificationError(str(error)) from error
    if unassigned_native:
        raise ReleaseVerificationError(
            f"native bundle file is not assigned to a component: {unassigned_native[0]}"
        )
    if set(actual_by_id) != expected_ids:
        raise ReleaseVerificationError("resolved component manifest has an undeclared component")
    offer = archive.read(_archive_relative_member(files, "OPEN_SOURCE_SOURCE_OFFER.txt")).decode(
        "utf-8"
    )
    canonical_offer_path = component_manifest_path.parent / "OPEN_SOURCE_SOURCE_OFFER.txt"
    try:
        canonical_offer = canonical_offer_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ReleaseVerificationError("reviewed LGPL source offer is unavailable") from error
    _verify_source_offer(offer, runtime_components, canonical_text=canonical_offer)
    _verify_license_evidence(
        archive=archive,
        files=files,
        relative_names=relative_names,
        runtime_components=runtime_components,
        component_manifest_path=component_manifest_path,
        contract=contract,
        resolved=resolved,
        sbom_root=root,
    )


def verify_release(
    *,
    zip_path: Path,
    sidecar_path: Path,
    sbom_path: Path,
    runtime_lock: Path,
    build_lock: Path,
    pyproject_path: Path,
    component_manifest_path: Path,
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
    sbom_document = _verify_sbom(sbom_path, version, runtime_lock, pyproject_path)

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
        if not isinstance(build_info, dict):
            raise ReleaseVerificationError("BUILD_INFO must be a JSON object")
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
        _verify_native_components(
            archive=archive,
            files=files,
            relative_names=relative_names,
            sbom_document=sbom_document,
            build_info=build_info,
            component_manifest_path=component_manifest_path,
            runtime_lock=runtime_lock,
            build_lock=build_lock,
        )


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

        try:
            tls_result = subprocess.run(  # noqa: S603
                [executable, "--tls-backend-smoke"],
                check=False,
                capture_output=True,
                timeout=30,
                env=_packaged_environment(),
            )
        except subprocess.TimeoutExpired as error:
            raise ReleaseVerificationError("packaged Schannel backend smoke timed out") from error
        if (
            tls_result.returncode != 0
            or b"ARUBA_SESSION_TRACKER_TLS_BACKEND_OK active=schannel" not in tls_result.stdout
        ):
            raise ReleaseVerificationError("packaged Qt TLS backend is not Schannel-only")

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
        "결과 찾기",
        "최신 세션 결과",
        "전체 추적 이력",
        "조회 출발지",
        "조회 대상",
        "IP별 관측 횟수 TOP 5",
        "포트·프로토콜별 관측 횟수 TOP 5",
        "출발지 IP·포트",
        "목적지 IP·포트",
        "KST",
        "한국어-MD",
        'id="result-filter"',
        'id="filter-ip"',
        'id="filter-protocol"',
        'id="filter-port"',
        'class="report-row"',
        'class="flow-panel"',
        'class="summary-stats"',
        'class="frequency-list"',
        'class="frequency-bar" aria-hidden="true"',
        'class="protocol-cell"',
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
        "프로토콜별 최신 세션",
        "장비별 최신 세션",
        "최신 표시 세션 상태",
        "주요 세션 변화",
        "XMLHttpRequest",
        "WebSocket",
        "navigator.clipboard",
        "localStorage",
        "sessionStorage",
        "eval(",
    )
    section_positions = tuple(
        report_text.find(marker)
        for marker in (
            "전체 이력 관측 빈도 TOP 5",
            "결과 찾기",
            "최신 세션 결과",
            "전체 추적 이력",
        )
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
    for name in INJECTION_VARIABLES:
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
    parser.add_argument("--build-lock", type=Path, required=True)
    parser.add_argument("--pyproject", type=Path, required=True)
    parser.add_argument("--component-manifest", type=Path, required=True)
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
        build_lock=args.build_lock,
        pyproject_path=args.pyproject,
        component_manifest_path=args.component_manifest,
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
