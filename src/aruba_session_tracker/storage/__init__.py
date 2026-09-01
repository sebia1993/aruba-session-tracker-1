"""Public local-persistence API for Aruba Session Tracker."""

from typing import Any, cast

from aruba_session_tracker.storage import html_report, session_store
from aruba_session_tracker.storage.csv_export import guard_csv_cell, write_csv_atomic
from aruba_session_tracker.storage.html_report import RunReportSnapshot
from aruba_session_tracker.storage.html_report_presentation import (
    render_html_report,
    write_html_report_atomic,
    write_html_report_stream_atomic,
)
from aruba_session_tracker.storage.raw import RawArtifact, RawOutputStore, UnsafeStoragePath
from aruba_session_tracker.storage.session_store import (
    DeletePreview,
    DeletionResult,
    PollPersistenceIndeterminate,
    PollPersistenceResult,
    PollPersistenceStatus,
    SessionStore,
    StorageError,
    StorageHealth,
)

# Keep direct submodule imports and SessionStore's established import path on the
# approved presentation without changing the proven serializer/atomic writer.
_html_report_module = cast(Any, html_report)
_html_report_module.render_html_report = render_html_report
_html_report_module.write_html_report_atomic = write_html_report_atomic
_html_report_module.write_html_report_stream_atomic = write_html_report_stream_atomic
_session_store_module = cast(Any, session_store)
_session_store_module.write_html_report_stream_atomic = write_html_report_stream_atomic

__all__ = [
    "DeletePreview",
    "DeletionResult",
    "PollPersistenceIndeterminate",
    "PollPersistenceResult",
    "PollPersistenceStatus",
    "RawArtifact",
    "RawOutputStore",
    "RunReportSnapshot",
    "SessionStore",
    "StorageError",
    "StorageHealth",
    "UnsafeStoragePath",
    "guard_csv_cell",
    "render_html_report",
    "write_csv_atomic",
    "write_html_report_atomic",
]
