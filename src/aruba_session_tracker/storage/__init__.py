"""Public local-persistence API for Aruba Session Tracker."""

from aruba_session_tracker.storage.csv_export import guard_csv_cell, write_csv_atomic
from aruba_session_tracker.storage.html_report import (
    RunReportSnapshot,
    render_html_report,
    write_html_report_atomic,
)
from aruba_session_tracker.storage.raw import RawArtifact, RawOutputStore, UnsafeStoragePath
from aruba_session_tracker.storage.session_store import (
    DeletePreview,
    DeletionResult,
    SessionStore,
    StorageError,
)

__all__ = [
    "DeletePreview",
    "DeletionResult",
    "RawArtifact",
    "RawOutputStore",
    "RunReportSnapshot",
    "SessionStore",
    "StorageError",
    "UnsafeStoragePath",
    "guard_csv_cell",
    "render_html_report",
    "write_csv_atomic",
    "write_html_report_atomic",
]
