"""Read-only SSH collection primitives."""

from .ssh import (
    MAX_OUTPUT_BYTES,
    MAX_OUTPUT_LINES,
    POLL_DEADLINE_SECONDS,
    CancellationToken,
    CollectorError,
    CommandBatch,
    CommandConnection,
    CommandOutput,
    HostKeyApproval,
    HostKeyInfo,
    PollDeadline,
    SSHCollector,
    SSHConnectionFactory,
    StrictNetmikoFactory,
    run_bounded_approval,
)

__all__ = [
    "MAX_OUTPUT_BYTES",
    "MAX_OUTPUT_LINES",
    "POLL_DEADLINE_SECONDS",
    "CancellationToken",
    "CollectorError",
    "CommandBatch",
    "CommandConnection",
    "CommandOutput",
    "HostKeyApproval",
    "HostKeyInfo",
    "PollDeadline",
    "SSHCollector",
    "SSHConnectionFactory",
    "StrictNetmikoFactory",
    "run_bounded_approval",
]
