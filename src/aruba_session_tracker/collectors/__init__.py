"""Read-only SSH collection primitives."""

from .ssh import (
    MAX_OUTPUT_BYTES,
    MAX_OUTPUT_LINES,
    CancellationToken,
    CollectorError,
    CommandBatch,
    CommandConnection,
    CommandOutput,
    HostKeyApproval,
    HostKeyInfo,
    SSHCollector,
    SSHConnectionFactory,
    StrictNetmikoFactory,
)

__all__ = [
    "MAX_OUTPUT_BYTES",
    "MAX_OUTPUT_LINES",
    "CancellationToken",
    "CollectorError",
    "CommandBatch",
    "CommandConnection",
    "CommandOutput",
    "HostKeyApproval",
    "HostKeyInfo",
    "SSHCollector",
    "SSHConnectionFactory",
    "StrictNetmikoFactory",
]
