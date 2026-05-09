"""Audit store and logging."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol

from .types import AuditEntry, AuditEntryInput, AuditQueryOptions


class AuditStore(Protocol):
    def append(self, entry: AuditEntry) -> None: ...
    def query(self, token_id: str, options: AuditQueryOptions | None = None) -> list[AuditEntry]: ...
    def query_by_service(self, service: str, options: AuditQueryOptions | None = None) -> list[AuditEntry]: ...


class MemoryAuditStore:
    """In-memory audit store for dev/testing."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def append(self, entry: AuditEntry) -> None:
        self._entries.append(entry)

    def query(self, token_id: str, options: AuditQueryOptions | None = None) -> list[AuditEntry]:
        results = [e for e in self._entries if e.token_id == token_id]
        return _apply_query_options(results, options)

    def query_by_service(self, service: str, options: AuditQueryOptions | None = None) -> list[AuditEntry]:
        results = [e for e in self._entries if e.service == service]
        return _apply_query_options(results, options)


def _apply_query_options(entries: list[AuditEntry], options: AuditQueryOptions | None) -> list[AuditEntry]:
    if options is None:
        return entries

    results = entries
    if options.from_time:
        results = [e for e in results if e.timestamp >= options.from_time]
    if options.to_time:
        results = [e for e in results if e.timestamp <= options.to_time]
    if options.action:
        results = [e for e in results if e.action == options.action]
    if options.service:
        results = [e for e in results if e.service == options.service]
    if options.result:
        results = [e for e in results if e.result == options.result]
    if options.offset:
        results = results[options.offset:]
    if options.limit:
        results = results[: options.limit]

    return results


def log_action(
    token_id: str,
    entry: AuditEntryInput,
    store: AuditStore | None = None,
) -> None:
    """Log an action against a token. Mirrors the TypeScript logAction signature."""
    if store is None:
        raise ValueError("audit store is required")

    store.append(
        AuditEntry(
            token_id=token_id,
            timestamp=datetime.now(timezone.utc),
            action=entry.action,
            service=entry.service,
            result=entry.result,
            details=entry.details,
            url=entry.url,
            screenshot_ref=entry.screenshot_ref,
            access_mode=entry.access_mode,
        )
    )


def get_audit_trail(
    token_id: str,
    options: AuditQueryOptions | None = None,
    store: AuditStore | None = None,
) -> list[AuditEntry]:
    """Get the audit trail for a token."""
    if store is None:
        raise ValueError("audit store is required")
    return store.query(token_id, options)


def get_audit_trail_by_service(
    service: str,
    options: AuditQueryOptions | None = None,
    store: AuditStore | None = None,
) -> list[AuditEntry]:
    """Get the audit trail for a service across all tokens."""
    if store is None:
        raise ValueError("audit store is required")
    return store.query_by_service(service, options)
