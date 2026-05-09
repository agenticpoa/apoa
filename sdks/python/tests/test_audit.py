"""Tests for audit logging and querying."""

from datetime import datetime, timezone

from apoa import (
    AuditEntry,
    AuditEntryInput,
    AuditQueryOptions,
    MemoryAuditStore,
    get_audit_trail,
    get_audit_trail_by_service,
    log_action,
)


class TestAuditStore:
    def test_append_and_query(self):
        store = MemoryAuditStore()
        entry = AuditEntry(
            token_id="token-1",
            timestamp=datetime.now(timezone.utc),
            action="read",
            service="test.com",
            result="allowed",
        )
        store.append(entry)
        results = store.query("token-1")
        assert len(results) == 1
        assert results[0].action == "read"

    def test_query_by_service(self):
        store = MemoryAuditStore()
        store.append(AuditEntry(token_id="t1", timestamp=datetime.now(timezone.utc), action="read", service="a.com", result="allowed"))
        store.append(AuditEntry(token_id="t2", timestamp=datetime.now(timezone.utc), action="write", service="b.com", result="allowed"))
        store.append(AuditEntry(token_id="t3", timestamp=datetime.now(timezone.utc), action="read", service="a.com", result="denied"))

        assert len(store.query_by_service("a.com")) == 2
        assert len(store.query_by_service("b.com")) == 1

    def test_query_with_filters(self):
        store = MemoryAuditStore()
        store.append(AuditEntry(token_id="t1", timestamp=datetime.now(timezone.utc), action="read", service="a.com", result="allowed"))
        store.append(AuditEntry(token_id="t1", timestamp=datetime.now(timezone.utc), action="write", service="a.com", result="denied"))
        store.append(AuditEntry(token_id="t1", timestamp=datetime.now(timezone.utc), action="read", service="a.com", result="allowed"))

        results = store.query("t1", AuditQueryOptions(result="allowed"))
        assert len(results) == 2

        results = store.query("t1", AuditQueryOptions(action="write"))
        assert len(results) == 1

        results = store.query("t1", AuditQueryOptions(limit=1))
        assert len(results) == 1


class TestLogAction:
    def test_log_action(self):
        store = MemoryAuditStore()
        log_action(
            "token-1",
            AuditEntryInput(
                action="rate_lock:read",
                service="mortgage.com",
                result="allowed",
                details={"note": "routine check"},
            ),
            store,
        )
        entries = get_audit_trail("token-1", store=store)
        assert len(entries) == 1
        assert entries[0].action == "rate_lock:read"
        assert entries[0].details["note"] == "routine check"

    def test_log_action_browser_fields(self):
        store = MemoryAuditStore()
        log_action(
            "token-1",
            AuditEntryInput(
                action="rate_lock:read",
                service="mortgage.com",
                result="allowed",
                url="https://portal.mortgage.com/rate-lock",
                access_mode="browser",
                screenshot_ref="s3://audit/rate-lock-001.png",
            ),
            store,
        )
        entry = get_audit_trail("token-1", store=store)[0]
        assert entry.url == "https://portal.mortgage.com/rate-lock"
        assert entry.access_mode == "browser"
        assert entry.screenshot_ref == "s3://audit/rate-lock-001.png"

    def test_get_audit_trail_by_service(self):
        store = MemoryAuditStore()
        log_action("t1", AuditEntryInput(action="read", service="a.com", result="allowed"), store)
        log_action("t2", AuditEntryInput(action="write", service="a.com", result="allowed"), store)
        results = get_audit_trail_by_service("a.com", store=store)
        assert len(results) == 2
