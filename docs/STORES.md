# Production Store Adapters

The SDK ships `MemoryRevocationStore` and `MemoryAuditStore` for dev and tests. For production, implement the interfaces against your own infrastructure.

This guide gives concrete adapter recipes for two common pairings — **Redis for revocation** (low-latency check on every `authorize()` call) and **Postgres for audit** (durable append-only log). Both stores are pluggable, so you can mix and match: Postgres revocation, DynamoDB audit, whatever fits your stack.

---

## RevocationStore

The interface is identical across SDKs (TypeScript is async, Python is sync to match each ecosystem's idioms).

**TypeScript:**
```typescript
interface RevocationStore {
  add(record: RevocationRecord): Promise<void>;
  check(tokenId: string): Promise<RevocationRecord | null>;
  list(principalId: string): Promise<RevocationRecord[]>;
}
```

**Python:**
```python
class RevocationStore(Protocol):
    def add(self, record: RevocationRecord) -> None: ...
    def check(self, token_id: str) -> RevocationRecord | None: ...
    def list(self, principal_id: str) -> list[RevocationRecord]: ...
```

`check()` is on the hot path — `authorize()` calls it before every action. Optimize for read latency; durability matters less than for audit (revoking is idempotent — losing a revocation in flight just means re-revoking).

### Redis adapter — TypeScript (`ioredis`)

```typescript
import Redis from 'ioredis';
import type { RevocationRecord, RevocationStore } from '@apoa/core';

export class RedisRevocationStore implements RevocationStore {
  constructor(private redis: Redis, private prefix = 'apoa:rev') {}

  async add(record: RevocationRecord): Promise<void> {
    const key = `${this.prefix}:${record.tokenId}`;
    const principalKey = `${this.prefix}:by-principal:${record.revokedBy}`;
    await this.redis
      .multi()
      .set(key, JSON.stringify({ ...record, revokedAt: record.revokedAt.toISOString() }))
      .sadd(principalKey, record.tokenId)
      .exec();
  }

  async check(tokenId: string): Promise<RevocationRecord | null> {
    const raw = await this.redis.get(`${this.prefix}:${tokenId}`);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return { ...parsed, revokedAt: new Date(parsed.revokedAt) };
  }

  async list(principalId: string): Promise<RevocationRecord[]> {
    const tokenIds = await this.redis.smembers(`${this.prefix}:by-principal:${principalId}`);
    if (tokenIds.length === 0) return [];
    const keys = tokenIds.map((id) => `${this.prefix}:${id}`);
    const raws = await this.redis.mget(...keys);
    return raws
      .filter((r): r is string => r !== null)
      .map((r) => {
        const parsed = JSON.parse(r);
        return { ...parsed, revokedAt: new Date(parsed.revokedAt) };
      });
  }
}
```

Use it:
```typescript
import Redis from 'ioredis';
import { createClient } from '@apoa/core';

const apoa = createClient({
  revocationStore: new RedisRevocationStore(new Redis(process.env.REDIS_URL!)),
  // ...
});
```

### Redis adapter — Python (`redis`)

```python
import json
from datetime import datetime
from redis import Redis
from apoa import RevocationRecord


class RedisRevocationStore:
    def __init__(self, redis: Redis, prefix: str = "apoa:rev") -> None:
        self.redis = redis
        self.prefix = prefix

    def add(self, record: RevocationRecord) -> None:
        key = f"{self.prefix}:{record.token_id}"
        principal_key = f"{self.prefix}:by-principal:{record.revoked_by}"
        payload = json.dumps({
            "token_id": record.token_id,
            "revoked_at": record.revoked_at.isoformat(),
            "revoked_by": record.revoked_by,
            "reason": record.reason,
            "cascaded": record.cascaded,
        })
        with self.redis.pipeline() as pipe:
            pipe.set(key, payload)
            pipe.sadd(principal_key, record.token_id)
            pipe.execute()

    def check(self, token_id: str) -> RevocationRecord | None:
        raw = self.redis.get(f"{self.prefix}:{token_id}")
        if raw is None:
            return None
        data = json.loads(raw)
        return RevocationRecord(
            token_id=data["token_id"],
            revoked_at=datetime.fromisoformat(data["revoked_at"]),
            revoked_by=data["revoked_by"],
            reason=data.get("reason"),
            cascaded=data.get("cascaded", []),
        )

    def list(self, principal_id: str) -> list[RevocationRecord]:
        token_ids = self.redis.smembers(f"{self.prefix}:by-principal:{principal_id}")
        if not token_ids:
            return []
        keys = [f"{self.prefix}:{tid.decode() if isinstance(tid, bytes) else tid}" for tid in token_ids]
        raws = self.redis.mget(keys)
        records = []
        for raw in raws:
            if raw is None:
                continue
            data = json.loads(raw)
            records.append(RevocationRecord(
                token_id=data["token_id"],
                revoked_at=datetime.fromisoformat(data["revoked_at"]),
                revoked_by=data["revoked_by"],
                reason=data.get("reason"),
                cascaded=data.get("cascaded", []),
            ))
        return records
```

### Notes

- **TTLs**: revocation records have no natural expiry — a token revoked yesterday is still revoked today. Either keep records forever, or set a TTL beyond the longest token lifetime your principals issue (e.g., 2 years). Don't set a TTL shorter than your max token lifetime.
- **Cascade**: when `cascadeRevoke()` revokes a parent + children, each token gets its own `RevocationRecord` with `cascaded` listing the children. The store doesn't need to know about the cascade structure — `add()` is called once per record.
- **Read-through cache**: `check()` is on the hot path. If your Redis is already an LRU cache, you might add a process-local TTL cache on top to avoid the network roundtrip for hot tokens.

---

## AuditStore

```typescript
interface AuditStore {
  append(entry: AuditEntry): Promise<void>;
  query(tokenId: string, options?: AuditQueryOptions): Promise<AuditEntry[]>;
  queryByService(service: string, options?: AuditQueryOptions): Promise<AuditEntry[]>;
}
```

```python
class AuditStore(Protocol):
    def append(self, entry: AuditEntry) -> None: ...
    def query(self, token_id: str, options: AuditQueryOptions | None = None) -> list[AuditEntry]: ...
    def query_by_service(self, service: str, options: AuditQueryOptions | None = None) -> list[AuditEntry]: ...
```

Audit is append-only and high-volume. Optimize for write throughput and queryability over time ranges. Durability matters — losing audit entries is the worst-case for a compliance story.

### Postgres schema

```sql
CREATE TABLE apoa_audit (
  id BIGSERIAL PRIMARY KEY,
  token_id TEXT NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL,
  action TEXT NOT NULL,
  service TEXT NOT NULL,
  result TEXT NOT NULL CHECK (result IN ('allowed', 'denied', 'escalated')),
  details JSONB,
  url TEXT,
  screenshot_ref TEXT,
  access_mode TEXT
);

CREATE INDEX apoa_audit_token_time ON apoa_audit (token_id, timestamp DESC);
CREATE INDEX apoa_audit_service_time ON apoa_audit (service, timestamp DESC);
```

For very high volume, partition by `timestamp` range (monthly partitions are a reasonable default) and detach + archive old partitions to cold storage on whatever schedule your compliance posture requires.

### Postgres adapter — TypeScript (`pg`)

```typescript
import type { Pool } from 'pg';
import type {
  AuditEntry,
  AuditQueryOptions,
  AuditStore,
} from '@apoa/core';

export class PostgresAuditStore implements AuditStore {
  constructor(private pool: Pool) {}

  async append(entry: AuditEntry): Promise<void> {
    await this.pool.query(
      `INSERT INTO apoa_audit
        (token_id, timestamp, action, service, result, details, url, screenshot_ref, access_mode)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        entry.tokenId,
        entry.timestamp,
        entry.action,
        entry.service,
        entry.result,
        entry.details ?? null,
        entry.url ?? null,
        entry.screenshotRef ?? null,
        entry.accessMode ?? null,
      ]
    );
  }

  async query(tokenId: string, options?: AuditQueryOptions): Promise<AuditEntry[]> {
    return this.runQuery({ tokenIdEq: tokenId }, options);
  }

  async queryByService(service: string, options?: AuditQueryOptions): Promise<AuditEntry[]> {
    return this.runQuery({ serviceEq: service }, options);
  }

  private async runQuery(
    filter: { tokenIdEq?: string; serviceEq?: string },
    options?: AuditQueryOptions
  ): Promise<AuditEntry[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];
    const push = (cond: string, value: unknown) => {
      params.push(value);
      conditions.push(cond.replace('?', `$${params.length}`));
    };

    if (filter.tokenIdEq) push('token_id = ?', filter.tokenIdEq);
    if (filter.serviceEq) push('service = ?', filter.serviceEq);
    if (options?.from) push('timestamp >= ?', options.from);
    if (options?.to) push('timestamp <= ?', options.to);
    if (options?.action) push('action = ?', options.action);
    if (options?.result) push('result = ?', options.result);
    // service filter on top of the primary filter, when called via query()
    if (options?.service && !filter.serviceEq) push('service = ?', options.service);

    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const sql = `
      SELECT token_id, timestamp, action, service, result, details, url, screenshot_ref, access_mode
      FROM apoa_audit
      ${where}
      ORDER BY timestamp DESC
      LIMIT ${limit} OFFSET ${offset}
    `;

    const { rows } = await this.pool.query(sql, params);
    return rows.map((r) => ({
      tokenId: r.token_id,
      timestamp: r.timestamp,
      action: r.action,
      service: r.service,
      result: r.result,
      details: r.details ?? undefined,
      url: r.url ?? undefined,
      screenshotRef: r.screenshot_ref ?? undefined,
      accessMode: r.access_mode ?? undefined,
    }));
  }
}
```

### Postgres adapter — Python (`psycopg`)

```python
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row
from apoa import AuditEntry, AuditQueryOptions


class PostgresAuditStore:
    def __init__(self, pool: ConnectionPool) -> None:
        self.pool = pool

    def append(self, entry: AuditEntry) -> None:
        with self.pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO apoa_audit
                  (token_id, timestamp, action, service, result, details, url, screenshot_ref, access_mode)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    entry.token_id,
                    entry.timestamp,
                    entry.action,
                    entry.service,
                    entry.result,
                    entry.details,
                    entry.url,
                    entry.screenshot_ref,
                    entry.access_mode,
                ),
            )

    def query(self, token_id: str, options: AuditQueryOptions | None = None) -> list[AuditEntry]:
        return self._run_query(("token_id = %s", token_id), options)

    def query_by_service(self, service: str, options: AuditQueryOptions | None = None) -> list[AuditEntry]:
        return self._run_query(("service = %s", service), options)

    def _run_query(
        self,
        primary: tuple[str, str],
        options: AuditQueryOptions | None,
    ) -> list[AuditEntry]:
        conditions = [primary[0]]
        params: list = [primary[1]]

        if options:
            if options.from_time:
                conditions.append("timestamp >= %s")
                params.append(options.from_time)
            if options.to_time:
                conditions.append("timestamp <= %s")
                params.append(options.to_time)
            if options.action:
                conditions.append("action = %s")
                params.append(options.action)
            if options.result:
                conditions.append("result = %s")
                params.append(options.result)
            if options.service and primary[0].startswith("token_id"):
                conditions.append("service = %s")
                params.append(options.service)

        limit = (options.limit if options else None) or 100
        offset = (options.offset if options else None) or 0

        sql = f"""
            SELECT token_id, timestamp, action, service, result, details, url, screenshot_ref, access_mode
            FROM apoa_audit
            WHERE {' AND '.join(conditions)}
            ORDER BY timestamp DESC
            LIMIT {limit} OFFSET {offset}
        """

        with self.pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            return [
                AuditEntry(
                    token_id=r["token_id"],
                    timestamp=r["timestamp"],
                    action=r["action"],
                    service=r["service"],
                    result=r["result"],
                    details=r["details"],
                    url=r["url"],
                    screenshot_ref=r["screenshot_ref"],
                    access_mode=r["access_mode"],
                )
                for r in cur.fetchall()
            ]
```

### Notes

- **Append latency**: every `authorize()` call writes one row when audit is enabled. For high-throughput services, batch appends in memory and flush every N rows or every M seconds. Or pipe through a queue (Kafka, SQS) and have a worker write to Postgres asynchronously — you trade a small data-loss window for huge write-throughput gains.
- **Retention**: pick a retention policy that matches your compliance posture (90 days for general audit, 7 years for financial-services regulated workloads). Implement via partition detachment, not row-level DELETE — DELETE on a billion-row table is a bad time.
- **Query patterns**: `query()` (by token) is small and bounded by a single token's lifetime of actions. `queryByService()` can be unbounded and slow without good indexes — always require a `from`/`to` window in production callers.
- **Browser-mode fields**: `url` and `screenshot_ref` are only populated for `accessMode: "browser"` actions. Screenshots themselves go to object storage (S3, GCS); the audit store only holds the reference.

---

## Other backends

The same pattern applies to anything you'd reach for:

- **DynamoDB** — natural fit for both stores. Use `tokenId` as partition key for revocation; for audit, use `tokenId` as PK and `timestamp` as SK, plus a GSI on `service`.
- **MongoDB** — works fine; index `tokenId`, `service`, and `timestamp`.
- **Cassandra / ScyllaDB** — appropriate for high-volume audit; partition by `tokenId` or `service`, cluster by `timestamp DESC`.
- **In-memory + WAL on disk** — for single-node deployments that just need durability across restarts; libsql or sqlite work well.

The SDK doesn't ship adapters for any of these because production storage choices are personal — what's right depends on your stack, compliance posture, and scale. The interfaces are small enough that a from-scratch adapter is usually under 100 lines.

---

← Back to [README](../README.md)
