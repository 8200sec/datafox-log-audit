# SecurityEvent Repository v1

W3-07F 实现 SecurityEvent current state 的持久化存储：`SecurityEventMutation → Repository →
SecurityEvent Current State`。采用 **embedded SQLite**（独立 `datafox.db`），低资源单机部署，
无额外服务，不修改 OpenObserve Core。

## 1. 为什么 current state 不依赖 OpenObserve log upsert

SecurityEvent 是**可变业务对象**（`last_seen`/`event_count`/`status`/`related_event_ids` 会随检测
聚合变化）。OpenObserve log ingestion 是 append-only、按 event_id 无原地 update/upsert 语义——
用它存 current state 需要额外的 rewrite/compaction 语义。因此 v1 用 embedded SQLite 存「当前
状态」，未来通过 `SecurityEventRepository` trait 换 PostgreSQL HA。

## 2. Repository Abstraction

```rust
trait SecurityEventRepository {
    create(&SecurityEvent, &DetectionKey, episode_id) -> CreateOutcome
    apply_detection_update(&SecurityEventUpdate) -> UpdateOutcome
    get_by_event_id(tenant_id, event_id) -> Option<SecurityEvent>
    get_by_episode(tenant_id, &DetectionKey, episode_id) -> Option<SecurityEvent>
    list(tenant_id, limit) -> Vec<SecurityEvent>
}
```

- API 不暴露 SQLite 类型（`rusqlite` 只在 impl 内部）。
- `CreateOutcome::{ Created, AlreadyExists }`、`UpdateOutcome::{ Updated, NotFound }`。
- `RepositoryError::{ NotFound, AlreadyExists, ConstraintViolation, SerializationError,
  DatabaseError, TenantMismatch }`——**不把所有错误转成 String**。

## 3. SQLite Schema

独立 DataFox 库（`datafox.db`），**不写 OpenObserve metadata schema**。表 `security_events`
字段与 SecurityEvent Schema 一致；`related_event_ids_json` / `evidence_json` 用 TEXT 存 JSON；
`category`/`severity`/`status` 存 serde lowercase 字符串。

## 4. Unique Constraints

- `event_id` PRIMARY KEY（UNIQUE）。
- `UNIQUE(tenant_id, detection_key, episode_id)`——同一 detection episode 的 retry Create
  不产生重复。

`detection_key` 列 = `"{rule_id}|{rule_version}|{group_values}"`（tenant 独立成列）。

## 5. Idempotency

`create` 用 `INSERT OR IGNORE` + 唯一约束：retry 命中 `(tenant, detection_key, episode_id)` 冲突
→ 读回已有行 → `AlreadyExists(existing_event_id)`。**不依赖客户端判断幂等**。

## 6. Monotonic Update

`apply_detection_update` 在事务内 read-modify-write，只改 `last_seen / event_count / updated_at /
evidence / related_event_ids`：

- `last_seen = max(existing, incoming)`
- `event_count = max(existing, incoming)`
- `related_event_ids = bounded union`（去重 + `MAX_RELATED_EVENT_IDS` 上限）
- `evidence = incoming`（明确策略：新证据覆盖）

**不得 12→10 回退，不得 new last_seen → older**。

## 7. Status Ownership

Detection Update 的 SQL 只更新 mutable 列，**不碰 `status`**。`status=open` 由 Create 设定；
`acknowledged/resolved/closed` 属于未来独立 Workflow API/Command。immutable 字段
（`event_id/tenant_id/rule_id/rule_version/created_at`）也不在 Update 的 SET 列表。

## 8. Tenant Isolation

所有 get/create/update/query 显式带 `tenant_id` 条件；`get_by_event_id(tenant_id, event_id)`
与 `get_by_episode(tenant_id, …)` 都跨 tenant 安全（跨 tenant 返回 None）。

## 9. Concurrency

`Connection` 置于 `Mutex` 内，`&self` 方法串行化（单机低并发）。并发 Create 同 episode：唯一约束
保证最终 1 行；并发 Update：单调合并（max）保证不回退、不丢 ID。测试用多线程覆盖。

## 10. Migration

`PRAGMA user_version` 追踪 DataFox schema version（v1）。启动时 `migrate()`：`0 → 1` 建表+索引，
`=1` 跳过，`>1`（未来更高级 schema）报错。**禁止无版本地随意 CREATE/ALTER**。

## 11. Indexes

- 唯一：`event_id` PK、`(tenant_id, detection_key, episode_id)`。
- 查询：`(tenant_id, status)`、`(tenant_id, severity)`、`(tenant_id, last_seen)`、
  `(tenant_id, rule_id)`。低写入成本优先，避免过多索引。

## 12. Enrichment

Repository 不查 AuditEvent 回填 `src_ip/username/hostname/raw_log`——这些由
RuleMatch/SecurityEventBuilder 提供最小必要上下文（threshold 从 `group_values` 提取）。避免写
SecurityEvent 时额外查 OpenObserve。

## 13. Future (未实现)

- `SecurityEventHistorySink`：append created/updated/acknowledged/resolved/closed 历史
  （写 `security_events` stream），本阶段不做。
- PostgreSQL HA：`SecurityEventRepository` 换成 sqlx（workspace 已有 sqlx+postgres）实现。

## 14. Resource Impact

- 依赖：`rusqlite`（`bundled`，编译内嵌 SQLite，无系统库/服务）。
- 实测（in-memory，单连接）：insert 10k ≈ 255ms（~25µs/op）、update 10k ≈ 229ms（~23µs/op）。
- 无 Redis/Kafka/PostgreSQL server/daemon；`datafox.db` 文件大小随事件数线性增长。
