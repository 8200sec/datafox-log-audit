# Threshold Window State v1

W3-07D 实现 `threshold` 规则的**有状态滑动窗口**：接收 W3-07C 的 `RuleMatch`，维护窗口状态，
产出 `WindowEvaluation`。**不生成、不持久化 SecurityEvent。**

```
AuditEvent → RuleEvaluator（无状态）→ RuleMatch
                                         │ (threshold rules)
                                         ▼
                              WindowStateManager（有状态）
                                         │
                                         ▼
                                  WindowEvaluation
```

## 1. WindowKey

```rust
WindowKey { tenant_id, rule_id, rule_version, group_values }
```

- 必须包含 `tenant_id`（tenant 隔离）与 `rule_version`（不同版本不复用旧状态），**不能**只
  用 `rule_id` + group values。
- `group_values` 按 `aggregation.group_by` **声明顺序** canonicalize（`field=value` 逗号连接），
  **不依赖 HashMap iteration order**。

## 2. Sliding Window Semantics

每次新 `RuleMatch`（`window_seconds = N`）：

1. 定位/新建对应 `WindowState`；
2. 淘汰 `timestamp < current_event_time - N` 的旧 entry；
3. 加入当前事件（去重后）；
4. 计算 count。

窗口内保存**全部**当前窗口 event（`WindowEntry { timestamp, event_id }`，绝不保存完整
AuditEvent），用于准确淘汰过期事件——**不是**只存 count/first_seen/last_seen。

## 3. Event-Time Strategy

- 窗口事件时间 = `RuleMatch.matched_at`（来自规范化 AuditEvent timestamp，**不是浏览器时间**）。
- v1 乱序策略：**允许有限乱序**；早于当前窗口起点（anchored at latest event）的事件直接忽略
  （`OutOfWindow`），不会因旧事件让窗口无限扩张。无复杂 watermark framework。

## 4. threshold_reached vs threshold_crossed

- `threshold_reached = count >= threshold`。
- `threshold_crossed` = **上升沿**（前一次未 reached 且本次 reached）。

| count 变化 | reached | crossed |
| --- | --- | --- |
| 9 → 10 | true | true |
| 10 → 11 | true | false |
| 11 → 3（过期） | false | false（re-armed） |
| 再次 9 → 10 | true | true |

内部用 `previous_reached`（armed/disarmed）实现。

## 5. Tenant Isolation

`WindowKey` 含 `tenant_id`；`WindowEvaluation.tenant_id` 来自 `RuleMatch`（即 AuditEvent 可信
context）。一个 tenant 的状态不影响其它 tenant；per-tenant 容量限制只作用于该 tenant。

## 6. Capacity Protection

集中常量/配置（`WindowLimits`，默认）：

- `MAX_ACTIVE_WINDOWS_GLOBAL = 100_000`
- `MAX_ACTIVE_WINDOWS_PER_TENANT = 10_000`
- `MAX_EVENTS_PER_WINDOW = 10_000`
- `MAX_GROUP_VALUE_LENGTH = 256`

达到容量时：**先清理 expired windows**；仍超限 → 返回 `CapacityExceeded`，**不做 LRU 驱逐
活跃窗口**。

### 为何不用 LRU 驱逐活跃窗口

恶意高基数 group key（如伪造大量 src_ip）不能通过 LRU 把**真实攻击检测窗口**挤掉。LRU/stale
清理只作用于「已过期或明确 inactive」的 state；活跃检测状态宁可报错暴露，也不静默丢失。

## 7. High-Cardinality Protection

- `group_by` ≤ `MAX_GROUP_BY_FIELDS = 3`（沿用 W3-07B）。
- group value 长度超 `MAX_GROUP_VALUE_LENGTH` → 返回 `GroupValueTooLong`（**不静默截断制造
  巨大 key**）。

## 8. Memory Strategy

- 纯内存、标准库 `HashMap`/`Vec`；无 Redis/Kafka/DB/缓存框架。
- 未内部加锁：调用方用 `Mutex`/`RwLock` 包裹，临界区仅 `record`，锁内无 IO。
- 单条估算（64-bit）：`WindowEntry` ≈ 8B（i64）+ event_id（String ≈ 24B header + 堆）≈ 40B；
  `WindowState` ≈ 24B（Vec header）+ 8B（window_seconds）+ 1B（bool）+ 每 entry ~40B。
  内存随 active state 有明确上限（global/per-tenant/per-window 三级 cap）。

## 9. Restart Behavior

v1：**Window State = in-memory only**，进程重启状态清空。不增加持久化；未来 persistence 作为
独立设计，不改 Search/WAL Core。

## 10. Single Rules

`rule_type = single` **不进入** WindowStateManager（由 W3-07C Match 直接交给 W3-07E）。
`record()` 对非 threshold 规则返回 `InvalidWindow`。

## 11. Failure Behavior

窗口状态错误不 panic、不影响 ingestion、不修改 AuditEvent。返回明确 `WindowError`：
`CapacityExceeded` / `InvalidWindow` / `InvalidGroupKey` / `GroupValueTooLong` /
`MaxEventsPerWindow`；`Duplicate` / `OutOfWindow` 为非致命 outcome（`WindowOutcome`）。

## 12. Duplicate Event

同一 `audit_event_id` 在同一 WindowKey 内重复到达 → 不重复计数（`WindowOutcome::Duplicate`）。

## 13. Related Event Samples

窗口内部保存全部当前窗口 event ID（用于准确淘汰）；对外 `WindowEvaluation.sample_event_ids`
有上限 `MAX_SAMPLE_EVENT_IDS`（= SecurityEvent `MAX_RELATED_EVENT_IDS`，100），**不无限复制 ID**。
