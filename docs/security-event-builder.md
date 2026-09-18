# SecurityEvent Builder v1

W3-07E 实现**无状态、无 IO** 的 SecurityEvent Builder：把 `RuleMatch`（single）/ `WindowEvaluation`
（threshold）转成 `SecurityEventMutation`。**不持久化、不查 OpenObserve、不实现 Repository。**

## 1. Single vs Threshold

| | Single | Threshold |
| --- | --- | --- |
| 输入 | `RuleMatch` | `WindowEvaluation` |
| 触发 | 每条 AuditEvent 命中即独立事件 | `threshold_crossed` 建新 episode |
| correlation identity | detection_key + `audit_event_id` | detection_key + `episode_id` |

## 2. Create / Update / NoOp

`SecurityEventMutation`：

- `Create { security_event, detection_key, episode_id }`
- `Update { detection_key, episode_id, last_seen, event_count, evidence, related_event_ids, updated_at }`
- `NoOp`

Threshold 映射：

- `threshold_crossed = true` → **Create**（新 episode）
- `threshold_reached = true && threshold_crossed = false` → **Update**（同 episode）
- `threshold_reached = false` → **NoOp**

Builder **不查找 existing event**——W3-07F Repository 根据 `detection_key` + `episode_id`
找到对应 SecurityEvent 应用变更。

## 3. DetectionKey

```rust
DetectionKey { tenant_id, rule_id, rule_version, group_values }
```

- `tenant_id` 只来自 RuleMatch/WindowEvaluation 可信 context；RuleDefinition 不提供 tenant；
  Builder 不接受客户端 override。
- `group_values` **复用 W3-07D 的 canonical ordering**（`canonical_group_key`，按
  `aggregation.group_by` 声明顺序），**不重写另一套**，避免 WindowState key 与 SecurityEvent
  key 不一致。single 规则 `group_values = ""`。

## 4. Episode Semantics

每次 `threshold_crossed`（上升沿）产生**新 episode**：

```
9→10  创建 episode A
10→11 继续 episode A（Update）
11→3  episode A 离开触发态（NoOp）
9→10  创建 episode B（不得继续更新 A）
```

实现：W3-07D `WindowEvaluation` 最小扩展了 `episode_started_at`（最近一次 crossing 的时间戳，
未达到阈值时为 `None`）。Builder 用 `episode_id = episode_started_at` 标识 episode——同 episode
内稳定、跨 episode 不同。single 规则 `episode_id = audit_event_id`（每事件独立）。

## 5. Status Ownership

- `Create` → `status = open`。
- `Update` **不含 status 字段**（类型层面禁止修改）。
- `open/acknowledged/resolved/closed` 属于人工/工作流生命周期；新 Detection 不得
  `acknowledged/resolved/closed → open`；是否 reopen 属于未来独立 Policy。

## 6. Immutable Fields

创建后不得由 Builder update mutation 修改：`event_id`、`tenant_id`、`rule_id`、
`rule_version`、`created_at`。`Update` 结构上**不含这些字段**（类型保障）。

## 7. event_id

`event_id` 由 server-side 生成（`Uuid::now_v7()`，项目 workspace `uuid` crate v7）。客户端、
AuditEvent、RuleDefinition 均不得指定。

## 8. Create 字段来源

- `status=open`；`created_at=updated_at=now`（server clock，Builder 注入时间戳）。
- `first_seen`/`last_seen`：single = `matched_at`；threshold = `WindowEvaluation.first_seen/last_seen`。
- `event_count`：single = 1；threshold = 当前实际 count。
- `related_event_ids`：single = `[audit_event_id]`；threshold = `sample_event_ids`
  （已去重 + 上限）。**event_count ≠ related_event_ids.len()**（threshold 全量计数，sample 有界）。
- `title/description/category/event_type/severity` 来自 RuleDefinition（**severity 不被
  AuditEvent severity 覆盖**）。
- `src_ip/dst_ip/username/asset_id`：threshold 从 `group_values` 提取（group_by 命中的实体）；
  single 为 None（Repository 后续可从 related_event 补齐）。

## 9. Evidence

- single：`matched_event_id` + `matched_fields`（+ `rule_type`）。
- threshold：`threshold` / `window_seconds` / `group_by` / `group_values` / `current_count` /
  `first_seen` / `last_seen`。
- **不复制 raw_log**；原始证据通过 `related_event_ids` 关联。

## 10. 为何 Builder 不访问 Storage

- 纯函数、无状态：不缓存历史 SecurityEvent、不保存 AuditEvent、不起后台任务/timer、不维护
  HashMap。状态属于 W3-07D WindowState 与未来 W3-07F Repository。
- 便于单测（注入时间戳，无 sleep、无 IO）。
- 清晰分层：Builder 只决定「要 Create / Update / NoOp」，具体落库与查找由 W3-07F 完成。
