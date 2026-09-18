# Detection Pipeline v1

W3-07G 把各独立组件串入 DataFox Audit Ingestion Path：日志摄取成功后，自动执行检测，产出
`SecurityEvent`（存 embedded SQLite）。

## 1. 完整链路

```
Raw Log
  → Audit Ingest API (POST /api/{org}/audit/ingest)
  → Parser (audit_parser)
  → Normalizer → AuditEvent
  → OpenObserve ingestion (audit_events stream)
         │ 成功后（best-effort，不回滚）
         ▼
  → DetectionPipeline
      → RuleRegistry.active_rules (deterministic order)
      → RuleEvaluator (per rule)
      → single: SecurityEventBuilder → Repository (Create)
      → threshold: WindowStateManager → SecurityEventBuilder → Repository (Create/Update)
         │
         ▼
  → SecurityEventRepository (embedded SQLite datafox.db)
```

## 2. Module Responsibilities（不重复实现）

| 组件 | 职责 |
| --- | --- |
| `RuleRegistry` | 注册内置规则、返回 active（enabled）规则、确定性顺序、id 查找 |
| `RuleEvaluator` | 条件求值（无状态） |
| `WindowStateManager` | threshold 滑动窗口（有状态） |
| `SecurityEventBuilder` | Create/Update/NoOp mutation（无状态） |
| `SecurityEventRepository` | SQLite 落库（有状态） |
| `DetectionPipeline` | **只编排**：路由 + 调用上述组件 + 汇总 outcome |

Pipeline 不重写 condition evaluation / window / builder / SQL。

## 3. Single Path

`evaluate → Matched(RuleMatch) → builder.build_single → Create → repository`。**不进
WindowStateManager**。每条 AuditEvent 命中即独立 SecurityEvent（episode = audit_event_id）。

## 4. Threshold Path

`evaluate → Matched → window.record → WindowEvaluation`：
- `threshold_crossed` → `builder.build_threshold → Create → repository`
- `threshold_reached && !crossed` → `Update → repository`
- 未达阈值 → `NoOp`（`MatchedNoTrigger`）

不重写 threshold/滑动窗口逻辑。

## 5. Tenant Isolation

Pipeline 全链保持同一可信 tenant：`AuditEvent.tenant_id → RuleMatch → WindowKey →
SecurityEventMutation → Repository`。任何 RuleDefinition / body 不能改 tenant。E2E 多租户测试覆盖。

## 6. Failure Semantics

- **检测失败不回滚 AuditEvent ingestion**：OpenObserve `audit_events` 写入成功后，若 Detection
  Pipeline 出错，只记录 `DetectionError` / 可观测 outcome，**不把整个 ingest 改成 failure**，不
  panic。日志保存优先级高于派生检测。
- `DetectionOutcome` 结构化：`NoRuleMatched / MatchedNoTrigger / SecurityEventCreated /
  SecurityEventUpdated / DetectionError / CapacityExceeded`——禁止只返回 bool。

## 7. Restart Semantics

- `WindowStateManager`（threshold 滑动窗口）= **纯内存**，进程重启清空。
- `SecurityEventRepository`（SQLite `datafox.db`）= **持久**，重启保留已有 SecurityEvent。
- v1 不做 window persistence。

## 8. Resource Behavior

- 进程内 pipeline，无 Kafka/Redis/daemon/worker service/PostgreSQL。
- `MAX_ACTIVE_RULES = 1000` 防无限规则；窗口沿用 W3-07D 容量保护（global/per-tenant/per-window）。
- 单事件检测不建无界线程/task；Pipeline 同步执行（SQLite ~25µs/op + 内存窗口）。
- 轻量进程内统计：`events_evaluated / rules_evaluated / rules_matched / security_events_created /
  security_events_updated / detection_errors / window_capacity_errors`（AtomicU64）。

## 9. 为什么检测失败不回滚 AuditEvent ingestion

- AuditEvent 是**事实**（不可变、已入 OO）；SecurityEvent 是**派生**（可重算）。
- 检测可能因规则 bug / capacity / DB 瞬时错误失败，重试即可；但 AuditEvent 一旦丢弃无法恢复。
- 因此：ingest 成功先返回，检测作为 best-effort 后置步骤，错误只记录不传播为 ingest failure。

## 10. Config

- `ZO_DATAFOX_DB`：SecurityEvent SQLite 路径（默认 `datafox.db`，服务运行目录）。

## 11. Built-in Rules（v1 注册顺序）

1. `builtin.ssh_bruteforce`（threshold, group_by=src_ip, window 300s, ≥10, high）
2. `builtin.suspicious_sudo_shadow`（single, sudo_command + command contains /etc/shadow, high）
3. `builtin.repeated_pam_failure`（threshold, group_by=event_attributes.target_user, window 300s,
   ≥5, medium）

> 注：PAM 的 group_by 用 `event_attributes.target_user`（W3-05 PAM parser 把用户放
> `target_user`，非 `username`），因此偏离 W3-07B 示例里的 `group_by=username`。
