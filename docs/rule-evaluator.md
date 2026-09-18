# Rule Evaluator v1（无状态）

W3-07C 实现**无状态条件求值**：给定 `RuleDefinition` + `AuditEvent`，产出 `RuleMatch` / `NotMatched` /
`Error`。**不实现**滑动窗口、threshold state、SecurityEvent 聚合/持久化。

## 1. RuleDefinition vs RuleEvaluator

- `RuleDefinition`（W3-07B）：声明式规则模型，可序列化/验证/存储。
- `RuleEvaluator`（本阶段）：**无状态**地把一条规则套到一条 AuditEvent 上，返回匹配结果。

```
AuditEvent ──┐
             ├─► RuleEvaluator ──► RuleMatch / NotMatched / Error
RuleDefinition┘
```

RuleEvaluator 不直接生成/更新 SecurityEvent（留给 W3-07E）。

## 2. RuleMatch

```rust
struct RuleMatch {
    rule_id, rule_version,
    tenant_id,          // 来自 AuditEvent 可信 tenant context
    audit_event_id,
    matched_at,         // AuditEvent 自身时间戳
    group_values,       // threshold 规则的 group_by 取值
    evidence,           // 轻量上下文（rule_type / matched_fields）
}
```

- 不含 SecurityEvent lifecycle 状态，不生成 SecurityEvent `event_id`。
- `tenant_id` 只来自 AuditEvent；RuleDefinition 不允许覆盖；不从 rule payload 创建 tenant。

## 3. EvaluationResult

`Matched(RuleMatch)` / `NotMatched` / `Error(EvaluationError)`。

字段类型错误、非法规则、未知字段 → **Error**，绝不静默当 NotMatched。

## 4. FieldResolver + TypedValue

统一 `resolve_field(FieldPath, AuditEvent) -> Result<Option<TypedValue>, Error>`：

- 标准字段：`event_type category result severity username hostname src_ip src_port dst_ip dst_port source_type source_name`
- `event_attributes.<key>`（单层，无无限 JSONPath）

`TypedValue`：`String` / `Number(f64)` / `Boolean` / `Null`。**不 stringify 后比较**——比较发生在
typed value 上。`src_port`/`dst_port`（u16）→ `Number`；`result`/`severity`/`source_type` 枚举 →
其 serde lowercase 字符串。

`Ok(None)` = 字段路径合法但本事件无值（missing）；`Err` = 字段路径未知（invalid rule）。

## 5. Operator Semantics

- `eq`/`neq`：同类 `String`/`Number`/`Boolean` 比较；跨类 → `TypeMismatch`。
- `contains`/`not_contains`/`starts_with`/`ends_with`：仅 `String`，否则 `TypeMismatch`。
- `gt`/`gte`/`lt`/`lte`：仅 `Number`，否则 `TypeMismatch`。
- `in`/`not_in`：比较值必须是数组，元素与字段同类匹配（无同类命中 → false/true）。
- `exists`/`not_exists`：不比较值。
- 无 regex。

## 6. Missing Field Behavior

字段不存在时：

- `exists` → `false`（NotMatched）
- `not_exists` → `true`（Matched）
- 其它 operator → **NotMatched**（非 Error）

类型错误 / 未知字段 / 缺 value 才是 Error。

## 7. all / any（short-circuit）

- `all`：任一子条件 false 立即 NotMatched（不再求值后续）。
- `any`：任一子条件 true 立即 Matched（不再求值后续）。

嵌套深度仍受 `MAX_CONDITION_DEPTH = 4` 约束；Evaluator 对未验证的过深规则返回
`Error(ConditionTooDeep)`，不 panic、不 stack overflow。

## 8. Threshold Candidate Behavior

W3-07C **不维护窗口状态**。对 `rule_type = threshold` 只做：

1. 求值 match 条件；
2. 命中则产出 **Candidate RuleMatch**，并把 `aggregation.group_by` 对应值填入 `group_values`
   （如 `{"src_ip": "10.10.10.5"}`）。

是否达到 `threshold` / `window` 的判定留给 W3-07D。

## 9. Single Rule

`rule_type = single` 条件匹配 → 直接返回 RuleMatch（后续 W3-07E 转成 SecurityEvent）。

## 10. 为什么 W3-07C 不维护窗口状态

- **解耦**：条件求值（纯函数、可测）与窗口聚合（有状态、需时间语义与淘汰策略）是两类问题。
- **低资源硬约束**：无状态求值器不缓存 AuditEvent、不建窗口 HashMap、不建后台线程/timer/数据库，
  单次 evaluate 完成后不保留事件数据。
- **演进清晰**：先交付「匹配/不匹配」的确定性语义，再在 W3-07D 引入滑动窗口（keyed by group_by、
  按 window_seconds 淘汰）。

## 11. Evidence

`evidence` 只含轻量上下文（`rule_type`、`matched_fields`），**不复制完整 AuditEvent、不写入
raw_log**。原始证据最终通过 `related_event_id` 追踪。
