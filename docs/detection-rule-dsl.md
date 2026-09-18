# Detection Rule DSL v1

DataFox 检测规则的声明式定义模型。本阶段只定义 **RuleDefinition**（可序列化/反序列化/验证/
存储、未来可由 UI 创建、可导入导出），**不实现规则执行**（RuleEvaluator 留到 W3-07C）。

## 1. DSL 设计原则

- **Rule Definition 与 Rule Execution 解耦**：规则是数据（JSON 可表达），不是编译进代码的
  trait 实现。`RuleDefinition` 只是一个可验证的模型。
- **Storage Agnostic**：不绑定 SQLite/PostgreSQL/OpenObserve Stream；存储方案在后续 Rule
  Management 阶段决定。
- **可扩展但不提前实现**：`distinct_field` / `distinct_threshold` 等预留字段留到未来
  （Password Spray），本阶段不做复杂逻辑。

## 2. RuleDefinition

```json
{
  "id": "builtin.ssh_bruteforce",
  "version": "1.0.0",
  "title": "SSH brute force",
  "description": "Repeated failed SSH logins from one source",
  "enabled": true,
  "source": "builtin",
  "tags": ["ssh", "brute-force"],
  "category": "authentication",
  "event_type": "ssh_brute_force",
  "severity": "high",
  "rule_type": "threshold",
  "match": { "all": [ ... ] },
  "aggregation": { "group_by": ["src_ip"], "window_seconds": 300, "threshold": 10 }
}
```

| 字段 | 说明 |
| --- | --- |
| `id` | 稳定规则 ID（如 `builtin.ssh_bruteforce`），非空 |
| `version` | 严格 semver `MAJOR.MINOR.PATCH` |
| `title` | 显示标题，非空 |
| `description` | 可选描述 |
| `enabled` | 是否启用（默认 true） |
| `source` | `builtin` / `custom` / `imported`（仅表示来源，**不做授权**） |
| `tags` | 标签列表 |
| `category` | SecurityEvent category（authentication/privilege/…） |
| `event_type` | 产出 SecurityEvent 的稳定机器类型 |
| `severity` | 产出 SecurityEvent 的 severity（**不改变 AuditEvent severity**） |
| `rule_type` | `single` / `threshold` |
| `match` | Match DSL（见 §4） |
| `aggregation` | 阈值聚合（仅 `threshold` 需要） |

## 3. rule_type

- `single`：单条 AuditEvent 匹配即触发。
- `threshold`：时间窗口内匹配事件达到阈值触发。

不实现 sequence / absence / CEP / state machine。

## 4. Match DSL

逻辑组合 `all` / `any` + 叶子条件 `{ field, operator, value }`：

```json
{
  "all": [
    { "field": "event_type", "operator": "eq", "value": "ssh_login" },
    { "field": "result", "operator": "eq", "value": "failure" }
  ]
}
```

- 最大嵌套深度 `MAX_CONDITION_DEPTH = 4`。
- 空 `all`/`any` 列表非法（`EmptyMatch`）。

## 5. Operators

`eq` `neq` `contains` `not_contains` `starts_with` `ends_with` `gt` `gte` `lt` `lte`
`in` `not_in` `exists` `not_exists`。

- **无 regex**（v1 不启用）。
- `exists`/`not_exists` 不需要 `value`；其余需要 `value`。
- 类型校验：`in`/`not_in` → 数组；`gt/gte/lt/lte` → 数字；`contains/starts_with/ends_with` →
  字符串。

## 6. Field Paths

统一 `FieldPath`，仅允许：

- 标准 AuditEvent 顶层字段：`event_type` `category` `result` `severity` `username`
  `hostname` `src_ip` `src_port` `dst_ip` `dst_port` `source_type` `source_name`
- `event_attributes.<key>`（单层 key，如 `event_attributes.command`、
  `event_attributes.auth_method`、`event_attributes.target_user`）

任意未知顶层字段被拒绝。

## 7. Aggregation（threshold）

```json
{ "group_by": ["src_ip"], "window_seconds": 300, "threshold": 10 }
```

- `window_seconds > 0`、`threshold >= 1`、`group_by` 非空且 ≤ `MAX_GROUP_BY_FIELDS = 3`、
  group_by 字段合法。
- 预留 `distinct_field` / `distinct_threshold`（Password Spray），v1 不执行。

## 8. Validation

`validate()` 覆盖：id 非空、semver、title 非空、match 非空、深度 ≤4、合法 field path、
operator/value 类型合理、`threshold` 必须有 aggregation、`single` 聚合可选、window>0、
threshold≥1、group_by 数量与字段合法。

## 9. 完整 JSON 示例

### 9.1 builtin.ssh_bruteforce（threshold）

```json
{
  "id": "builtin.ssh_bruteforce",
  "version": "1.0.0",
  "title": "SSH brute force",
  "enabled": true,
  "source": "builtin",
  "category": "authentication",
  "event_type": "ssh_brute_force",
  "severity": "high",
  "rule_type": "threshold",
  "match": {
    "all": [
      { "field": "event_type", "operator": "eq", "value": "ssh_login" },
      { "field": "result", "operator": "eq", "value": "failure" }
    ]
  },
  "aggregation": { "group_by": ["src_ip"], "window_seconds": 300, "threshold": 10 }
}
```

### 9.2 builtin.suspicious_sudo_shadow（single）

```json
{
  "id": "builtin.suspicious_sudo_shadow",
  "version": "1.0.0",
  "title": "Sensitive sudo command",
  "enabled": true,
  "source": "builtin",
  "category": "privilege",
  "event_type": "suspicious_sudo",
  "severity": "high",
  "rule_type": "single",
  "match": {
    "all": [
      { "field": "event_type", "operator": "eq", "value": "sudo_command" },
      { "field": "event_attributes.command", "operator": "contains", "value": "/etc/shadow" }
    ]
  }
}
```

### 9.3 builtin.repeated_pam_failure（threshold）

```json
{
  "id": "builtin.repeated_pam_failure",
  "version": "1.0.0",
  "title": "Repeated PAM authentication failure",
  "enabled": true,
  "source": "builtin",
  "category": "authentication",
  "event_type": "repeated_pam_failure",
  "severity": "medium",
  "rule_type": "threshold",
  "match": {
    "all": [
      { "field": "event_type", "operator": "eq", "value": "pam_auth" },
      { "field": "result", "operator": "eq", "value": "failure" }
    ]
  },
  "aggregation": { "group_by": ["username"], "window_seconds": 300, "threshold": 5 }
}
```

## 10. 版本策略

`id` 稳定不变；规则逻辑变更时 **只增加 `version`**（semver 递增）。Rule Identity = `id`，
`version` 标识某次逻辑修订。

## 11. Future Extensions（暂不实现）

- `sequence` / `absence` / 有状态规则。
- `distinct_field` / `distinct_threshold`（Password Spray）。
- `regex` operator。
- MITRE ATT&CK 元数据（进入 SecurityEvent `evidence`/`attributes`，不进核心 schema）。
- Rule Management（存储、UI、导入导出）。
