# SecurityEvent Schema v1

DataFox 安全检测阶段的 `SecurityEvent` 数据契约。它是检测规则（audit_rule）的产物，与
`AuditEvent`（audit_parser 的产物）分层清晰。

## 1. AuditEvent vs SecurityEvent

```
raw log → audit_parser → AuditEvent → audit_rule → SecurityEvent
```

| | AuditEvent | SecurityEvent |
| --- | --- | --- |
| 谁产生 | `audit_parser`（事实标准化） | `audit_rule`（检测/关联） |
| 语义 | 单条原始日志的标准化事实 | 由 1..N 条 AuditEvent 关联出的安全事件 |
| severity | 保留日志/源头的原始等级 | 由检测规则决定，可与 AuditEvent 不同 |
| 生命周期 | 一次性（不可变事实） | 会聚合更新（`last_seen`/`event_count`/`status`） |

**关键边界**：Parser 只做事实标准化，**不把风险检测逻辑放进 Parser**。风险升级（例如
单条 `ssh login failure` 的 severity 保持 syslog 原始等级，但「5 分钟同 `src_ip` 失败
≥10 次」升级为 `high`）发生在 Detection Rule 层，生成独立的 `SecurityEvent`，**不修改
原 AuditEvent**。

## 2. Detection Rule 与 SecurityEvent 的关系

- Detection Rule（W3-07B 实现）消费 AuditEvent，产出/聚合 SecurityEvent。
- `rule_id`（如 `builtin.ssh_bruteforce`）+ `rule_version` 标识触发规则。
- `event_type` 是稳定 machine-readable 类型（如 `ssh_brute_force`）；`title` 才是显示文案
  （如「SSH 暴力破解」）。
- Rule 的触发上下文（阈值、窗口、分组键等）进入 `evidence`，**不为每种 Rule 增加顶层字段**。

## 3. 字段定义

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `event_id` | string | 系统生成唯一 ID，**不可被客户端/AuditEvent/Rule payload 覆盖** |
| `tenant_id` | string | 可信 server-side context；与触发它的 AuditEvent 同 tenant |
| `rule_id` / `rule_version` | string | 触发规则 id + 版本 |
| `title` | string | 显示标题（非空） |
| `description` | string? | 可选描述 |
| `category` | enum | authentication/privilege/network/malware/policy/data_access/system/other |
| `event_type` | string | 稳定机器类型（`ssh_brute_force` 等） |
| `severity` | enum | info/low/medium/high/critical（Rule 决定） |
| `status` | enum | open/acknowledged/resolved/closed |
| `first_seen` / `last_seen` | i64 (ms) | 首/末条关联 AuditEvent 时间，`first_seen <= last_seen` |
| `event_count` | u64 | 关联 AuditEvent 总数，`>= 1` |
| `src_ip` / `dst_ip` / `username` / `asset_id` | string? | 关键实体 |
| `related_event_ids` | string[] | 触发事件 ID 样本（去重 + 上限） |
| `evidence` | object | Rule 触发上下文（可扩展） |
| `created_at` / `updated_at` | i64 (ms) | 首次生成 / 最后更新，`created_at <= updated_at` |

## 4. Severity

统一 5 级：`info` / `low` / `medium` / `high` / `critical`。

`SecurityEvent.severity` 由 Detection Rule 决定，**独立于** `AuditEvent.severity`。Rule 可
把多低等级日志聚合升级为高等级事件，而原 AuditEvent 的 severity 保持不变。

## 5. Status Lifecycle

v1 仅 4 态：`open → acknowledged → resolved → closed`。无自定义工单状态机。

## 6. related_event_ids 策略

- `MAX_RELATED_EVENT_IDS = 100`（`src/audit_rule/src/security_event.rs`）。
- 列表是**去重的有界样本**；`event_count` 才是完整关联数量。
- 超过上限后：`event_count` 继续增长，列表仅保留前 100 个去重 ID，**禁止无限增长**。
- `record_related_event(id)` 统一处理「计数 +1、样本去重、上限截断」。

## 7. Evidence

`evidence` 是 `serde_json::Value`（可扩展对象），保存 Rule 触发上下文，例如：

```json
{
  "threshold": 10,
  "window_seconds": 300,
  "group_by": "src_ip",
  "group_value": "10.10.10.5",
  "failed_users": ["root", "admin"]
}
```

MITRE ATT&CK 等信息未来也进入 `evidence`/`attributes`，不进入核心 schema。

## 8. Tenant Isolation

`tenant_id` 必须来自可信 server-side context，且 `SecurityEvent.tenant_id ==` 触发它的
`AuditEvent.tenant_id`。绝不信任客户端传入的 tenant。

## 9. Immutability

生成后**不可变**：`event_id`、`tenant_id`、`rule_id`、`created_at`。
聚合时**可变**：`last_seen`、`event_count`、`status`、`updated_at`、`evidence`、`related_event_ids`。

## 10. 示例

### 10.1 SSH brute force

```json
{
  "event_id": "sev-bf-0001",
  "tenant_id": "tenant-a",
  "rule_id": "builtin.ssh_bruteforce",
  "rule_version": "1.0.0",
  "title": "SSH brute force",
  "category": "authentication",
  "event_type": "ssh_brute_force",
  "severity": "high",
  "status": "open",
  "first_seen": 1700000000000,
  "last_seen": 1700000300000,
  "event_count": 10,
  "src_ip": "10.10.10.5",
  "evidence": { "threshold": 10, "window_seconds": 300 }
}
```

### 10.2 sudo sensitive command

```json
{
  "event_id": "sev-sudo-0002",
  "tenant_id": "tenant-a",
  "rule_id": "builtin.sudo_sensitive",
  "rule_version": "1.0.0",
  "title": "Sensitive sudo command",
  "category": "privilege",
  "event_type": "suspicious_sudo",
  "severity": "high",
  "status": "open",
  "first_seen": 1700000000000,
  "last_seen": 1700000000000,
  "event_count": 1,
  "username": "alice",
  "evidence": { "target_user": "root", "command": "/usr/bin/cat /etc/shadow" }
}
```

### 10.3 PAM repeated failure

```json
{
  "event_id": "sev-pam-0003",
  "tenant_id": "tenant-a",
  "rule_id": "builtin.pam_failure",
  "rule_version": "1.0.0",
  "title": "Repeated PAM authentication failure",
  "category": "authentication",
  "event_type": "repeated_pam_failure",
  "severity": "medium",
  "status": "open",
  "first_seen": 1700000000000,
  "last_seen": 1700000300000,
  "event_count": 25,
  "src_ip": "10.0.0.9",
  "evidence": { "threshold": 20, "window_seconds": 600, "pam_service": "sshd" }
}
```
