# AuditEvent Schema v1

DataFox 日志审计系统统一审计事件数据模型（AuditEvent v1）。本文件是权威规范；
实现源码见 `web/src/schemas/audit-event/`（TypeScript types + Zod 校验 + fixtures +
单测）。

> 状态：v1 — 稳定基线，供后续 **Parser Framework** 与 **AuditEvent 业务 API** 使用。

## 1. 设计目标与约束

1. **`raw_log` 永远保留** —— 原始日志行是审计溯源的最终依据，任何解析/富化都不得丢失。
2. **公共 Schema 不承载厂商字段** —— 厂商/产品特有字段一律进入 `event_attributes`。
3. **`severity` 归一化** —— 全链路统一为 `info | low | medium | high | critical`。
4. **`result` 归一化** —— 建议统一为 `success | failure | unknown`。
5. **`tenant_id` 服务端指派** —— 永不信任浏览器/采集端直传的租户标识。
6. **`event_id` 全局唯一** —— 幂等、去重、关联都依赖它。
7. **`parser_id` / `parser_version` 可追踪** —— 每个事件记录产出它的解析器及版本。
8. **面向未来多源** —— 覆盖 Linux、Windows、Firewall、Router、Database、Web、Application 日志。
9. **不针对样例日志做厂商耦合** —— 字段按语义抽象，不按某厂商报文形状设计。

## 2. 目标 Stream

| Stream | 内容 | 说明 |
| --- | --- | --- |
| `audit_events` | 解析成功的规范化事件（`AuditEvent`） | 每行源日志一条 |
| `audit_parse_failures` | 解析失败/无法识别的日志（`AuditParseFailure`） | 保留原始行，供后续重放/新解析器版本重处理 |

## 3. 字段定义

时间戳统一为 **epoch 毫秒（number）**。

### 3.1 `audit_events` — `AuditEvent`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `_timestamp` | number (epoch ms) | ✅ | 事件时间；源无时间戳时由解析器回退为 ingest 时间 |
| `event_id` | string | ✅ | 全局唯一事件 ID（见 §7） |
| `tenant_id` | string | ✅ | 租户 ID，服务端指派（见 §6） |
| `source_type` | `SourceType` | ✅ | 源大类：`os/firewall/router/database/web/application/network/other` |
| `source_name` | string | — | 具体源标识（主机/设备/应用实例） |
| `collector_id` | string | — | 采集器/Agent 标识 |
| `vendor` | string | — | 厂商名，如 `Cisco` |
| `product` | string | — | 产品名，如 `ASA` |
| `product_version` | string | — | 产品版本 |
| `hostname` | string | — | 主机名 |
| `asset_id` | string | — | 资产 ID |
| `src_ip` | string | — | 源 IP |
| `src_port` | number (int 0–65535) | — | 源端口 |
| `dst_ip` | string | — | 目的 IP |
| `dst_port` | number (int 0–65535) | — | 目的端口 |
| `username` | string | — | 用户名/主体 |
| `category` | string | — | 事件大类，如 `authentication`、`network` |
| `event_type` | string | — | 事件类型，如 `login_failed`、`connection_denied`（开放值，由解析器定义） |
| `action` | string | — | 记录的动作，如 `deny`、`login`、`update` |
| `result` | `Result` | — | `success/failure/unknown` |
| `severity` | `Severity` | ✅ | `info/low/medium/high/critical` |
| `message` | string | — | 人类可读摘要 |
| `raw_log` | string | ✅ | 原始日志行（不可丢失） |
| `parser_id` | string | — | 解析器 ID（见 §8） |
| `parser_version` | string | — | 解析器版本（见 §8） |
| `ingest_timestamp` | number (epoch ms) | ✅ | 服务端入库时间 |
| `event_attributes` | object | — | 厂商/产品扩展字段（见 §5） |

### 3.2 `audit_parse_failures` — `AuditParseFailure`

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `_timestamp` | number (epoch ms) | ✅ | 事件时间 |
| `tenant_id` | string | ✅ | 租户 ID（服务端指派） |
| `source_type` | string | — | 解析前可判定时的源大类，否则省略 |
| `source_name` | string | — | 源标识（可判定时） |
| `raw_log` | string | ✅ | 未解析的原始日志行 |
| `parser_id` | string | — | 尝试过的解析器（可选） |
| `parser_version` | string | — | 解析器版本（可选） |
| `error_message` | string | ✅ | 失败原因（无匹配解析器 / 校验失败 / …） |
| `ingest_timestamp` | number (epoch ms) | ✅ | 服务端入库时间 |

## 4. 标准枚举

### 4.1 `Severity`

```
info | low | medium | high | critical
```

归一化规则：解析器把源告警级别映射到五档；源无级别时默认 `info`。

### 4.2 `Result`

```
success | failure | unknown
```

### 4.3 `SourceType`

```
os | firewall | router | database | web | application | network | other
```

- `os` —— Linux/Windows 系统日志（`product` 区分具体 OS）
- `firewall` —— 防火墙
- `router` —— 路由/交换设备
- `database` —— 数据库审计
- `web` —— Web 服务器
- `application` —— 业务应用
- `network` —— 其它网络设备
- `other` —— 兜底

## 5. 扩展字段规范（`event_attributes`）

- 所有厂商/产品特有字段放入 `event_attributes`（`Record<string, unknown>`）。
- 键名采用**带厂商/产品前缀的点分命名**，避免冲突，例如：
  - `cisco.asa.message_id`
  - `microsoft.windows.event_id`
  - `nginx.request_id`
- 禁止把厂商字段平铺进 `AuditEvent` 公共字段——新增语义字段需先升级 Schema（v1→v2）。

## 6. `tenant_id` 生成规范

- `tenant_id` 由**服务端**根据已认证的 Org/租户上下文指派，采集端/浏览器上报的租户标识一律忽略。
- 采集端仅携带凭据（token / org_identifier），由服务端解析成可信 `tenant_id`。

## 7. `event_id` 生成规范

- 必须全局唯一、稳定（同一事件重复投递产生相同 ID，以支持幂等去重）。
- 推荐：`<parser_id> + <_timestamp> + hash(raw_log + source_name)` 的确定性哈希，或 ULID/UUIDv7。
- 生成方：解析器/采集管线（服务端侧），不信任客户端传入值。

## 8. Parser mapping 规范

- 每个事件记录 `parser_id`（稳定标识，如 `cisco-asa`）与 `parser_version`（语义化版本，如 `1.2.0`）。
- 同一 `parser_id` 的 Schema 输出必须向后兼容；破坏性变更须 `parser_version` 主版本递增。
- `parser_id` 未知/无匹配 → 落入 `audit_parse_failures`，并记录 `error_message`。
- 解析器把源字段映射到公共字段；无法映射的源字段进入 `event_attributes`。

## 9. 示例

### 9.1 完整事件（防火墙 deny）

```json
{
  "_timestamp": 1735689600000,
  "event_id": "evt-01J2A1B2C3D4E5F6G7H8J9K0",
  "tenant_id": "tenant-datafox-demo",
  "source_type": "firewall",
  "source_name": "edge-fw-01",
  "collector_id": "collector-syslog-3",
  "vendor": "Cisco",
  "product": "ASA",
  "product_version": "9.18.4",
  "hostname": "edge-fw-01",
  "asset_id": "asset-1001",
  "src_ip": "10.20.0.5",
  "src_port": 52314,
  "dst_ip": "172.16.0.10",
  "dst_port": 443,
  "username": "jdoe",
  "category": "network",
  "event_type": "connection_denied",
  "action": "deny",
  "result": "failure",
  "severity": "high",
  "message": "Connection denied by access-list",
  "raw_log": "Jan  1 08:00:00 edge-fw-01 %ASA-4-106023: Deny tcp src outside:10.20.0.5/52314 dst inside:172.16.0.10/443 by access-group \"outside-in\"",
  "parser_id": "cisco-asa",
  "parser_version": "1.2.0",
  "ingest_timestamp": 1735689601200,
  "event_attributes": {
    "cisco.asa.message_id": "106023",
    "cisco.asa.access_group": "outside-in",
    "cisco.asa.interface": "outside"
  }
}
```

### 9.2 最小事件（仅必填）

```json
{
  "_timestamp": 1735689600000,
  "event_id": "evt-min-00000000000000000001",
  "tenant_id": "tenant-datafox-demo",
  "source_type": "application",
  "severity": "info",
  "raw_log": "application started",
  "ingest_timestamp": 1735689600001
}
```

### 9.3 解析失败

```json
{
  "_timestamp": 1735689600000,
  "tenant_id": "tenant-datafox-demo",
  "source_name": "unknown-device",
  "raw_log": "\u001b[31mgarbage line with no known format\u001b[0m",
  "error_message": "No parser matched the source",
  "ingest_timestamp": 1735689600500
}
```

## 10. 实现位置

- 类型与枚举：`web/src/schemas/audit-event/{types,enums}.ts`
- Zod 校验：`web/src/schemas/audit-event/schema.ts`
- Fixtures：`web/src/schemas/audit-event/fixtures.ts`
- 单测：`web/src/schemas/audit-event/audit-event.spec.ts`
- 统一出口：`web/src/schemas/audit-event/index.ts`
