# SecurityEvent API & Workflow v1

W3-08 实现 SecurityEvent 的查询与工作流 HTTP API：`list / detail / actions / acknowledge /
resolve / close`。分层为 **HTTP handler → Service → Repository**，租户隔离贯穿三层，状态机 +
审计 trail 在同一事务内完成。

## 1. Endpoints

全部挂在 `/api/{org_id}/security-events` 下，复用 OpenObserve 认证（`{org_id}` 即认证后的
tenant，绝不从 body/query 取租户）。

| Method | Path | 说明 |
| --- | --- | --- |
| GET | `/api/{org_id}/security-events` | 分页列表（多过滤器） |
| GET | `/api/{org_id}/security-events/{event_id}` | 单条详情 |
| GET | `/api/{org_id}/security-events/{event_id}/actions` | 工作流审计历史 |
| POST | `/api/{org_id}/security-events/{event_id}/acknowledge` | 认领（open → acknowledged） |
| POST | `/api/{org_id}/security-events/{event_id}/resolve` | 处置（ack/resolved → resolved） |
| POST | `/api/{org_id}/security-events/{event_id}/close` | 关闭（open/ack/resolved → closed） |

`{event_id}` 是 SecurityEvent 的 `event_id`（detection 生成的 uuid v7），不是 AuditEvent id。

## 2. List 过滤器与分页

`GET /api/{org_id}/security-events` 查询参数（全部可选）：

- `status` = `open | acknowledged | resolved | closed`
- `severity` = `info | low | medium | high | critical`
- `rule_id`、`event_type`、`src_ip`、`username` — 精确匹配
- `last_seen_from` / `last_seen_to` — epoch **毫秒**闭区间
- `limit` — 每页条数，默认 `DEFAULT_LIMIT=50`，上限 `MAX_LIMIT=200`（超出 clamp，不报错）
- `offset` — 偏移量，默认 0
- `sort` = `desc`（默认，last_seen 降序）| `asc`

响应：

```json
{ "items": [ { "...": "SecurityEvent 字段" } ], "total": 42, "limit": 50, "offset": 0 }
```

`total` 是**未分页**的匹配总数。排序主键 `last_seen DESC`，次键 `event_id DESC`（稳定分页）。
v1 采用 offset/limit；cursor（`(last_seen, event_id)` 游标）留作后续优化，见 §7。

## 3. 工作流状态机

| from | 可到 |
| --- | --- |
| open | acknowledged / resolved / closed |
| acknowledged | resolved / closed |
| resolved | closed |
| closed | （终态，无出口） |

非法迁移返回 **409 Conflict**，不写任何行。状态机定义在 `Status::can_transition_to`，
repository 与 API 共用同一判定，不存在「API 通过但存储层绕过」的口子。

工作流 POST **只改 `status` + `updated_at`**，绝不触碰 `event_count / last_seen / rule_id /
severity / evidence / related_event_ids / created_at`——检测聚合与人工处置互不覆盖。

## 4. 审计 trail（security_event_actions）

每次成功迁移在同一 SQLite 事务内 append 一条 action：

```
(id uuid v7, tenant_id, security_event_id, action, from_status, to_status,
 actor_id, comment, created_at)
```

- `action` ∈ `acknowledge | resolve | close`（语义动作名，非状态名）。
- `actor_id` 取自**认证身份**（`Headers<UserEmail>.user_id`），绝不从 body 读。
- `comment` 可选，上限 `MAX_COMMENT_LENGTH=4000`（超出 400）。

## 5. 并发（compare-and-swap）

迁移在事务内 `SELECT status` → 校验状态机 → `UPDATE ... WHERE tenant_id=? AND event_id=?
AND status=?`（CAS）。若并发迁移已抢先改了 status，`UPDATE` 命中 0 行 → **409 Conflict**，
不会覆盖他人操作。状态变更与 action 记录同事务提交，要么都成、要么都不成。

## 6. 租户隔离

- 所有查询都以 `tenant_id` 为 WHERE 条件；`tenant_id` 只来自认证后的 `{org_id}`。
- 跨租户访问（event_id 存在于别的 org）返回 **404**，不泄露存在性。
- `list_actions` 本身查不到即空，service 层先 `get` 确认存在，保证「event 不存在」与
  「无历史」都能正确区分（前者 404）。

## 7. 已知限制（v1）

- 分页为 offset/limit；大 offset 下有性能退化风险，cursor 游标分页列为后续项。
- 存储为 embedded SQLite（`datafox.db`），单机单写；换 PostgreSQL HA 时只需替换
  `SecurityEventRepository` impl，API/service 层不变。
- 无 UI：本任务只交付 API，前端在后续周次接入。

## 8. 分层与文件

```
HTTP handler (src/api/ingest/src/request/audit/security_event.rs)
    → SecurityEventService (list/get/transition/actions, 错误→HTTP 映射)
        → SecurityEventRepository trait (src/audit_rule/src/repository.rs)
            → SqliteSecurityEventRepository (rusqlite 只在 impl 内)
```

- 路由注册：`src/api/http/src/handler/http/router/mod.rs`。
- 共享 repository 单例：`src/api/ingest/src/request/audit/ingest.rs::repository()`（检测管道
  与 API 共用同一实例，窗口状态与工作流状态一致）。
- handler 不 import `rusqlite`；Repository 错误通过 `ServiceError` 映射为
  404/409/400/500。
