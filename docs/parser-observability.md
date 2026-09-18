# Parser Observability & Parse Failure Center

DataFox 日志接入的「解析状态」观测能力。目标：让管理员一眼看清日志摄取量、Parser 使用
分布、专用 Parser 覆盖率、Generic Parser 使用率、Fallback 数量、Parse Failure 数量与
原因，以及最需要新增 Parser 的日志源。

> **核心原则**：不引入 Prometheus / Kafka / Redis / 新的 metrics database / 后台 daemon。
> 所有统计都来自已有的 `audit_events` 与 `audit_parse_failures` 两个 stream，复用
> OpenObserve 现有 Search / Aggregation 能力（SQL `GROUP BY`）。

## 1. Parser Classification

Parser 按逻辑分三类，分类由 **parser_id 映射**得出（不新增 `AuditEvent` 顶层字段）：

| 分类 | 值 | parser_id |
| --- | --- | --- |
| `specialized` | 专用（某产品/领域） | `linux-auth`（后续 vendor parser 归入此类） |
| `generic` | 通用（整类格式，无领域语义） | `generic-json`、`generic-syslog` |
| `fallback` | 兜底（无专用 Parser 认领） | `fallback` |

- 权威映射在 **Rust**：`src/audit_parser/src/observability.rs` 的 `classify_parser(parser_id)`。
- 归一化时 `Normalizer` 把分类结果写入 `event_attributes.parser_quality`（值：
  `specialized` / `generic` / `fallback`），因此前端可直接 `GROUP BY parser_quality` 聚合，
  无需在浏览器端重复维护分类映射。
- 未知 parser_id（测试 parser、未来未登记的 vendor parser）默认归 `generic`——安全假设是
  「通用，直到被显式登记为专用」。

## 2. Fallback vs Failure（必须区分）

| | Fallback | ParseFailure |
| --- | --- | --- |
| 含义 | 日志**成功保存**，只是没有专用 Parser 认领 | Parser **已尝试**但 parsing / normalization 出错 |
| 落入 stream | `audit_events`（`parser_id = fallback`） | `audit_parse_failures` |
| 是否算失败 | **否** | 是 |

两者在 API、UI、统计中严格区分：Fallback 计入成功摄取（是 `audit_events` 的一部分），
ParseFailure 独立计数、独立展示，绝不混入成功事件。

## 3. Metrics Definition

设：

- `total_ingested` = `audit_events` 中所有事件数量（成功摄取，含 fallback）。
- `specialized_count` / `generic_count` / `fallback_count` = 对应 `parser_quality` 的事件数。
- `parse_failure_count` = `audit_parse_failures` 中的记录数。

比率定义（分母见下，注意**不要重复计数**——failure 在独立 stream，不在 `audit_events` 中）：

```
specialized_ratio   = specialized_count / total_ingested
generic_ratio       = generic_count     / total_ingested
fallback_ratio      = fallback_count    / total_ingested
parse_failure_ratio = parse_failure_count / (total_ingested + parse_failure_count)
```

- `parse_failure_ratio` 的分母是「成功 + 失败」总数，代表「所有被处理的日志中失败占比」。
- 除数为 0 时所有比率为 0（`safeRatio`，避免 NaN）。

实现：纯函数在 `web/src/utils/parseObservability.ts`（`computeObservabilityStats` +
`safeRatio`），单测覆盖零分母、排序、比率计算。

## 4. Query Strategy

前端「解析状态」页在首次加载发起 **6 个聚合请求**（`Promise.all` 并发，无重复、无轮询）：

| # | SQL（`audit_events` / `audit_parse_failures`） | 产出 |
| --- | --- | --- |
| 1 | `SELECT parser_quality, count(*) … GROUP BY parser_quality` | 三类计数（求和 = total） |
| 2 | `SELECT parser_id, count(*) … GROUP BY parser_id` | Parser usage |
| 3 | `… WHERE parser_id='fallback' GROUP BY source_name` | Fallback source top |
| 4 | `SELECT failure_code, count(*) … GROUP BY failure_code` | Failure reasons（求和 = failure count） |
| 5 | `SELECT source_name, count(*) … GROUP BY source_name`（failures） | Failure source top |
| 6 | `SELECT * … ORDER BY _timestamp DESC LIMIT 100`（failures） | Failure records |

- 全部走 OpenObserve 现有 `POST /api/{org}/_search`（SQL 聚合），**不新建统计库**、
  **不为每条日志写额外 metrics event**、**不复制 Search Engine**。
- 缺失 stream（尚无 failure）按空结果处理，不报错——驱动空状态而非错误状态。
- 时间范围通过 `start_time` / `end_time`（µs）作用于所有查询。

## 5. Performance & Resource

- 首次加载 6 个并发聚合请求，单次往返；支持手动刷新。
- **禁止** 1 秒级自动轮询；默认无自动刷新（仅手动），避免页面关闭后残留后台查询。
- 页面卸载即停止；不引入常驻资源消耗（无 daemon、无新存储）。

## 6. Troubleshooting Workflow

1. **无数据 / 摄取为 0** → 确认 Collector 是否在发、`/api/{org}/audit/ingest` 是否 200。
2. **Fallback 占比高** → 看 `Fallback source top`，优先为占比最高的 source 新增专用 Parser。
3. **Parse failure 高** → 看 `Failure reasons`（`failure_code` 聚合）定位主因（如
   `INVALID_TIMESTAMP` / `PARSER_EXCEPTION`）；`Failure records` 展开 `raw_log` 逐条复现。
4. **专用解析率低** → 说明大多数日志走 generic / fallback，按 source 判断该补哪个 vendor Parser。
