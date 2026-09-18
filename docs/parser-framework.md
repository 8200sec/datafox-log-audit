# Parser + Normalization Framework

DataFox 日志审计系统的日志 Parser 与 Normalization 框架。为后续 Generic JSON、
Syslog、Linux、Windows、Firewall、Database 等 Parser 提供统一接口与调度路径。

> **Parser Runtime = Backend Rust（`src/audit_parser/`）。** 所有真实日志解析只发生在服务端
> 摄取路径。**前端不执行任何真实日志解析** —— 前端只消费 `AuditEvent` 契约做展示与校验
> （`web/src/schemas/audit-event/`）。

## 1. 架构

```
Collectors ──► Audit Ingest API (POST /api/{org_id}/audit/ingest)
                    │ authenticate → 获得可信 org/tenant context
                    ▼
              ParserRegistry.detect ──► Parser.parse ──► ParsedEvent
                    │ (priority 排序)                        │
                    │ 未命中 → FallbackParser                 ▼
                    │                                     Normalizer
                    │                                          │
                    ▼                                          ▼
              ParseFailure ───────────► audit_parse_failures   AuditEvent
                                                                  │
                                                                  ▼
                                       OpenObserve existing ingestion (bulk)
                                                                  │
                                                                  ▼
                                                          audit_events stream
```

- **Parser** 只做识别与提取，产出中间 `ParsedEvent`（字段未归一化）。
- **Normalizer** 把 `ParsedEvent` 归一化为标准 `AuditEvent`。
- **Dispatcher** 编排 detect → parse → normalize，任何环节失败都落到结构化 `ParseFailure`。
- **Fallback** 兜底，**日志绝不静默丢失**。

## 2. Runtime 位置（重要）

| 层 | 位置 | 职责 |
| --- | --- | --- |
| **Parser Runtime（服务端）** | `src/audit_parser/`（Rust） | Parser trait / Registry / Dispatcher / Normalizer / Failure / Dummy+Fallback |
| **数据契约（前端）** | `web/src/schemas/audit-event/`（TS） | AuditEvent 接口、severity/result/source_type 枚举、Zod 校验、fixtures |

前端**不再**包含 ParserRegistry / Dispatcher / detect / parse / Normalizer 执行逻辑
（这些已从 `web/src/parser/` 迁移至 Rust 后端）。浏览器不在日志标准化链路中。

## 3. Parser 生命周期

1. **detect**（廉价识别）：`detect(input) -> bool`，不抛错。
2. **parse**（完整提取）：`parse(input) -> anyhow::Result<ParsedEvent>`，可抛错（Dispatcher 转 `PARSER_EXCEPTION`）。
3. **normalize**（归一化）：由 Normalizer 转成 `AuditEvent`。

## 4. Rust Parser trait

```rust
pub trait Parser: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn version(&self) -> &str;          // semver，破坏性变更主版本递增
    fn priority(&self) -> i32;          // 越大越先尝试
    fn supported_source_types(&self) -> &[&'static str]; // 空 = 任意
    fn detect(&self, input: &RawLogInput) -> bool;
    fn parse(&self, input: &RawLogInput) -> anyhow::Result<ParsedEvent>;
}
```

- `detect` 与 `parse` 分离。
- Parser **不得修改** `input.raw_log`（不变式）。

## 5. ParserRegistry（Rust）

```rust
impl ParserRegistry {
    pub fn register(&mut self, parser: Arc<dyn Parser>) -> anyhow::Result<()>;
    pub fn set_fallback(&mut self, parser: Arc<dyn Parser>);
    pub fn lookup(&self, id: &str) -> Option<Arc<dyn Parser>>;
    pub fn list(&self) -> Vec<Arc<dyn Parser>>;            // priority 降序
    pub fn detect(&self, input: &RawLogInput) -> Vec<Arc<dyn Parser>>;
}
```

- 新增 Parser 只需 `register()`，**Dispatcher 主逻辑不改**。
- **无 vendor 大型 match/switch** —— 声明式注册 + priority + detect。

## 6. Normalizer（Rust）

把 `ParsedEvent` 归一化为 `AuditEvent`，统一处理 timestamp / severity / result /
source_type / src_ip / src_port / dst_ip / dst_port / username / hostname /
category / event_type / action。

- severity 最终只能输出 `info | low | medium | high | critical`。
- result 最终只能输出 `success | failure | unknown`。
- `tenant_id` 只取 `input.tenant.tenant_id`（可信），**不接受 raw_log 覆盖**。

## 7. Failure model（Rust）

```rust
pub struct ParseFailure {
    pub timestamp: i64,
    pub raw_log: String,
    pub source_type: Option<String>,
    pub source_name: Option<String>,
    pub collector_id: Option<String>,
    pub parser_id: Option<String>,
    pub parser_version: Option<String>,
    pub failure_stage: FailureStage,   // detect | parse | normalize
    pub failure_code: FailureCode,
    pub failure_message: String,
}
```

`failure_code`：`UNSUPPORTED_FORMAT | MISSING_REQUIRED_FIELD | INVALID_TIMESTAMP |
INVALID_IP | INVALID_ENUM | PARSER_EXCEPTION | NORMALIZATION_FAILED`。

Parser panic/error 一律转 `ParseFailure`，**不静默丢日志**。

## 8. Audit Ingestion API（服务端入口）

已实现路由（遵循 OpenObserve `context_path="/api"` + `path="/{org_id}/..."` 约定）：

```
POST /api/{org_id}/audit/ingest
```

实现位置：`src/api/ingest/src/request/audit/ingest.rs`（注册于
`src/api/http/.../router/mod.rs`）。

流程：

1. **authenticate** → 从 `Headers<UserEmail>` 提取已认证用户；`org_id` 来自路径（可信服务端上下文）。
2. 构造 `RawLogInput{ raw_log, received_at, source_type?, source_name?, collector_id?, tenant_id=org_id }`。
3. **Dispatcher.dispatch** → `Ok(AuditEvent)` 或 `Failure(ParseFailure)`。
4. `Ok` → 序列化 → `logs::ingest::ingest(... "audit_events" ...)`（复用现有 bulk ingestion）。
5. `Failure` → 序列化 → `... "audit_parse_failures" ...`。
6. 若 `audit_parse_failures` 写入也失败 → 返回 **500** + `log::error!`（不 swallow）。

**Single-event 请求**（当前实现）：

```json
{
  "source_type": "firewall",
  "source_name": "edge-fw-01",
  "collector_id": "syslog-3",
  "raw_log": "<134>Oct 11 22:14:15 edge-fw-01 %ASA-4-106023: Deny tcp ..."
}
```

curl：

```bash
curl -s -X POST "http://localhost:5080/api/{org_id}/audit/ingest" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source_type":"firewall","source_name":"edge-fw-01","raw_log":"<134>... Deny tcp ..."}'
```

> **Batch contract（后续）**：当前只支持 single event。批量设计为
> `{ "events": [ {…}, {…} ] }`，一次 dispatch 多条后合并为单次
> `IngestionRequest::JsonValues(Bulk, vec![...])` 写入。待需要时补充。

> **接入说明**：复用 `src/core/src/logs/ingest.rs`（`logs::ingest::ingest`），
> 属 `src/core`（非 protected 清单），**未改动** Storage/WAL/Ingester/Parquet writer。

## 9. 新增 Parser 教程（Rust）

```rust
pub struct CiscoAsaParser;
impl Parser for CiscoAsaParser {
    fn id(&self) -> &str { "cisco-asa" }
    fn name(&self) -> &str { "Cisco ASA" }
    fn version(&self) -> &str { "1.0.0" }
    fn priority(&self) -> i32 { 50 }
    fn supported_source_types(&self) -> &[&'static str] { &["firewall"] }
    fn detect(&self, i: &RawLogInput) -> bool {
        i.source_type.as_deref() == Some("firewall") && i.raw_log.contains("%ASA-")
    }
    fn parse(&self, i: &RawLogInput) -> anyhow::Result<ParsedEvent> {
        Ok(ParsedEvent {
            parser_id: "cisco-asa".into(),
            parser_version: "1.0.0".into(),
            raw_log: i.raw_log.clone(),           // 原样，不改写
            timestamp: Some(parse_asa_time(&i.raw_log)),
            severity: Some("warning".into()),     // 未归一化，交给 Normalizer
            result: Some("deny".into()),
            source_type: Some("firewall".into()),
            attributes: Some(serde_json::json!({"cisco.asa.message_id": "106023"})),
            ..Default::default()
        })
    }
}

registry.register(Arc::new(CiscoAsaParser)).unwrap(); // 即插即用
```

## 10. 测试规范

- 后端：`src/audit_parser/tests/parser_test.rs`（15 项，`cargo test -p audit_parser`）。
  覆盖注册/priority/detect/parse/fallback/normalization/parser error/normalization error/
  raw_log 不变式/tenant 覆盖拒绝/parser id+version/malformed/dispatcher 稳定。
- 前端：`web/src/schemas/audit-event/audit-event.spec.ts`（13 项，契约层）。
- 新增 Parser 时补充该 Parser 的 detect/parse 单测，复用框架级契约测试。
