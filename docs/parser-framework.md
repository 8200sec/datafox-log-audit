# Parser + Normalization Framework

DataFox 日志审计系统的日志 Parser 与 Normalization 框架。为后续 Generic JSON、
Syslog、Linux、Windows、Firewall、Database 等 Parser 提供统一接口与调度路径。

> 实现：`web/src/parser/`（纯 TypeScript，无浏览器 API，设计为运行于服务器端/日志摄取路径）。
> 数据模型：见 `docs/audit-event-schema.md`（AuditEvent v1）。

## 1. 架构

```
 RawLogInput ──► ParserRegistry.detect ──► 命中? ──► Parser.parse ──► ParsedEvent
      │                                        │                            │
      │                                        │ (priority 排序)              ▼
      │                                        │                        Normalizer
      │                                        │                            │
      │                                   未命中                           ▼
      │                                        ▼                      AuditEvent ──► audit_events
      │                                    FallbackParser
      │                                        │
      └────────────────────────────────────────┴──► 任何异常/失败 ──► ParseFailure ──► audit_parse_failures
```

- **Parser** 只做识别与提取，产出中间 `ParsedEvent`（字段未归一化）。
- **Normalizer** 负责把 `ParsedEvent` 归一化为标准 `AuditEvent`（severity/result/source_type/IP/port/timestamp 等）。
- **Dispatcher** 编排 detect → parse → normalize，任何环节失败都落到结构化 `ParseFailure`，**日志绝不静默丢失**。
- **Fallback** 兜底：无专用 Parser 匹配时仍产出最小可用事件，不因「不认识格式」而丢弃。

> 运行位置：本框架是**纯 TypeScript、无 DOM/浏览器依赖**，可直接运行于 Node worker /
> 摄取服务，或移植为 Rust 实现。解析逻辑严禁下沉到浏览器 Vue 组件。

## 2. Parser 生命周期

1. **detect**（廉价识别）：`detect(input): boolean` —— 判断能否处理该日志，不抛异常。
2. **parse**（完整提取）：`parse(input): ParsedEvent` —— 提取字段，可抛异常（由 Dispatcher 捕获转 `PARSER_EXCEPTION`）。
3. **normalize**（归一化）：由 Normalizer 把 `ParsedEvent` 转成 `AuditEvent`。

## 3. RawLogInput

```ts
interface RawLogInput {
  raw_log: string;         // 原始日志行（不可变）
  received_at: number;     // epoch ms，采集端接收时间
  source_type?: string;    // 源大类提示（detect/parse 可细化）
  source_name?: string;
  collector_id?: string;
  tenant: TenantContext;   // 可信服务端租户上下文
  transport?: TransportMetadata; // protocol / remote_ip / remote_port
}
```

**`tenant_id` 只来自 `tenant: TenantContext`（可信服务端上下文），原始日志中的租户标识一律忽略。**

## 4. Parser Interface

```ts
interface Parser {
  id: string;                    // 稳定标识，如 "cisco-asa"
  name: string;
  version: string;               // semver，破坏性变更主版本递增
  priority: number;              // 数值越大越先尝试
  supportedSourceTypes: string[];// 声明的源大类，空 = 任意
  detect(input: RawLogInput): boolean;
  parse(input: RawLogInput): ParsedEvent;
}
```

- `detect` 与 `parse` 分离：识别廉价、提取完整。
- Parser **不得修改** `input.raw_log`（不变式），只返回新的 `ParsedEvent`。

## 5. Parser Registry

```ts
class ParserRegistry {
  register(parser: Parser): void;      // 重复 id 抛错
  setFallback(parser: Parser): void;
  lookup(id: string): Parser | undefined;
  list(): Parser[];                    // 按 priority 降序
  detect(input: RawLogInput): Parser[];// 命中且按 priority 排序
  getFallback(): Parser | null;
}
```

- **新增 Parser 只需 `register()`，Dispatcher 无需改动**。
- **无大型 `if vendor == … else if` switch** —— 用注册表 + priority + detect 声明式解决。

## 6. Normalizer

把 `ParsedEvent` 归一化为 `AuditEvent`，统一处理：

| 维度 | 行为 |
| --- | --- |
| timestamp | `parsed._timestamp ?? received_at`；无效值 → `INVALID_TIMESTAMP` 失败 |
| severity | 别名映射 → `info/low/medium/high/critical`，未识别默认 `info` |
| result | 别名映射 → `success/failure/unknown`，未识别默认 `unknown` |
| source_type | 别名映射 → 标准 `SourceType`，未识别默认 `other` |
| IP | 校验 IPv4/IPv6，无效则丢弃该字段（宽松） |
| port | 校验 0–65535，无效则丢弃（宽松） |
| username / hostname / category / event_type / action | 透传 |
| event_id | 确定性哈希（tenant+source+raw+time），幂等去重 |
| tenant_id | 仅取 `input.tenant.tenant_id`（可信） |
| raw_log | **byte-for-byte 原样保留** |

severity 最终只能输出 `info/low/medium/high/critical`；result 最终只能输出 `success/failure/unknown`。

## 7. Failure Handling

任何异常都不静默丢日志，统一落到 `ParseFailure`（→ `audit_parse_failures`）。

```ts
interface ParseFailure {
  _timestamp: number;
  raw_log: string;
  source_type?: string;
  source_name?: string;
  collector_id?: string;
  parser_id?: string;
  parser_version?: string;
  failure_stage: "detect" | "parse" | "normalize";
  failure_code: FailureCode;
  failure_message: string;
}
```

`failure_code`：

```
UNSUPPORTED_FORMAT      无匹配 Parser 且无 fallback
MISSING_REQUIRED_FIELD  raw_log 为空等必填缺失
INVALID_TIMESTAMP       时间戳无效
INVALID_IP              IP 无效（预留/严格模式）
INVALID_ENUM            枚举越界（预留/严格模式）
PARSER_EXCEPTION        Parser 抛异常
NORMALIZATION_FAILED    归一化失败（预留）
```

## 8. raw_log 不变式

- `AuditEvent.raw_log` 必须与输入 `RawLogInput.raw_log` **完全一致**（byte-for-byte）。
- 不得 trim、rewrite 或重新序列化。已由测试 #9 覆盖。

## 9. 新增 Parser 教程

以 `CiscoParser` 为例（本任务不实现，仅示意）：

```ts
export const CiscoAsaParser: Parser = {
  id: "cisco-asa",
  name: "Cisco ASA",
  version: "1.0.0",
  priority: 50,
  supportedSourceTypes: ["firewall"],
  detect: (input) => input.source_type === "firewall" && input.raw_log.includes("%ASA-"),
  parse: (input): ParsedEvent => ({
    parser_id: "cisco-asa",
    parser_version: "1.0.0",
    raw_log: input.raw_log,           // 原样，不改写
    _timestamp: parseAsaTime(input.raw_log),
    severity: "warning",              // 未归一化，交给 Normalizer
    result: "deny",
    source_type: "firewall",
    message: "ASA deny",
    attributes: { "cisco.asa.message_id": "106023" }, // 厂商字段进 attributes
  }),
};

registry.register(CiscoAsaParser);    // 即插即用，Dispatcher 不变
```

要点：
1. 实现 `Parser` 接口，`detect` 做廉价识别，`parse` 做提取。
2. 厂商字段进 `attributes`（→ `event_attributes`），不进公共 Schema。
3. severity/result 用源原始值，归一化交给 Normalizer。
4. `raw_log` 原样透传。

## 10. 测试规范

`web/src/parser/parser.spec.ts` 覆盖框架契约（注册/优先级/detect/parse/不匹配/fallback/异常/归一化失败/raw_log 不变式/severity/result/tenant 信任/parser 元数据/malformed 不 crash）。新增 Parser 时，为每个 Parser 补充 `detect` 与 `parse` 单测，并复用框架级测试保证契约不变。
