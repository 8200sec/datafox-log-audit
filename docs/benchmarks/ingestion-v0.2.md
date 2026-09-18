# Ingestion Baseline Benchmark — v0.2

DataFox Log Audit v0.2 ingestion baseline 的功能与资源基准验证记录。

> 所有数字来自本地 debug build，非 release。真实吞吐以 release build + 生产硬件为准；
> 本文记录的是「可复现的本地验证结果」，不是生产容量承诺。

## 1. 测试环境

| 项 | 值 |
| --- | --- |
| 硬件 | Apple Silicon arm64，10 核 / 24 GB（**未限制到 4C/16GB**，按实际硬件记录） |
| OS | macOS（darwin） |
| Rust toolchain | nightly-2026-05-20 |
| 构建 | `cargo build`（**debug**，未 `--release`） |
| 后端 | 单节点 `./target/debug/openobserve`（`:5080`） |
| 数据存储 | 本地磁盘 `data/`（sled + parquet） |
| 客户端 | Python3 `requests` 并发压测（`/tmp/datafox-bench.py`） |

## 2. 测试数据

每 10 条日志的混合分布（覆盖全部 parser 路径 + 固定 10% 失败样本）：

| 占比 | 样本 | 目标 parser |
| --- | --- | --- |
| 30% | `<34>… sshd[pid]: Accepted password for userN from 10.0.0.N port 55231 ssh2` | linux-auth |
| 30% | `<34>… cron[pid]: (root) CMD (run-parts …)` | generic-syslog |
| 20% | `{"timestamp":"…","message":"event N","level":"info"}` | generic-json |
| 10% | `unrecognized-format-line-N` | fallback |
| 10% | `{"@timestamp":"garbage","message":"bad"}` | **ParseFailure** |

## 3. Ingestion Profile（每档 20s）

| 目标 EPS | 实际 EPS | 平均延迟 | p95 | 峰值 CPU | RSS 变化 | 失败率 |
| --- | --- | --- | --- | --- | --- | --- |
| 100 | 91.5 | 8.3 ms | 10.3 ms | ~72% | 505 → 548 MB | 10% |
| 500 | **259.4**（饱和） | 19.2 ms | 25.1 ms | ~130% | 762 → 981 MB | 10% |
| 1000 | **226.3**（饱和） | 44.1 ms | 49.6 ms | ~154% | 981 → 1114 MB | 10% |

- **单节点 debug build 摄取上限 ≈ 230–260 EPS**。超过后延迟随并发线性上升（500/1000 档均未达目标，客户端请求排队，后端饱和）。
- 失败率稳定 10% = 注入的 10% malformed 样本，全部正确落入 `audit_parse_failures`。
- 磁盘：100 EPS 档约 +3.1 MB / 2k 条；高并发下 compactor/GC 后台合并，净增量波动（1000 档甚至为负）。

## 4. 查询延迟（约 3 万条事件后）

| 查询 | 延迟 |
| --- | --- |
| 15 分钟 count(*)（audit_events） | 82 ms |
| 全文 message `LIKE '%user%' LIMIT 50` | 911 ms |
| `GROUP BY parser_id` | 102 ms |
| `GROUP BY failure_code`（failures） | 29 ms |

## 5. Known Limitations

1. **debug build 吞吐受限**：~230–260 EPS 是 debug 单节点上限；release 预期高一个数量级，未测。
2. **单事件 API**：审计摄取 bridge 目前每条日志一个 HTTP 请求（`POST /api/{org}/audit/ingest`），
   无 batch/bulk 端点；高 EPS 时 HTTP 往返开销成为瓶颈。后续可加批量端点（不涉及 core 改动）。
3. **历史日志无 `parser_quality`**：解析状态页通过 `parser_id` 查询侧映射（`classifyParser`）
   分类，覆盖历史日志，未批量回填历史 `audit_events`。
4. **custom 时间范围**：解析状态页当前仅 15m/1h/24h/7d 预设，custom 待接入 `ODateTimeRange`。
