# Detection v0.3 Benchmark

DataFox Log Audit v0.3 detection 与 security event 的功能与资源基准验证记录。

> 所有数字来自本地 **debug build**，非 release。真实吞吐以 release build + 生产硬件为准；
> 本文记录的是「可复现的本地验证结果」，不是生产容量承诺。

## 1. 测试环境

| 项 | 值 |
| --- | --- |
| Git commit | `192f1eaff feat(web): add security event center v1`（v0.3 验证基线） |
| 测试日期 | 2026-09-19 |
| 硬件 | Apple M4（Mac16,12），10 核 / 24 GB（**未限制到 4C/16GB**，按实际硬件记录） |
| OS | macOS 26.6.2 |
| Rust toolchain | 1.97.0-nightly（2026-05-19） |
| Node | v24.13.0 |
| OpenObserve 基线 | `v1.0.1`（DataFox 二开 fork） |
| DataFox 版本 | v0.3 detection baseline |
| 构建 | `cargo build`（**debug**，未 `--release`） |
| 后端 | 单节点 `./target/debug/openobserve`（`:5080`） |
| Parser 数量 | 5（generic-json / generic-syslog / linux-auth / fallback / dummy） |
| Active 内置规则 | 3（ssh_bruteforce / suspicious_sudo_shadow / repeated_pam_failure） |

## 2. SQLite SecurityEvent 数据规模基准

使用真实 `SqliteSecurityEventRepository`（file-backed），插入 1k / 10k / 50k 条
SecurityEvent（status / severity / rule / last_seen 均匀分布），逐条测 insert / update，
再测 list page / filter / detail lookup。来源 `src/audit_rule/tests/scale_benchmark.rs`
（`cargo test -p audit_rule --test scale_benchmark -- --ignored --nocapture`）。

| 规模 | DB 文件大小 | insert p50 / p95 | update p50 / p95 | list p50 / p95 | detail p50 / p95 |
| --- | --- | --- | --- | --- | --- |
| 1,000 | 467 KB | 360 / 465 µs | 279 / 370 µs | 1.43 / 1.99 ms | 32 / 34 µs |
| 10,000 | 4.3 MB | 325 / 447 µs | 248 / 411 µs | 1.82 / 2.47 ms | 32 / 36 µs |
| 50,000 | 21.7 MB | 346 / 581 µs | 266 / 586 µs | 4.08 / 4.98 ms | 33 / 39 µs |

filter（单次，50k 规模）：status ~1.7 ms、severity ~1.6 ms、rule ~1.9 ms。
detail 命中主键索引（~32 µs）；list page 含 COUNT(*) + LIMIT/OFFSET，随总量略增但仍 <5 ms。

## 3. Detection Throughput（EPS）

混合日志（50% generic-syslog、20% generic-json、20% linux-auth ssh failure、10% 失败/回退），
开启全部 3 条内置检测规则，通过 `POST /api/default/audit/ingest` 单事件端点压测。

| 目标 EPS | 客户端并发 | 实际吞吐 | ingest 延迟 p50 / p95 | CPU | RSS |
| --- | --- | --- | --- | --- | --- |
| 100 | 串行 | 278 eps（饱和） | 3.6 / 4.1 ms | ~86% | 269 MB |
| 500 | 串行 | 278 eps（饱和） | 3.6 / 4.1 ms | ~90% | 350 MB |
| 1000 | 串行 | 278 eps（饱和） | 3.6 / 4.1 ms | ~90% | 515 MB |
| 100 | 16 并发 | 1439 eps | 10.5 / 15.2 ms | ~176% | 524 MB |
| 500 | 16 并发 | 1534 eps | 10.0 / 14.2 ms | ~319% | 524 MB |
| 1000 | 16 并发 | 1536 eps | 9.9 / 14.4 ms | ~338% | 524 MB |

- **串行客户端 ~278 EPS 即饱和**（单事件 HTTP 端点，每请求 ~3.6 ms）。
- **16 并发下 ~1500 EPS 饱和**，100 / 500 / 1000 EPS 目标均可达到；延迟升至 ~10 ms（排队）。
- 检测阶段（SSH brute-force 阈值窗口）持续生成 SecurityEvent，未观察到检测错误或窗口容量告警。

## 4. 空闲基线

| 项 | 值 |
| --- | --- |
| 后端空闲 RSS | ~249 MB |
| 后端空闲 CPU | ~3.3%（无请求） |
| SQLite 无请求 CPU | 0（同步内嵌，无后台轮询） |
| 前端 dev server | 不计入正式部署 baseline |

## 5. 查询延迟

| 查询 | 延迟 |
| --- | --- |
| OpenObserve 24h `COUNT(*)`（audit_events） | 32 ms |
| OpenObserve message 全文 `LIKE '%Failed%'` LIMIT 50 | 248 ms |
| OpenObserve `GROUP BY parser_id` | 44 ms |
| SecurityEvent SQLite list page（50k，page 50） | ~4 ms |
| SecurityEvent SQLite detail（主键） | ~33 µs |

无 >1s 的本地测试热点；全文 `LIKE` 为最慢项（248 ms），仍在可接受范围，v0.3 不做微优化。

## 6. Known Limitations

1. **Window State 重启后丢失**：threshold 窗口是内存态，后端重启即清空（按设计）。
   SecurityEvent current state 与 action history 持久化于 SQLite，窗口不持久化。
2. **Rule Registry 以内置 rules 为主**：v0.3 仅注册 3 条内置规则；无运行时动态注册/热更新。
3. **无 Rule Management UI**：规则编辑/管理界面未实现（W3-10 明确禁止提前开发）。
4. **无 Window persistence**：无 Redis/Kafka 等外部窗口存储；重启后窗口从零重建。
5. **SQLite 单机 current-state store**：`datafox.db` 为单节点嵌入式存储，无多节点共享。
6. **无 PostgreSQL HA**：`SecurityEventRepository` trait 预留了替换点，但 v0.3 未实现 PG 后端。
7. **无 SecurityEvent HistorySink**：SecurityEvent 不落 OpenObserve log 流（raw_log 不复制）。
8. **Parser 覆盖有限**：仅 generic-json / generic-syslog / linux-auth / fallback。
9. **Windows / vendor parser 未实现**：Windows EventLog、Fortinet/Cisco/Huawei 等厂商 parser 尚未实现。
10. **单事件 ingest 端点**：无 batch/bulk 审计摄取端点，高 EPS 时 HTTP 往返为瓶颈（与 v0.2 相同）。

## 7. 4C/16GB Target Evaluation

本机为 Apple M4（10 核 / 24 GB），**无法准确限制到 4 vCPU / 16 GB**（未使用 cgroup/VM 限制）。
上述吞吐/延迟均在 10 核 24GB 硬件上测得。**4C/16GB 目标需专门环境验证**，此处不伪造数据。
