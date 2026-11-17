# sqlite-wal-forensic-auditor

Python 实现的 SQLite WAL（Write-Ahead Log）取证审计器。应用删除或修改
数据后，主库页面已经变化，但 WAL 中可能仍保留旧页面镜像。本工具不把
整个 WAL 当作“可查询数据库”，而是严格按照 SQLite 的 WAL 读取语义重建
**页面版本**，帮助取证人员区分真正可见的历史与不可采信的残留帧。

## 它解析什么

- 32 字节 WAL header：magic、文件格式版本、页面大小、checkpoint 序号、
  salt-1/salt-2 与 header checksum。
- 24 字节 frame header：page number、提交后数据库大小（db-size）、
  salt-1/salt-2、累积 checksum-1/checksum-2。
- checksum 链：逐帧累积，支持 big-endian 与 little-endian 两种 checksum
  词序变体（按 header checksum 实测判定，而非只看 magic）。
- commit frame：frame header 的 db-size 非零即提交边界；每个有效
  commit frame 对应一个可见数据库快照版本。

## 输出的证据

- **可见版本**：按每个有效 commit frame 重建的页面快照与 db-size。
- **最后一次完整提交点**：最后一个 checksum、salt 均合法的 commit frame。
- **页面覆盖/复用时间线**：每个页面在何时（哪个 frame、哪个字节偏移）
  被新镜像覆盖，以及该覆盖是否属于提交帧。
- **未提交尾部**：位于最后一个 commit frame 之后的帧；页面镜像存在但
  不属于任何快照。
- **孤立帧**：stale salt、checksum 不匹配、checksum 链断裂或被截断的帧，
  逐条给出原因与字节偏移。
- **校验失败位置**：frame 索引、字节偏移、存储值与重新计算值。
- **checkpoint / 并发痕迹**：文件内出现多个 WAL header、checkpoint 序号
  推进、重复 salt、页面大小变化。
- **截断检测**：chunk 在 frame header 或页面数据中途被切断。

## 关键边界场景

- chunk 截断：header/页面不完整时记录异常并停止该段扫描，已确认的提交
  仍然有效。
- wal-index（`-shm`）缺失：审计只依赖 WAL 字节流，直接重放 checksum 链，
  不读取共享内存索引；报告仅提示 shm 是否存在。
- 页面大小变化：同一文件中出现新 WAL header 且页面大小不同时，按段
  （segment）独立解析并报告变化。
- 重复 salt：salt 对在多个段中重复出现时单独告警，提示无法仅凭 salt
  区分帧的归属。
- 并发 checkpoint：checkpoint 序号变化与嵌入式 WAL header 被标记为
  checkpoint/重置痕迹。
- 陈旧 salt 帧：salt 与当前 header 不符的帧被跳过且不计入 checksum 链，
  这与 SQLite 读取器的行为一致；真正的 checksum 不匹配才会使后续帧全部
  失效。

## 使用方法

```bash
# 文本报告
python -m wal_auditor /path/to/app.db-wal

# JSON 报告（便于自动化流水线）
python -m wal_auditor /path/to/app.db-wal --json

# 显式指定 wal-index 路径（可选，默认 <wal>-shm）
python -m wal_auditor /path/to/app.db-wal --shm /path/to/app.db-shm
```

作为库调用：

```python
from wal_auditor import audit_wal

report = audit_wal("app.db-wal")
for version in report.visible_versions:
    print(version.frame_index, version.db_size)
payload = report.to_dict()
```

## 模块结构

- `wal_auditor/format.py`：二进制常量、结构体与 checksum 算法。
- `wal_auditor/parser.py`：无解释的字节流解析，分段、分帧并记录异常。
- `wal_auditor/auditor.py`：可见性判定、快照重建、页面时间线与取证结论。
- `wal_auditor/report.py`：中文文本报告与 JSON 渲染。
- `wal_auditor/__main__.py`：命令行入口。
- `tests/`：合成 WAL 构造器与 unittest 套件，含真实 SQLite WAL 集成测试。

## 运行测试

```bash
python -m unittest
```

## 取证边界：页面证据不等于 SQL 记录

本工具重建的是 **WAL 页面版本**，不是 SQL 行，也不是完整的逻辑数据库。
请特别注意：

- 未提交帧里出现的页面镜像，可能包含被回滚、从未提交或属于崩溃前写入的
  数据，**不能**直接当作有效业务记录引用。
- checksum 失败或 checksum 链断裂之后的帧无法通过 SQLite 自身的完整性
  校验，只能作为“曾出现在磁盘上的字节”这一物理证据。
- 一个 B-tree 页面同时包含多行及未分配空间，单页镜像无法证明某一行在
  某个时间点已提交；行的可见性还取决于主库页面、回滚/提交状态与读取
  快照。
- 页面被覆盖只说明磁盘块内容变化，不等同于 SQL 层面的 `DELETE` 语义；
  空闲块、复用块中可能残留旧数据片段。
- 报告中的“可见版本”仅表示：按 WAL 规则，该 commit frame 能让读取器
  看到对应的页面集合；它不替代对主库文件和事务语义的联合分析。

结论应表述为“在某字节偏移的某 frame 中发现某页面镜像”，而不是
“数据库中存在/删除了某条 SQL 记录”。
