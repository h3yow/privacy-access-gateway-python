# 本地隐私数据访问与脱敏网关（Privacy Access Gateway）

在 FastAPI 服务模板上实现的多租户本地网关，提供：

1. **敏感字段识别与确定性脱敏**——同一租户内相同原值永远得到相同替换结果；规则缺失/不完整绝不静默放行。
2. **基于角色与属性（RBAC + ABAC）的字段级 / 行级访问控制**——越权访问被拒绝且拒绝原因可区分。
3. **策略版本化与历史结论可复现**——策略变更后，仍可按当时生效的策略版本重放历史判定。
4. **并发隔离、保留期管理与逐条容错**——跨租户不串读、不重复脱敏；到期按确定语义清除或不可逆脱敏；重复执行幂等；单条畸形记录不阻塞整批处理。
5. **批量接入（一批几十到几百条）**——逐条独立判定、独立落库，单条坏数据不带崩整批也不被悄悄放过；支持按 `batch_id` 安全重发（断点续跑、结果逐字一致）。
6. **兜底敏感识别**——租户规则未声明、但内容明显是敏感信息（自由文本里的邮箱/手机号/身份证形态，或一看就是证件/卡号的字段名）同样拦截，拒绝原因与既有的缺字段/类型错/取值不匹配可区分。
7. **可核验但不泄密的审计日志**——日志与持久层只保存指纹/令牌与判定依据，从不保存原始敏感值。

---

## 1. 快速开始

```bash
uv sync                       # 安装依赖
uv run python main.py         # 启动服务（默认 127.0.0.1:8000）
uv run pytest                 # 运行全部测试
```

环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PRIVACY_GATEWAY_MASTER_KEY` | 仅用于本地开发的固定值 | 派生各租户 HMAC 密钥的主密钥，**生产必须覆盖** |
| `PRIVACY_GATEWAY_DATABASE` | `gateway.db` | SQLite 数据文件路径 |

---

## 2. 识别与脱敏语义

### 2.1 敏感字段声明

每个租户开通时声明一组敏感字段规则（`sensitive_fields`），规则在策略版本内不可变：

```json
{
  "field_name": "phone",
  "strategy": "partial",
  "pattern": "1\\d{10}",
  "keep_prefix": 3,
  "keep_suffix": 4,
  "description": "phone number partial mask"
}
```

- `strategy`
  - `token`：整体替换为确定性不透明令牌，如 `TOK_PHONE_8F1A...`。
  - `partial`：保留指定头尾，中间打星号，如 `138****1234`；`keep_prefix` 与 `keep_suffix` 至少一个为正，且保证至少掩码 1 个字符（配置过大也不会回显原值）。
  - `hash`：输出 `sha256:<指纹>`。
- `pattern`：可选正则（`re.fullmatch` 语义）。原值不匹配时写入被拒绝。

### 2.2 确定性与稳定性

- 令牌与指纹均由 **HMAC-SHA256（每租户独立密钥）** 派生：
  `HMAC(tenant_key, "token" | "fingerprint", field_name + raw_value)`。
- 租户密钥由主密钥按 `HMAC(master_key, "tenant-key" + tenant_id)` 派生。
- 因此：**同租户 + 同字段 + 同原值 ⇒ 同令牌**；跨租户即使原值相同，令牌与指纹也完全不同。
- 网关不做任何模糊归一化：`13800001234`、`138-0000-1234`、`+8613800001234` 是三个不同原值，各自稳定映射到不同令牌（测试 `test_variants_are_distinguished_but_individually_stable` 覆盖）。

### 2.3 拒绝（不静默放行）

写入时所有已声明敏感字段必须存在且可通过校验，否则该条写入以 422 拒绝（单条接口抛错；批量接口体现在该条的 `reason` 上）：

| reason | 触发条件 |
| --- | --- |
| `sensitive_field_missing` | 负载缺少策略声明的敏感字段 |
| `value_pattern_mismatch` | 原值不匹配规则正则 |
| `non_string_value` | 敏感值不是字符串 |
| `invalid_payload` / `invalid_attributes` | 负载/属性为空或不是对象 |
| `undeclared_sensitive_content` | **兜底**：未声明字段的自由文本里出现明显敏感内容（见 2.6） |
| `undeclared_sensitive_field_name` | **兜底**：未声明字段名一看即敏感（见 2.6） |

### 2.5 去重与“整条内容幂等”

幂等单位是**整条业务内容**，不是单个敏感字段。系统对「规范化后的脱敏 payload + 业务 attributes」计算 `content_fingerprint`（HMAC，字段顺序无关），在租户级临界区内按它查重：

- 整条内容完全一致（包括非敏感字段与 attributes）⇒ 返回 `duplicate`（幂等，不新增记录、不重复脱敏；审计原因 `duplicate_write_idempotent`）。
- **仅仅共用了同一个敏感值、但业务内容不同**（例如同一个手机号对应两笔不同订单）⇒ 两条记录各自正常成立，不会被当成重复拒掉；确定性脱敏对该共用值仍给出一致的令牌/掩码。
- 旧版“指纹相同但 payload 不同即 `fingerprint_collision_conflict` 拒绝”的行为已移除：共享敏感值是合法的业务关联，不应误拒。

### 2.6 兜底敏感识别（规则没声明也要拦）

已声明规则永远优先；对策略**未声明**的顶层字段，网关再做两道保守的启发式扫描（实现见 `app/fallback.py`）：

1. **值形态扫描**（`undeclared_sensitive_content`）——在任意字符串字段（包括自由文本）里识别：
   - 邮箱：`local@domain.tld`；
   - 中国大陆手机号：带数字边界的 `1[3-9] + 9 位`（避免把 12 位订单号等更长数字串截断误报）；
   - 居民身份证形态：带边界的 17 位数字 + 数字/`X`。
2. **字段名扫描**（`undeclared_sensitive_field_name`）——对下划线/大小写归一化后，命中明确的证件/联系方式/银行卡命名（如 `id_card`、`id_card_no`、`passport_no`、`email_addr`、`mobile`、`bank_card_no`、`card_number` 等），即使取值本身不像也 fail-closed 拒绝，要求租户先显式声明规则。

边界与取舍（有意为之）：

- **只扫描 payload 的顶层标量字段**；不递归嵌套容器，也不扫描业务 `attributes`（attributes 按非敏感业务属性处理，供 ABAC 使用）。
- 普通业务键 `id`、`order_id` 这类**不**在命名词表里，避免误伤。
- 命中后不做自动脱敏放行，而是**拒绝并要求租户声明规则**——这样新发现的敏感类型由租户决定脱敏策略，不会以网关猜测的形态悄悄落库。
- 命中证据只含字段名、检测器名（`email`/`mobile_cn`/`id_card_cn`/字段名类别）和命中值的 **HMAC 指纹**；命中的原文片段只在内存中短暂使用，不返回、不入日志、不入库。
- 这两个 reason 与 `sensitive_field_missing` / `non_string_value` / `value_pattern_mismatch` 明确区分，上游可据此决定“补声明后重推”还是“修数据后重推”。

### 2.7 “原始值永不落盘、永不入日志”

- `records` 表只保存脱敏后的 payload、`{fingerprint, token}` 索引与 `content_fingerprint`；**原始值不在任何列中**。
- 审计表 `input_summary`/`evidence` 只保存字段名、长度、指纹、令牌、命中的规则/检测器描述。
- 批量幂等表保存的是请求内容的**单向请求指纹**（用于识别“同 batch_id 但内容变了”的重推），不含原值，且该指纹不写入日志。
- 测试 `test_raw_value_never_persisted`、`test_fallback_raw_match_never_persisted_or_logged`、`test_batch_contains_no_raw_values_in_persisted_results` 直接扫描 SQLite 文件字节、审计 JSON 与完整测试日志，断言原值不存在。

---

## 3. 访问控制策略模型

策略 `PolicyVersion` 由字段规则集 + 角色集 + 默认角色构成，带单调递增版本号与 `effective_at`。

### 3.1 字段级（RBAC）

每个角色对字段配置 `visible | masked | denied`：

- 敏感字段默认 **denied**（必须显式授权，最小权限）；非敏感字段默认 visible。
- 敏感字段即使 `visible` 也只能以存储的脱敏形态返回（标记为 `visible_as_masked`）——系统根本不持有原值。
- 读取记录时，若结果中包含任何 `denied` 字段 ⇒ 整请求 403 `field_access_denied`（不返回半成品）。

### 3.2 行级（ABAC）

角色可声明 `row_filters`，全部条件针对记录的业务 `attributes` 判定：

```json
{"region": "cn-north", "owner_id": "$owner_id"}
```

- 字面量直接相等比较；`"$xxx"` 表示从**请求主体属性** `subject.attrs` 中解析（属主型访问）。
- 任一条件不满足（含主体缺少对应属性）⇒ 行被拒绝，读单条返回 403 `row_filter_denied`，列表中过滤且计数。

### 3.3 可区分的拒绝原因

| reason | 含义 |
| --- | --- |
| `unknown_role` | 主体角色在当前策略版本中不存在 |
| `row_filter_denied` | ABAC 行过滤未通过（证据含每个属性的期望值/实际值） |
| `field_access_denied` | 行可见但请求触及 `denied` 字段 |
| `record_not_found` | 记录不存在（跨租户读取也得到此原因，避免存在性探测） |
| `record_anonymized` | 记录已被保留期不可逆匿名化 |

### 3.4 畸形策略（开通/变更时即拒绝，原因可区分）

| reason | 含义 |
| --- | --- |
| `invalid_strategy` | 未知脱敏策略 |
| `rule_incomplete` | partial 未配置保留长度 / 字段名为空等 |
| `malformed_pattern` | 正则无法编译 |
| `duplicate_field_rule` | 同一字段重复定义规则 |
| `invalid_field_visibility` | 字段可见性取值非法 |
| `malformed_role_fields` / `malformed_row_filters` | 角色结构不是对象 |
| `role_name_missing` / `duplicate_role` | 角色缺名 / 重复定义 |
| `default_role_undefined` | 默认角色未在角色集中定义 |
| `effective_at_out_of_order` | 新版本生效时间早于当前版本 |
| `tenant_already_exists` / `tenant_not_provisioned` | 租户状态冲突 |

---

## 4. 策略版本化与审计复现

- 每次开通生成版本 1；`POST /tenants/{t}/policy` 追加新版本并整体生效（不可修改旧版本）。
- 每条审计结论记录 `policy_version`、主体、输入摘要、判定证据与时间。
- `GET /tenants/{t}/audit/{id}/replay` 加载**当时的策略版本**重新判定：
  - `match`：复现结论与历史一致（含拒绝原因）；`mismatch`：不一致；`inconclusive`：记录已被物理清除等。
  - read 重放使用证据中保存的主体业务属性重新跑行/字段过滤；
  - write 重放比对历史指纹与现存记录索引；
  - retention 重放确认被清除记录确已不存在、被匿名化记录确无敏感索引。
- 典型验证：v1 下 auditor 对某字段被拒，策略升级 v2 放行后，重放 v1 审计仍得到 **deny / field_access_denied / version=1**。

---

## 5. 保留期规则

租户配置 `retention_days` 与 `retention_action`（`purge` | `anonymize`）。

- **边界语义**：记录在 `created_at + retention_days` 时刻**尚未**到期；严格晚于该时刻 1 秒即到期（`now > cutoff`，闭开区间，测试覆盖恰好在边界与边界 +1 秒）。
- `purge`：物理删除记录及去重索引；删除后读取得到 `record_not_found`。
- `anonymize`：保留非敏感业务字段；所有敏感字段替换为 `***RETENTION-ANONYMIZED***`，**清空指纹/令牌索引并置状态 `anonymized`**，使任何跨记录的身份关联不可逆；读取得到 403 `record_anonymized`。
- **幂等**：到期记录只处理一次，重复执行返回空列表、不产生额外副作用（仅有一条新的 retention 审计）。
- **逐条容错**：单条记录处理失败被捕获进 `errors:[{record_id, error}]`，其余记录继续处理；下次执行可补偿失败项（`test_one_bad_record_does_not_block_sweep`）。

---

## 6. 并发与多租户隔离

- 所有“查重 + 插入”在存储层全局可重入锁保护的临界区内完成；8 线程并发写相同原值 ⇒ 恰好 1 条记录、0 个错误。
- 所有 SQL 均带 `tenant_id` 条件；record_id 跨租户查询返回 `record_not_found`。
- 相同 20 个原值在两租户并发写入后，令牌集合互不相交，记录 id 集合互不相交。
- SQLite 启用 WAL；表结构以 `(tenant_id, ...)` 为主键的一部分。

---

## 6A. 批量接入（Batch Ingestion）

`POST /tenants/{t}/records/batch` 一次提交多条记录，body：

```json
{
  "batch_id": "upstream-20261005-0001",
  "items": [
    {"payload": {"phone": "13800001111", "note": "订单 A"},
     "attributes": {"order": "A"}, "client_item_id": "up-1001"},
    {"payload": {"phone": "bad-value", "note": "订单 B"},
     "client_item_id": "up-1002"}
  ]
}
```

- `items[*]`：每条含 `payload`（必填、非空对象）、可选 `attributes`、可选 `client_item_id`（上游自己的逐条对账键，结果中原样回显）。
- `batch_id`：**可选**幂等键。上游“超时后重推同一批”时应带上同一个 `batch_id`。

### 6A.1 逐条独立结果

每条记录独立判定、独立落库；一条数据有问题不会回滚或带崩整批，也不会被悄悄放过。HTTP 整体返回 200，逐条结果在 `items` 中按下标对齐：

```json
{
  "batch_id": "upstream-20261005-0001",
  "policy_version": 1,
  "summary": {"total": 2, "created": 1, "duplicate": 0, "rejected": 1},
  "items": [
    {"index": 0, "client_item_id": "up-1001", "status": "created",
     "reason": "classified_and_stored", "record_id": "...", "policy_version": 1},
    {"index": 1, "client_item_id": "up-1002", "status": "rejected",
     "reason": "value_pattern_mismatch",
     "message": "value of 'phone' does not match required pattern",
     "policy_version": 1}
  ]
}
```

- 条状态：`created`（成功落盘）/ `duplicate`（命中已有同内容记录，幂等）/ `rejected`（被拒绝，带可区分 `reason` 与可读 `message`）。
- 成功条给 `record_id`；拒绝条给 `reason`。原因码覆盖：`sensitive_field_missing`、`non_string_value`、`value_pattern_mismatch`、`undeclared_sensitive_content`、`undeclared_sensitive_field_name`，彼此可区分，方便上游按条对账和只重推失败项。
- **批量响应不含脱敏 payload 之外的任何原值**（敏感字段本就只有令牌/掩码）；被兜底拦截的原值片段也不出现在响应里。

### 6A.2 信封级错误（整批 422）

只有“批量信封本身不可解析/不一致”才在条目处理之前整体拒绝：

| reason | 触发条件 |
| --- | --- |
| `empty_batch` | `items` 为空或不是列表 |
| `malformed_batch_item` | 某个元素不是对象或缺 `payload` 键 |
| `invalid_payload` / `invalid_attributes` / `invalid_client_item_id` | 元素级结构类型错误 |
| `batch_too_large` | 超过单批上限 1000 条 |
| `invalid_batch_id` | `batch_id` 给了但为空串 |
| `batch_id_shape_mismatch` | 同一 `batch_id` 重推时条目数与首次不同 |
| `batch_id_content_mismatch` | 同 `batch_id` 重推时某条的请求内容（或 `client_item_id`）与首次不一致 |
| `batch_in_progress`（409） | 同一 `batch_id` 正由另一个请求在处理中 |

### 6A.3 安全重发、并发与崩溃恢复

- **结果逐字一致**：同一 `batch_id` 重推，返回的每条 `status`/`record_id`/`reason` 与首次完全相同（便于上游对账），既不新增记录，也不重复产生逐条审计/写入副作用；每次重推仅额外记录一条 `batch_idempotent_replay` 的批次级审计（只含计数）。
- **断点续跑**：若处理进程在批次中途崩溃（批次停留 `processing`、部分条目已存结果），重推会复用已完成条目的存档结果、只补跑未完成条目，最终仍然恰好成功一次。
- **并发**：同一 `batch_id` 的并发请求，一个处理、其余得到明确的 `409 batch_in_progress`（稍后重试即可取到最终结果）；不同 `batch_id` 的批量、并发单条写入、读取、保留期扫描可以同时进行，互不串租户、不丢记录、不出现读不到的中间态。
- **不带 `batch_id`**：每次都正常处理，不做批次级幂等登记；同内容重复提交会通过内容级去重表现为各条 `duplicate`。
- **体量**：单批上限 1000 条；常规规模（一次几百条）在本地 SQLite/WAL 下毫秒~百毫秒级完成，无超时级退化（测试 400 条 < 5s，实际约 0.1s/500 条）。

---

## 7. HTTP 接口

| 方法与路径 | 说明 |
| --- | --- |
| `POST /tenants/{t}/provision` | 开通租户（策略 v1 + 保留期配置） |
| `POST /tenants/{t}/policy` | 追加策略新版本 |
| `GET  /tenants/{t}/policy` | 列出全部历史策略版本 |
| `POST /tenants/{t}/records` | 单条写入（自动脱敏 / 内容级查重），body：`{payload, attributes}` |
| `POST /tenants/{t}/records/batch` | **批量写入**，body：`{batch_id?, items:[{payload, attributes?, client_item_id?}]}` |
| `GET  /tenants/{t}/records/{id}?role=` | 简单角色读取 |
| `POST /tenants/{t}/records/{id}/read` | 带主体属性读取，body：`{role, attrs}` |
| `POST /tenants/{t}/records/query` | 列表查询（行/字段过滤后返回） |
| `POST /tenants/{t}/retention/run?now=` | 执行保留期扫描（`now` 可注入以便测试边界） |
| `GET  /tenants/{t}/audit?limit=` | 审计列表（仅安全摘要） |
| `GET  /tenants/{t}/audit/{id}/replay` | 按当时策略版本复现历史判定 |

错误响应统一为：

```json
{"error": "AccessDeniedError", "reason": "row_filter_denied", "message": "..."}
```

---

## 8. 验证方法

```bash
uv run pytest -q          # 安静模式，仅汇总
uv run pytest -s          # 输出每个用例的中文场景行与安全决策日志
```

测试矩阵（97 个用例）：

| 文件 | 覆盖点 |
| --- | --- |
| `tests/test_masking.py` | 原值变体（大小写/格式/空白）、稳定性、跨租户令牌隔离、partial 边界、写后读一致性、原始值不落盘不入日志、各类写入拒绝原因 |
| `tests/test_fallback_detection.py` | **新增**：自由文本中的邮箱/手机号/身份证形态兜底拦截、长数字串不误报、证件/银行卡类字段名识别、字段名下划线变体、普通 `id` 不误伤、已声明字段不重复兜底、与既有 4 类拒绝原因区分、干净文本放行、兜底命中原值不落盘不入审计 |
| `tests/test_batch_ingestion.py` | **新增**：一批混合成功/重复/拒绝逐条可区分、5 类拒绝原因互不相同、逐条独立提交、信封级 6 种结构错误、批量上限、`batch_id` 重发逐字一致且不多存、形状/内容不一致的重发拒绝、共享敏感值不同内容各自成立、仅整条内容一致才算重复、批量与单条共享去重、批量链路原值不落盘不入日志、无 `batch_id` 行为 |
| `tests/test_batch_idempotency_concurrency.py` | **新增**：重发 record_id/状态一致、重发不重复副作用（仅多重放标记）、处理中途崩溃后断点续跑且恰好一次、8 线程并发同批只存一份、批量+单条+读取并发不丢记录/无中间态、两租户同批不串且指纹不交、批量与保留期扫描并发、400 条性能 |
| `tests/test_policies.py` | 5 类畸形字段规则、5 类畸形角色、未知角色、ABAC 区域/属主过滤、字段拒绝与行拒绝原因区分、默认角色、策略变更后历史结论重放 |
| `tests/test_concurrency.py` | 跨租户令牌/指纹隔离、跨租户读取失败、8 线程同值去重为 1 条、双租户 40 条并发写入不串扰 |
| `tests/test_retention.py` | 边界（恰好到期 vs +1 秒）、purge 幂等、anonymize 不可逆且幂等、保留期配置校验、单条失败不阻塞整批且可补偿 |
| `tests/test_audit_replay.py` | 旧版本字段拒绝重放、ABAC 主体属性重放、写入指纹一致性重放、被拒写入重放、匿名化销毁确认 |
| `tests/test_api.py` | HTTP 全生命周期、原因码区分、审计响应不含原值、策略变更 + 重放、保留期幂等、**批量端点逐条结果/重发一致/空信封拒绝/单条兜底** |

`tests/conftest.py` 会为每个用例打印一行 `[PASS]/[FAIL] 场景: …`（取测试文档首行，新增用例均为中文场景说明），可以直接看出覆盖了哪些场景与每个场景的结果；这些场景行只包含用例名/描述，不含任何敏感值。

测试日志示例（注意：只有指纹与判定依据，没有原值）：

```
[INFO] decision {"decision": "allow", "event": "write",
  "input_summary": {"fields": ["phone"],
                    "fingerprints": {"phone": "f530c20f..."}},
  "evidence": {"rules": {"phone": "rule:partial:phone"}},
  "reason": "classified_and_stored", "tenant_id": "t1"}
[WARNING] decision {"decision": "reject", "event": "write",
  "reason": "value_pattern_mismatch", ...}
```

---

## 9. 代码结构

```
app/
  config.py       主密钥/数据库配置
  errors.py       四类领域异常与稳定 reason 码
  models.py       规则/策略版本/记录/审计等领域类型
  masking.py      HMAC 密钥派生、指纹、确定性令牌、partial 掩码、内容/请求指纹
  classifier.py   字段规则校验与负载脱敏（拒绝原因在此产生）
  fallback.py     兜底识别：未声明字段的值形态扫描与敏感字段名扫描
  access.py       字段可见性与 ABAC 行过滤判定
  retention.py    到期边界判定（UTC、闭开区间）
  audit.py        审计条目构造
  logging_utils.py 仅输出安全摘要的日志
  storage.py      SQLite 表结构、版本化策略、去重索引、审计
  service.py      编排：开通/改策略/写/读/列表/保留期/重放
  schemas.py      Pydantic 入参模型
  api.py / deps.py FastAPI 路由、异常映射、依赖装配
main.py           应用入口
tests/            六个测试模块 + conftest 标准策略夹具
```
