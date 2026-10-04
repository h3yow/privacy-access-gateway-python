# 本地隐私数据访问与脱敏网关（Privacy Access Gateway）

在 FastAPI 服务模板上实现的多租户本地网关，提供：

1. **敏感字段识别与确定性脱敏**——同一租户内相同原值永远得到相同替换结果；规则缺失/不完整绝不静默放行。
2. **批量接入（逐条独立判定/落库，安全可重发）**——上游一次推几十到几百条，单条畸形或不合规不带崩整批、不被静默放过；每条返回 `created / duplicate / rejected` 与彼此可区分的原因；超时重推同一批不多存、不重复副作用，结果与首次一致。
3. **接入兜底识别**——除租户声明的规则外，对规则未声明但内容/字段名明显敏感的数据（自由文本里的邮箱、手机号、证件号，证件类字段名等）同样拦截，原因码与“缺字段/取值不匹配/类型不对”明确区分。
4. **基于角色与属性（RBAC + ABAC）的字段级 / 行级访问控制**——越权访问被拒绝且拒绝原因可区分。
5. **策略版本化与历史结论可复现**——策略变更后，仍可按当时生效的策略版本重放历史判定。
6. **并发隔离、保留期管理与逐条容错**——跨租户不串读、不重复脱敏；到期按确定语义清除或不可逆脱敏；重复执行幂等；单条畸形记录不阻塞整批处理。
7. **可核验但不泄密的审计日志**——日志与持久层只保存指纹/令牌与判定依据，从不保存原始敏感值（批量与兜底识别链路同样如此）。

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

写入时所有已声明敏感字段必须存在且可通过校验，否则该条写入以 422 拒绝：

| reason | 触发条件 |
| --- | --- |
| `sensitive_field_missing` | 负载缺少策略声明的敏感字段 |
| `value_pattern_mismatch` | 原值不匹配规则正则 |
| `non_string_value` | 敏感值不是字符串 |
| `invalid_payload` | 负载为空或不是对象 |

### 2.4 兜底识别（未声明敏感数据的安全网）

声明规则只覆盖租户明确登记的字段。接入阶段还会扫描**所有未声明字段**（见 `app/fallback.py`）：

- **字段名疑似证件类**（`undeclared_sensitive_field_name`）：如 `id_card` / `id_no` / `cert_no` / `passport_no` /
  `identity_number` / `driver_license` / `national_id` / `ssn` / `身份证` / `护照` / `证件号` 等。
  字段名按词元切分后判定，因此 `order_id`、`item_id`、`product_id` 这类良性 **id 后缀**不会误伤。
- **自由文本内嵌敏感内容**（`undeclared_sensitive_content`）：扫描字符串值中的
  邮箱（`content.email`）、中国大陆手机号（`content.cn_mobile`，11 位且两侧非数字边界）、
  15/18 位身份证号（`content.cn_id_card`）。12 位以上连续数字不会在中间被误判成手机号。
- 命中证据只含 **字段名、检测器 id、命中位置/长度、HMAC 指纹**（指纹域与声明字段分隔，
  可核验但不泄漏）；匹配到的原文子串从不返回、入日志或落盘。
- 兜底命中**优先于**“缺声明字段”判定：即使同时缺 `phone`，自由文本里藏的邮箱仍以
  `undeclared_sensitive_content` 拒绝，避免真实风险被笼统原因掩盖。
- **边界**：兜底只针对未声明字段（已声明字段由其规则与正则负责，避免重复处理）；
  检测的是“明显敏感”的结构化模式（邮箱/手机/身份证 + 证件类名字），不做模糊语义理解，
  也不对非字符串值做内容解码——因此不能替代租户声明完整的字段规则，只作安全网。
- 兜底拒绝在单条与批量链路上行为一致，且整条链路（单条和批量）都不把原始敏感值写进
  持久化数据或日志。

### 2.5 “原始值永不落盘、永不入日志”

- `records` 表只保存脱敏后的 payload 与 `{fingerprint, token}` 索引；**原始值不在任何列中**。
- 审计表 `input_summary`/`evidence` 只保存字段名、长度、指纹、令牌、命中的规则描述。
- 测试 `test_raw_value_never_persisted` 直接扫描 SQLite 文件字节与审计 JSON，断言原值与完整证件号均不存在。

### 2.6 去重与幂等身份

- 记录的幂等身份是**整条业务内容**：对脱敏后的 payload 做规范化 JSON（sort_keys）+ sha256，
  存入 `records_hash_ledger`（`(tenant_id, content_hash)` 唯一）。
- 内容完全相同（敏感字段与非敏感业务字段都一致）⇒ 返回 `duplicate`（不新增记录、不重复脱敏；
  审计原因 `duplicate_write_idempotent`）。
- **仅共用同一敏感值、但业务内容不同的记录各自正常成立**：`dedup_index` 以
  `(tenant_id, field, fingerprint, record_id)` 为键允许同一指纹被多条记录共享，
  不再因“指纹相同但 payload 不同”而报 `fingerprint_collision_conflict`。
- 确定性脱敏保证：批内重复敏感原值、与库里已有记录撞同一敏感值，得到的令牌/指纹始终一致。
- 保留期 purge / anonymize 会同步释放内容哈希台账与指纹索引；旧库启动时自动平滑迁移。

---

## 2A. 批量接入怎么用

`POST /tenants/{t}/records/batch`，请求体：

```json
{
  "records": [
    {"item_id": "upstream-correlation-id-1",
     "payload": {"phone": "13800001234", "id_card": "11010119900101001X", "note": "n1"},
     "attributes": {"region": "cn-north"}},
    {"item_id": "upstream-correlation-id-2",
     "payload": {"phone": "13700001111", "id_card": "320101199505050011"}}
  ]
}
```

- `item_id` 是上游自己的对账键，会原样回到每条结果里（可省略）；条目顺序也通过 `index` 保留。
- **每条独立判定、独立落库**：批量调用本身只要信封合法就返回 200，逐条结果在 `results` 内。
  某条格式有问题/不合规不会带崩整批，也不会被悄悄放过。
- 每条结果的 `status`：
  - `created`：新落盘，带 `record_id`；
  - `duplicate`：命中已有同内容记录（幂等），返回**同一个** `record_id`；
  - `rejected`：带彼此可区分的 `reason`（`invalid_payload` / `sensitive_field_missing` /
    `value_pattern_mismatch` / `non_string_value` / `undeclared_sensitive_content` /
    `undeclared_sensitive_field_name` / `internal_item_error`）与安全的 `message`。
- 汇总计数：`batch_size / created / duplicate / rejected`，方便上游按条对账与按条重推。
- **信封级错误**（不是某一条的问题）才整体 422：`invalid_batch`（`records` 不是非空列表）、
  `batch_too_large`（超过 1000 条）。
- **安全重发**：上游超时后原样重推同一批，去重以整条内容哈希为身份——首次已落库的条目第二次
  全部返回 `duplicate` 且 record id 与首次一致，被拒绝条目原因保持一致，库里不多存任何记录、
  不产生重复副作用。并发重推（多线程/多请求同时推同一批）同样只落一份。

响应示例：

```json
{
  "tenant_id": "acme", "policy_version": 1, "batch_size": 2,
  "created": 1, "duplicate": 0, "rejected": 1,
  "results": [
    {"index": 0, "item_id": "upstream-correlation-id-1",
     "status": "created", "record_id": "477c...", "policy_version": 1},
    {"index": 1, "item_id": "upstream-correlation-id-2",
     "status": "rejected", "reason": "undeclared_sensitive_content",
     "message": "payload contains sensitive data not declared by policy"}
  ]
}
```

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

- 所有“查重 + 插入”在存储层全局可重入锁保护的临界区内完成，内容哈希台账 `(tenant_id, content_hash)` 唯一；
  多线程/多请求并发写同一内容 ⇒ 恰好 1 条记录、0 个错误；并发重推同一批 200 条 ⇒ 库里恰好 200 条，
  每次重推得到相同 record id 集合。
- 仅共用敏感值、业务内容不同的并发写入互不阻塞（批量线程与单条写入线程同时跑，3 条不同内容各自成立、
  指纹一致）。
- 批量接入与并发单条写入、读取、保留期清理同时进行时：读取只看到已提交的完整行，新批记录无丢失，
  到期旧记录被清除且不误伤新记录（测试 `test_batch_concurrent_with_reads_and_retention_loses_nothing`）。
- 所有 SQL 均带 `tenant_id` 条件；record_id 跨租户查询返回 `record_not_found`。
- 相同 20 个原值在两租户并发写入后，令牌集合互不相交，记录 id 集合互不相交。
- SQLite 启用 WAL；表结构以 `(tenant_id, ...)` 为主键的一部分。常规规模（一次数百条）本地批量写入
  约为 10 条/毫秒量级，无超时级退化（500 条批量 + 重发去重见
  `test_batch_hundreds_of_records_completes_without_timeout`）。

---

## 7. HTTP 接口

| 方法与路径 | 说明 |
| --- | --- |
| `POST /tenants/{t}/provision` | 开通租户（策略 v1 + 保留期配置） |
| `POST /tenants/{t}/policy` | 追加策略新版本 |
| `GET  /tenants/{t}/policy` | 列出全部历史策略版本 |
| `POST /tenants/{t}/records` | 写入（自动脱敏 / 查重），body：`{payload, attributes}` |
| `POST /tenants/{t}/records/batch` | **批量写入**，body：`{records: [{item_id?, payload, attributes?}, ...]}`，逐条返回结果 |
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
uv run pytest -q          # 已开启 live 日志：可看到每个场景的用例名与结果
uv run pytest             # 同上去掉 -q，场景/判定日志更完整
```

测试运行时每个用例前后会打印（仅用例名与结果，不含任何负载或敏感值）：

```
INFO [privacy_gateway.test] SCENARIO START | file=test_batch.py | case=test_batch_resend_is_idempotent_with_identical_results
INFO [privacy_gateway.test] SCENARIO RESULT | case=test_batch_resend_is_idempotent_with_identical_results | outcome=passed | duration_ms=10
```

测试矩阵（100 个用例）：

| 文件 | 覆盖点 |
| --- | --- |
| `tests/test_masking.py` | 原值变体（大小写/格式/空白）、稳定性、跨租户令牌隔离、partial 边界、写后读一致性、原始值不落盘不入日志、各类写入拒绝原因 |
| `tests/test_policies.py` | 5 类畸形字段规则、5 类畸形角色、未知角色、ABAC 区域/属主过滤、字段拒绝与行拒绝原因区分、默认角色、策略变更后历史结论重放 |
| `tests/test_concurrency.py` | 跨租户令牌/指纹隔离、跨租户读取失败、8 线程同值去重为 1 条、双租户 40 条并发写入不串扰 |
| `tests/test_retention.py` | 边界（恰好到期 vs +1 秒）、purge 幂等、anonymize 不可逆且幂等、保留期配置校验、单条失败不阻塞整批且可补偿 |
| `tests/test_audit_replay.py` | 旧版本字段拒绝重放、ABAC 主体属性重放、写入指纹一致性重放、被拒写入重放、匿名化销毁确认 |
| `tests/test_api.py` | HTTP 全生命周期、原因码区分、审计响应不含原值、策略变更 + 重放、保留期幂等 |
| `tests/test_batch.py` | **批量混合结果逐条可见、5 类彼此可区分原因、坏条不带崩整批、批内重复去重、超时重发幂等（record id/原因一致、不多存）、共用敏感值但内容不同各自成立、原值不入审计、信封错误、500 条体量与性能** |
| `tests/test_fallback_detection.py` | **证件类字段名识别（含中文）、`order_id` 等良性 id 不误伤、自由文本邮箱/手机/身份证内嵌识别、数字边界、已声明字段不重扫、命中确定性排序与指纹、单条/批量拒绝原因区分、兜底命中优先于缺字段、原值不进 SQLite 字节与审计** |
| `tests/test_batch_concurrency.py` | **4 线程并发重推同批 200 条恰好落 200 条且结果一致、批量与单写共用敏感值不碰撞、批量与读取/保留期清理并发无丢记录/无串租户** |
| `tests/test_batch_api.py` | **批量 HTTP 混合结果与重发、兜底 HTTP 拒绝且响应/审计不含原值、信封级 422** |

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
  errors.py       四类领域异常与稳定 reason 码（可附带安全的 summary/evidence）
  models.py       规则/策略版本/记录/审计等领域类型（StoredRecord 含 content_hash）
  masking.py      HMAC 密钥派生、指纹、确定性令牌、partial 掩码
  classifier.py   字段规则校验与负载脱敏（声明字段的拒绝原因在此产生）
  fallback.py     兜底识别：证件类字段名 + 自由文本内嵌邮箱/手机/身份证（只产出安全证据）
  access.py       字段可见性与 ABAC 行过滤判定
  retention.py    到期边界判定（UTC、闭开区间）
  audit.py        审计条目构造
  logging_utils.py 仅输出安全摘要的日志
  storage.py      SQLite 表结构、版本化策略、内容哈希台账/共享指纹索引、平滑迁移、审计
  service.py      编排：开通/改策略/单条写/批量写/读/列表/保留期/重放
  schemas.py      Pydantic 入参模型（含批量信封）
  api.py / deps.py FastAPI 路由（含 /records/batch）、异常映射、依赖装配
main.py           应用入口
tests/            十个测试模块 + conftest 标准策略夹具与场景日志钩子
```

### 8.1 本地手工验证新行为

```bash
uv run python main.py            # 起服务
# 1) 开通（只声明 phone 一个敏感字段）
curl -s -X POST localhost:8000/tenants/demo/provision -H 'Content-Type: application/json' -d '{
  "tenant_id":"demo",
  "sensitive_fields":[{"field_name":"phone","strategy":"partial","pattern":"1\\d{10}","keep_prefix":3,"keep_suffix":4}],
  "roles":[{"name":"admin","fields":{"phone":"masked"}}],"default_role":"admin",
  "retention_days":30,"retention_action":"purge"}'
# 2) 批量推：好条 / 坏格式条 / 自由文本藏邮箱条 / 证件名字段条 混合
curl -s -X POST localhost:8000/tenants/demo/records/batch -H 'Content-Type: application/json' -d '{
 "records":[
  {"item_id":"ok","payload":{"phone":"13800001234","note":"a"}},
  {"item_id":"bad","payload":{"phone":"nope"}},
  {"item_id":"hidden","payload":{"phone":"13800001234","note":"ping a@b.com"}},
  {"item_id":"idname","payload":{"passport_no":"G12345678"}}
 ]}'
# 3) 原样再推一遍：ok 变 duplicate 且 record_id 不变，拒绝原因不变
# 4) 查审计：只有指纹与判定依据
curl -s localhost:8000/tenants/demo/audit | python -m json.tool
```

预期：第 2 步 `created=1, rejected=3`，三条拒绝原因分别是
`value_pattern_mismatch`、`undeclared_sensitive_content`、`undeclared_sensitive_field_name`；
审计与终端日志中都搜不到 `13800001234`、`a@b.com`、`G12345678`。
