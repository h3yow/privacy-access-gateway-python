# 本地隐私数据访问与脱敏网关（Privacy Access Gateway）

在 FastAPI 模板上实现的本地多租户隐私数据网关，提供：

1. **敏感字段识别与确定性脱敏**：同租户、同作用域内，相同原值（含不同写法的变体）
   在多次写入与读取中得到稳定一致的替换结果；未命中规则或规则不完整一律拒绝，
   拒绝原因可区分；原始敏感值不进入持久化数据或日志。
2. **RBAC + ABAC 访问控制**：角色对字段级（masked / hidden / redacted）与
   行级（属性条件）可见范围可配置；越权拒绝原因可区分；策略按版本快照化，
   历史审计结论可按当时生效的策略版本复现。
3. **并发与保留期管理**：所有读写带租户隔离；确定性令牌映射靠唯一约束幂等；
   保留期到期按 `delete` / `anonymize` 的确定语义处理，重复执行无额外副作用；
   单条畸形记录只拒绝自身，不阻塞整批请求。

## 目录结构

```
app/
  errors.py      # 错误类型与可区分 reason 码
  models.py      # 领域模型（规则/角色/行条件/保留期/策略快照）
  masking.py     # 变体归一化 + HMAC-SHA256 确定性令牌
  policy.py      # 策略严格校验、加载、版本化 PolicyStore
  store.py       # SQLite：已脱敏记录 + 指纹→令牌映射（线程安全）
  access.py      # 字段级 / 行级判定（fail-closed）
  retention.py   # 保留期扫描（删除/匿名化、幂等、逐条容错）
  audit.py       # 审计（仅摘要与判定依据、指纹），支持按版本复现
  service.py     # 应用服务：写入识别脱敏、读取鉴权、批量容错
  api.py         # FastAPI 路由
examples/
  policy.example.json
tests/           # pytest 测试套件（46 个用例）
main.py          # uvicorn 入口
```

## 快速开始

```bash
uv sync
uv run uvicorn main:app --reload
# 发布策略
curl -X POST localhost:8000/admin/policies \
  -H 'Content-Type: application/json' \
  --data @examples/policy.example.json
# 批量写入（识别 + 脱敏；部分成功）
curl -X POST localhost:8000/tenants/tenant-a/records \
  -H 'Content-Type: application/json' \
  -d '{"records":[{"id":"u1","data":{"phone":"138-0000-1234","email":"a@b.com","city":"BJ"}}]}'
# 按角色读取
curl localhost:8000/tenants/tenant-a/records/u1 -H 'X-Role: admin'
```

环境变量：`PAG_DB_DIR`（SQLite 文件目录，默认当前目录）、`PAG_SECRET`（HMAC 密钥，
生产必须覆盖默认值）。

## 识别与脱敏语义

- **规则形态**：每条敏感规则含 `field / pattern / normalizer / scope / mode`。
- **变体归一化**（识别前先归一化，保证变体判定一致）：
  - `digits`：仅保留数字。`138-0000-1234`、`138 0000 1234`、`13800001234`
    归一化后同为 `13800001234`。
  - `alnum`：小写并仅保留字母/数字/中日韩文字，用于邮箱大小写、分隔符变体。
  - `lower`：strip + 小写；`exact`：strip 原样。
- **形态识别**：归一化结果必须匹配规则 `pattern`，否则按
  `classification_incomplete_rule` 拒绝（不静默放行）。
- **确定性令牌**：`HMAC-SHA256(scopeKey, normalized)`，`scopeKey` 由
  `secret + tenant + scope` 派生，输出 `tok_<16hex>`。
  - 同租户同 scope 相同原值 ⇒ 永远同一令牌；不同租户 / scope ⇒ 不同令牌。
  - 令牌不可逆，且无法跨 scope 关联。
- **不落盘的内容**：
  - 记录表只存令牌/占位符；令牌映射表的键是 **HMAC 指纹 `fp_<...>`**，
    不是原值也不是归一化值（避免手机号等低熵值被字典反推）。
  - 审计只存长度/字符类别摘要 + 指纹 + 判定依据。
- **拒绝原因（写入）**：
  - `classification_no_rule`：疑似敏感字段（命名或值形态命中探测）但无规则。
  - `classification_incomplete_rule`：有规则但归一化后不满足形态，或规则不可用。
  - `classification_bad_record`：记录/字段结构或类型畸形。

## 策略模型

- `FieldMode`：`masked`（呈现令牌）、`hidden`（字段移除）、
  `redacted`（保留键名，值为固定 `********`）。
- **字段级（RBAC）**：角色 `fields` 白名单，未列出的字段 fail-closed 拒绝
  （单条读取抛 `access_field_denied`；列表读取过滤并在 `denied_field` 中记录）。
- **行级（ABAC）**：`row_conditions` 全部 AND，操作符 `eq / ne / in / notin`；
  属性优先取记录，其次取请求主体属性。不满足 ⇒ `access_row_denied`。
  - 列表读取时不满足行条件的记录被过滤，出现在 `denied_row`，不阻塞其他行。
- 其他原因：`access_unknown_role`（角色无策略）、`access_record_not_found`
  （不存在或跨租户，响应不区分存在性以防探测）。
- **版本化**：每次 `POST /admin/policies` 产生一个不可变 `PolicyBundle`，
  版本号不可重复（`policy_duplicate_version`）。读取可带 `?policy_version=`
  回到旧视角；每条审计记录带 `policy_version`，历史结论据此复现。
- **畸形策略**在发布时即被拒绝，原因包括 `policy_missing_version`、
  `policy_bad_enum`、`policy_bad_pattern`、`policy_bad_normalizer`、
  `policy_missing_field`、`policy_duplicate_rule`、`policy_bad_operator`、
  `policy_bad_retention_days` 等。

## 保留期规则

- 每租户一条 `RetentionPolicy`：`retention_days` + `action`。
- 截止时间 `cutoff = now - retention_days`；`created_at <= cutoff`
  （**边界含等号**）的记录到期。扫描可通过 API 传入 `now`（ISO8601）以复现。
- `delete`：物理删除整行；`anonymize`：保留行，敏感字段改写为匿名哨兵
  `__ANONYMIZED__`，非敏感字段保留，并切断该租户相关 scope 的指纹→令牌映射。
- **幂等**：删除的行不再存在；匿名化行带 `anonymized=1` 标记被候选查询排除；
  重复扫描返回空处理结果，无额外副作用。
- **容错**：单条删除/匿名化失败仅记录 `retention_record_failed`，
  其余记录继续处理；返回体按租户汇总 `deleted / anonymized / errors`。

## 并发模型

- SQLite 单连接 + 进程内 `RLock`；令牌映射 `(tenant, scope, fp)` 主键与
  `(tenant, scope, token)` 唯一约束保证并发 get-or-create 线性化，不产生重复脱敏。
- 所有记录查询都带 `tenant_id` 条件，主键为 `(tenant_id, id)`，跨租户不可见。
- 批量写入逐条处理，畸形记录归入 `rejected`（含 index / record_id / reason），
  不影响同批其他记录。

## 验证方法

```bash
uv run pytest -s          # -s 打印可核验的审计摘要与判定依据
```

测试覆盖（46 个用例）：

| 文件 | 覆盖点 |
| --- | --- |
| `tests/test_masking.py` | 手机/邮箱变体归一化、同租户同 scope 稳定性、跨租户/scope 隔离、不可逆 |
| `tests/test_policy.py` | 10 类畸形策略的可区分原因、版本重复、新旧快照并存 |
| `tests/test_classification.py` | 稳定替换、三类识别拒绝原因、原值不落盘不入日志、写入幂等 |
| `tests/test_access_control.py` | 三种字段模式、字段/行/角色拒绝原因、列表过滤、跨租户隔离、历史版本复现 |
| `tests/test_concurrency.py` | 50 条跨 5 租户并发写入无重复脱敏、令牌跨租户隔离、8 租户并发无串读 |
| `tests/test_retention.py` | 删除/匿名化、cutoff 含等号边界、重复扫描幂等、映射清除、单条失败不阻塞 |
| `tests/test_api.py` | HTTP 原因码与状态码映射、部分成功、审计端点无原值 |

审计日志示例（单测以 `-s` 打印，**不含原值**）：

```
[audit] req=req-test action=write decision=allow policy=v1 record=ok
  basis={'fields': {'phone': {'scope': 'phone', 'normalizer': 'digits', 'mode': 'masked'}}, 'inserted': True}
  summaries={'phone': {'len': 11, 'digits': 11, 'alpha': 0, 'fingerprint': 'fp_0c0ed6c86623043e'}}
```

- `summaries` 只有长度/字符类别统计；`fingerprint` 为带密钥 HMAC，
  可用于核验"两次输入是否同值"而无法还原原值。
- `basis` 记录命中的规则、字段模式、行条件数量、策略版本等判定依据。

## 设计边界

- 本地单进程部署模型；多进程/分布式部署需要把锁与 SQLite 换成外部实现
  （接口层已隔离在 `store.py` / `audit.py`）。
- 可疑字段探测是保守的命名/形态启发式，目的是"宁拒勿放"；新增敏感类型时
  应同步发布明确规则，而不是依赖探测长期放行。
