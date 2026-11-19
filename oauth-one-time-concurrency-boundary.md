# 一次性授权凭据在并发兑换下的保证边界 —— fosite 源码分析

- 分析对象：本仓库（`github.com/ory/fosite`，基线提交 `a5f0b09`，`go 1.22 / toolchain go1.23.1`）
- 分析范围：授权码（authorization code）的签发、存储、令牌兑换全链路；对照设备码（RFC 8628）、刷新令牌旋转、RFC 7523 JTI、PAR、PKCE 的同类模式
- 方法：静态源码走查 + 可执行并发 PoC（已运行并清理，结论与复现步骤见 §6）
- 结论先行：**当前实现对"串行重放"有完整防护，但对"并发兑换同一授权码"不具备一次性保证。** 在窗口内并发的 N 个兑换可以全部成功并各自签发独立令牌，构成真正的凭据双花。根因是"读取激活态 → 失效"是两个独立存储调用而非原子 compare-and-swap，且决定性读发生在事务之外。

---

## 1. 一次性语义由哪些状态转换共同保证

### 1.1 凭据生命周期与状态位

授权码本身是不透明随机串（HMAC-SHA512/256，≥128 bit 熵，`token/hmac/hmacsha.go:47-85`）。存储中只保存其 **signature**（`AuthorizeCodeSignature` 取 token 的 HMAC 段，`handler/oauth2/strategy_hmacsha_plain.go:39-41`），原始 code 不落库。

内存参考实现用一个布尔位表达一次性状态（`storage/memory.go:99-102`）：

```go
type StoreAuthorizeCode struct {
    active bool
    fosite.Requester
}
```

完整生命周期由三次状态转换构成：

| 阶段 | 转换 | 代码位置 |
|---|---|---|
| 签发 | （无记录）→ `active=true` | `handler/oauth2/flow_authorize_code_auth.go:79-98` → `MemoryStore.CreateAuthorizeCodeSession`（`storage/memory.go:249-255`） |
| 兑换 | `active=true` → `active=false` | `handler/oauth2/flow_authorize_code_token.go:167` → `MemoryStore.InvalidateAuthorizeCodeSession`（`storage/memory.go:272-283`） |
| 重放检测 | 读到 `active=false` → 返回 `ErrInvalidatedAuthorizeCode` | `storage/memory.go:257-270`，由 `flow_authorize_code_token.go:33-52` 处理 |

注意失效是**软删除（置位）而非物理删除**：记录保留，专门用于让后续重放能识别"已使用"并触发令牌撤销。`DeleteAuthorizeCodeSession` 已不在任何生产代码中出现（仅存于生成的旧 mock `internal/oauth2_explicit_storage.go:48-56`），说明该接口已演化为"置失效"模型。

### 1.2 兑换两阶段的编排

令牌端点被 fosite 拆成两个独立阶段，由不同入口驱动：

1. **校验/装载阶段** `HandleTokenEndpointRequest`（`handler/oauth2/flow_authorize_code_token.go:21-104`），经 `Fosite.NewAccessRequest` 调用（`access_request_handler.go:95`）。
2. **签发阶段** `PopulateTokenEndpointResponse`（同文件 `:119-191`），经 `Fosite.NewAccessResponse` 调用（`access_response_writer.go:27-35`）。

两阶段之间没有任何锁或事务把它们绑定为一次原子操作。

### 1.3 串行重放路径（工作正常的部分）

当一个 code 被先后（非重叠）使用两次时，防护是完整的：

1. 第一次兑换在签发阶段把 `active` 置为 `false`（`flow_authorize_code_token.go:167`）。
2. 第二次兑换在**校验阶段**的 `GetAuthorizeCodeSession` 即收到 `ErrInvalidatedAuthorizeCode`（`storage/memory.go:265-267`）。
3. 处理器执行 RFC 6819 §5.2.2.3 风格的补救：按 request ID 撤销该授权已签发的 access token 与 refresh token（`flow_authorize_code_token.go:40-52`），然后返回 `invalid_grant`。

集成测试 `integration/authorize_code_grant_test.go:150-183`（`TestAuthorizeCodeFlowDupeCode`）验证了这条路径：二次兑换报错，且先前令牌在受保护资源处变为 401。**但该测试是串行的，不覆盖并发。**

---

## 2. 并发请求的成功路径与拒绝路径对比

### 2.1 关键事实：决定性读在事务之外

签发阶段的事务边界（`flow_authorize_code_token.go:155-188`）：

```go
ctx, err = storage.MaybeBeginTx(ctx, c.CoreStorage)   // :155
...
if err = c.CoreStorage.InvalidateAuthorizeCodeSession(ctx, signature); err != nil { ... } // :167
else if err = c.CoreStorage.CreateAccessTokenSession(...); err != nil { ... }              // :169
else if refreshSignature != "" {
    if err = c.CoreStorage.CreateRefreshTokenSession(...); err != nil { ... }             // :172
}
...
if err = storage.MaybeCommitTx(ctx, c.CoreStorage); err != nil { ... }                    // :186
```

而判断"这个 code 是否仍可兑换"的两次读都在 `MaybeBeginTx` **之前**：

- 校验阶段：`flow_authorize_code_token.go:32`
- 签发阶段开头又读一次：`flow_authorize_code_token.go:126`

`MaybeBeginTx` 仅在存储实现 `storage.Transactional` 时才真正开事务（`storage/transactional.go:28-36`）；参考实现 `MemoryStore` **没有实现 `Transactional`**（全文件无 `BeginTX/Commit/Rollback`），因此在 MemoryStore 下这三步连事务都没有，只是三次独立加锁的 map 操作。

### 2.2 TOCTOU 窗口

`InvalidateAuthorizeCodeSession` 的接口契约（`handler/oauth2/storage.go:30-33`）**没有任何前置条件**——它不要求行当前为 active，也不返回"已失效"冲突。内存实现无条件置位（`storage/memory.go:272-283`）：

```go
rel, ok := s.AuthorizeCodes[code]
if !ok { return fosite.ErrNotFound }
rel.active = false
s.AuthorizeCodes[code] = rel
return nil
```

于是两个并发兑换的交错为：

```
请求 A: Get(active=true)  ────────────────► Invalidate(置 false) → CreateAT/RT → 成功
请求 B: Get(active=true)  ─────► Invalidate(再次置 false，无错) → CreateAT/RT → 成功
                  ▲ B 的读发生在 A 的 Invalidate 之前，两者都基于同一"激活"快照继续
```

`MemoryStore` 的互斥锁（`authorizeCodesMutex`）只保证**单次 map 访问**的内存安全，不保证"读-改-写"的原子性；RWMutex 反而让多个读可以同时持有读锁观察到 `active=true`。锁消除了 data race，但没有消除 TOCTOU。

### 2.3 三种可能的并发结局

对同一 code 发起 N 个并发兑换，实际观察到三类结果（PoC 中均出现）：

| 结局 | 触发条件 | 路径 | 客户端可见错误 |
|---|---|---|---|
| **全部/多个成功（双花）** | 所有请求的两次 `Get` 都在任一 `Invalidate` 提交前观察到 `active=true` | 两条请求各自走完 `:167-188`，各自 `GenerateAccessToken` 产生独立签名并写入独立会话 | 无，均返回有效令牌 |
| 校验阶段拒绝 | 读发生在首个 Invalidate 之后 | `:33` 收到 `ErrInvalidatedAuthorizeCode` → 撤销关联令牌 → `:52` | `invalid_grant`（"already been used"） |
| 签发阶段拒绝 | 校验阶段通过，但 `:126` 的第二次读发生在首个 Invalidate 之后 | `:127-128` 任意错误直接包成 server error | `server_error`（注意：不是 `invalid_grant`） |

PoC 的确定性屏障实验（10 并发，强制 10 个首次读全部完成后才放行 Invalidate）连续 10 轮结果为 **7–10 个成功、0–3 个拒绝**；在最严格同步下出现过 `success=10 rejected=0`。这证明双花不是理论竞态，而是窗口内的必然结果，窗口大小只决定命中概率。

### 2.4 与刷新令牌旋转的对比

刷新令牌流程对并发冲突有**显式的存储级冲突约定**：`flow_refresh.go:217-222` 识别 `fosite.ErrSerializationFailure`（`errors.go:30-36`，HTTP 409，"another request is competing for the same resource"），并把它转译为可重试的 `invalid_request`。授权码流程**完全没有对应的冲突处理分支**——`flow_authorize_code_token.go` 全文不引用 `ErrSerializationFailure`，其 Invalidate 也没有条件语义可以产生该错误。这说明框架作者已意识到并发序列化冲突问题，但该治理没有覆盖授权码兑换。

---

## 3. 存储原子性、过期时间、重试与错误恢复之间的约束

### 3.1 原子性约束

1. **接口层面缺失 CAS 原语。** `AuthorizeCodeStorage`（`handler/oauth2/storage.go:19-34`）只有 Create/Get/无条件 Invalidate，没有"仅当 active 时才失效，否则报冲突"的方法。一次性保证被完全下放给存储实现，而接口没有表达这一要求。
2. **事务只包住写，不包住决定性读。** 即便存储实现了 `Transactional`，`GetAuthorizeCodeSession`（`:32`、`:126`）也在 `MaybeBeginTx` 之外。SQL 后端若默认隔离级别为 READ COMMITTED，两个事务可以同时读到 active 行，再各自 UPDATE——除非 UPDATE 带条件谓词或行锁。
3. **事务回滚的语义缺口。** `:159-165` 的 defer 保证 Invalidate/CreateAT/CreateRT 三者同成同败（有 mock 测试覆盖，`flow_authorize_code_token_test.go:511-644`），但回滚后 code 回到 active，客户端若重试会再次进入同一竞态。回滚维持了"未成功签发则 code 仍可用"的合理性，却没有限制重试的并发度。
4. **MemoryStore 是反模式示范。** 它不实现 `Transactional`，无条件 Invalidate，且直接存储/返回请求指针（`storage/memory.go:253, 269`）。生产 SQL 存储每次反序列化独立行，行为更接近"快照读"，TOCTOU 窗口在网络延迟下只会更大。

### 3.2 过期时间约束

- 授权码过期时间在签发时写入会话：`flow_authorize_code_auth.go:85`，默认 15 分钟（`config_default.go:384-390`）。
- 过期判定是**纯应用层、基于会话内时间戳**：`strategy_hmacsha_plain.go:97-108`，在 `Get` 成功之后执行（`flow_authorize_code_token.go:61`）。存储层不参与过期，也没有后台清理。
- 约束含义：**过期缩短了双花窗口的时间上限（≤ 码寿命），但不关闭窗口。** 在码有效期内的并发攻击不受任何限制。反过来，因为失效是软置位且记录不删除，过期与"已使用"是两个正交状态——一个已过期但未使用的码，与一个已使用的码，拒绝路径不同（前者 `ErrTokenExpired` → `invalid_grant`，后者 `ErrInvalidatedAuthorizeCode` → 带撤销的 `invalid_grant`）。

### 3.3 重试与错误恢复约束

1. 校验阶段的可重试性：网络/5xx 错误在 `:55-57` 映射为 `server_error`，code 尚未失效，客户端安全重试——但这正是并发窗口的来源：多个"安全重试"可以同时在途。
2. 签发阶段失败后的状态：事务回滚则全部写撤销，code 保持 active（可重试）；提交后响应丢失（客户端没收到令牌但服务端已提交）则 code 已 inactive，客户端重试只能得到 `invalid_grant` 且**无法取回已签发的令牌**——这是规范允许的可用性代价，但当前实现没有给出区分"冲突可重试"与"永久失败"的信号（对比刷新流程的 409 处理）。
3. 重放补救的非原子性：`:44-51` 的两次 Revoke 不在事务中，且任一失败只追加 hint 不阻断返回。并发双花场景下补救逻辑本身可能基于已被另一个请求改写的 request ID 映射执行。
4. 第二阶段重复读（`:126`）使得错误分类依赖调度时序：同样的并发输入，客户端可能收到 `invalid_grant` 或 `server_error`，行为不确定。

---

## 4. 规范允许的重复结果 vs. 真正的双花缺陷

### 4.1 规范允许、不构成漏洞的重复结果

依据 RFC 6749 §4.1.2、§4.1.3 与 RFC 6819：

1. **对已使用码的串行重放返回 `invalid_grant` 并撤销关联令牌**（`flow_authorize_code_token.go:40-52`）——这正是规范要求的行为。
2. **同一码的两次请求，先到者成功、后到者失败**——一次性语义的预期表现。
3. **服务端成功提交但客户端未收到响应后的重试失败**——规范未要求授权服务器保证响应投递；码已消费，拒绝重试符合 §4.1.3。
4. **过期码被拒绝**（`ErrTokenExpired`）——§4.1.2 要求码短期有效。
5. **并发下败者收到 409/可重试错误**（若实现了冲突检测）——RFC 6749 §5.2 与 HTTP 语义允许，刷新流程已采用此模式。

### 4.2 真正的安全缺陷：双花

以下结果超出规范允许范围，本仓库当前实现可产生：

- **同一授权码的两个或多个在途并发兑换全部成功**，每个响应包含不同的 access token（独立签名、独立会话行）。这违反 RFC 6749 §4.1.3 授权码"单值、短期、一次性"的核心假设，等价于把一次授权决策放大成 N 份独立凭据。
- 危害面：攻击者（或存在 bug 的客户端）在截获/触发兑换后并发重放，可获得多个并行有效令牌；`client_credentials` 等场景外的配额、审计、单次授权绑定全部被绕过。由于 PoC 显示 MemoryStore 下最多可达 10/10 全成功，窗口命中率在高并发或慢存储下不可忽略。
- 判定标准（用于区分）：**如果 N 个请求的时间区间互不重叠，至多 1 个成功 → 规范内；若存在重叠区间且 >1 个请求返回了可用 access token → 双花缺陷。**

### 4.3 同类一次性凭据的相同缺陷面

同一"事务外读 + 无条件失效"模式还存在于：

- **设备码兑换** `handler/rfc8628/token_handler.go`：读在 `:158`（Handle 阶段）与 `:66`（Populate 阶段），事务始于 `:96`，`InvalidateDeviceCodeSession` 在 `:108`，同样无条件。
- **RFC 7523 JTI 防重放** `handler/rfc7523/handler.go`：`IsJWTUsed`（`:290`，Handle 阶段）与 `MarkJWTUsedForTime`（`:96`，同阶段但两次独立存储调用）分离，无事务包裹；内存实现靠 map 存在性判断（`storage/memory.go:219-247`），check-then-mark 非原子。
- **PAR 一次性消费** `authorize_request_handler.go:303-316`：`GetPARSession` 后 `DeletePARSession`，无事务、无条件删除。
- **PKCE 会话** `handler/pkce/handler.go:135-151`：Get 后立即 Delete，发生在授权码事务之外，且 Delete 早于码失效。

这些位置的修复方向一致（见 §5），但本报告的可验证结论仅对授权码兑换给出了 PoC 证据，其余列为同源风险。

---

## 5. 最小修复建议（附源码证据与取舍）

### 5.1 首选：存储层条件失效（compare-and-swap），框架补冲突映射

**改动点 A —— 存储契约增加条件语义。** 二选一：

- 方案 A1（改动最小，向后兼容）：在文档与实现中要求 `InvalidateAuthorizeCodeSession` 具备 CAS 语义——仅当行存在且 active 时置位并返回 nil；行已 inactive 时返回 `fosite.ErrSerializationFailure`（或 `ErrNotFound`，由处理器归一化）。内存实现改为带 active 判定的条件翻转。
- 方案 A2（接口更显式）：新增 `InvalidateAuthorizeCodeSessionIfActive(ctx, signature) (bool, error)`，SQL 后端落地为单条条件 UPDATE：
  ```sql
  UPDATE authorize_codes SET active = false
  WHERE signature = $1 AND active = true;
  -- 影响行数 = 0 即冲突
  ```
  单条 UPDATE 在主流数据库（PostgreSQL/MySQL/SQLite）内置行锁，天然原子，不依赖隔离级别。

**改动点 B —— 处理器把冲突当作败者信号。** 在 `flow_authorize_code_token.go:167` 处，把冲突错误映射为 `invalid_grant`（或参照 `flow_refresh.go:217-222` 映射为带"请重试"提示的 409），并确保 defer 回滚已创建的令牌行。由于 Invalidate 是事务内第一步，败者回滚后不会留下任何令牌。

**PoC 已验证此方案有效**（见 §6.3）：在同一屏障压力下，CAS 存储把结果从 7–10 成功变为**恒定恰好 1 成功、9 拒绝、仅 1 个 access token 会话**，`-race` 干净，连续 5 轮稳定。

### 5.2 备选：把决定性读移入事务并升级为行锁

将 `:126` 的读与 `:167` 的失效放进同一事务，SQL 后端使用 `SELECT ... FOR UPDATE`：

```go
ctx, _ = storage.MaybeBeginTx(ctx, c.CoreStorage)          // 提前到读之前
ar, err := c.CoreStorage.GetAuthorizeCodeSessionForUpdate(...) // 行锁
// 校验 ...
c.CoreStorage.InvalidateAuthorizeCodeSession(...)          // 持锁翻转
```

代价：需要扩展存储接口、要求所有后端支持行锁、持锁时间覆盖令牌生成；且对不实现 `Transactional` 的 MemoryStore 仍需补 mutex 级 CAS。相比之下 5.1 的单条条件 UPDATE 更轻。

### 5.3 不推荐的"修复"

- 仅在处理器里加进程内 mutex：多实例部署下无效，且 fosite 作为库不应假定单进程。
- 仅缩短码寿命：只缩小窗口，不消除缺陷（§3.2）。
- 把 Get 改成读后立即 Invalidate 再校验：校验失败时需要补偿恢复，语义复杂且仍需条件写保证原子。

### 5.4 同源问题的统一处理

建议以同一 CAS 原语收敛 §4.3 列出的设备码、JTI、PAR、PKCE；其中刷新令牌已有 `ErrSerializationFailure` 约定，可作为统一错误模型的基准。

---

## 6. 可重复验收标准

### 6.1 验收判据（修复必须全部满足）

1. **并发单花**：对同一有效授权码发起 N≥10 个完全重叠的兑换请求，成功（返回非空 access_token）数**恒等于 1**，其余全部收到明确错误（`invalid_grant` 或 409 可重试），重复 20 轮无波动。
2. **存储单份**：压测后该 request ID 下 access token 会话数恒为 1、refresh token 会话数 ≤1。
3. **串行兼容**：现有 `integration/authorize_code_grant_test.go` 的 `TestAuthorizeCodeFlowDupeCode` 行为不变（二次串行兑换 `invalid_grant` + 关联令牌被撤销）。
4. **事务语义**：败者路径不残留任何令牌行；`flow_authorize_code_token_test.go:444-680` 现有事务回滚 mock 测试全部通过。
5. **无 data race**：全部并发用例在 `go test -race` 下无 WARNING。
6. **错误确定性**：并发败者不得返回裸 `server_error`；应返回可区分"冲突/已使用"的确定错误码。
7. **回归**：`go test ./...` 全量通过；设备码、刷新、PKCE 包不受影响。

### 6.2 复现当前缺陷的步骤（PoC 设计，可重新落地）

测试环境：go1.24（`/srv/fb2/mei8085/toolchains/go1.24`），`GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off`，模块缓存已就绪。

1. 在仓库内新建临时测试包（如 `tmp_concurrency_poc/`，验收后删除）。
2. 用 `compose.Compose` + `OAuth2AuthorizeExplicitFactory` + HMAC 策略（需设置 32 字节 `GlobalSecret`）装配 provider，存储用包装过的 `storage.MemoryStore`。
3. 包装器实现两个屏障：① 每个 worker 的**首次** `GetAuthorizeCodeSession` 在屏障处等待，直到 N 个 worker 都完成对 active 行的底层读后一起放行；② 第一次 `InvalidateAuthorizeCodeSession` 自旋等待 N 个首次读全部完成后再放行，保证所有读都先于任何失效。
4. 包装器对 Create/Get 返回**深拷贝**请求对象（模拟 SQL 行反序列化），避免共享 session map 干扰（这是 PoC 工件，不是框架缺陷）。
5. N 个 goroutine 经同一 start channel 同时驱动完整两阶段（`HandleTokenEndpointRequest` + `NewAccessResponse`），统计成功/拒绝数与存储会话数。
6. 观察值（本次实测）：修复前 10 轮 `success ∈ [7,10]`，曾出现 `success=10 rejected=0`，access token 会话数随成功数增长。

### 6.3 修复有效性验证

用 §5.1 的 CAS 包装器（mutex 保护 `active map`，条件翻转失败返回 `ErrNotFound`）替换存储后重跑同一压力：

- 实测（5 轮 + `-race` 3 轮）：`success` 恒为 1，拒绝恒为 9，access token 会话恒为 1，无 data race。
- 该测试可直接转化为仓库内永久回归测试（建议放在 `handler/oauth2/`，用可注入屏障的 fake storage，而非依赖 sleep）。

### 6.4 本次执行的基线命令与结果

```
go test ./storage/ ./handler/oauth2/ -count=1          # ok
go test ./handler/oauth2/ ./handler/rfc8628/ ./handler/pkce/ ./storage/ ./handler/rfc7523/ -count=1  # 全部 ok
```

PoC 目录运行后已删除，`git status` 恢复干净，未修改任何生产代码。

---

## 7. 兼容性影响

1. **存储实现者（主要影响面）**：fosite 是库，一次性保证历来由存储后端负责。若采用方案 A1（仅强化契约 + MemoryStore 改为条件翻转），现有 SQL 后端中**已经**用条件 UPDATE/行锁实现 Invalidate 的（如 Ory Hydra 生产级存储）行为不变且本就安全；只有"无条件 UPDATE"的后端需要修改。接口签名不变，编译兼容。
2. **方案 A2（新增接口方法）**：属于破坏性变更，所有自定义 `AuthorizeCodeStorage` 实现需要补方法；可用可选接口 + 类型断言（参照 `Transactional` 的 `Maybe*` 模式，`storage/transactional.go:28-58`）规避，未实现新接口时回退旧行为并打文档警告。
3. **客户端可观察变化**：并发败者从不确定的 `server_error`/偶发成功，变为确定的 `invalid_grant` 或 409。符合 RFC 6749 §5.2，合法客户端的串行重试不受影响；依赖"并发都成功"这一未定义行为的集成（理论上不应存在）会暴露问题。
4. **MemoryStore 语义**：条件翻转后，对不存在或已失效行的 Invalidate 将返回错误而非 nil；当前唯一生产调用点（`flow_authorize_code_token.go:167`）本就把错误转入回滚路径，行为自洽。
5. **性能**：条件 UPDATE 与无条件 UPDATE 成本相同；无额外往返、无持锁期延长（方案 A1）。
6. **测试/文档**：需更新 `handler/oauth2/storage.go:30-33` 的接口注释，明确一次性/原子性责任；新增并发回归测试。

---

## 8. 仍未证实的假设与边界

1. **未审计真实 SQL 后端**：仓库只内置 MemoryStore，Ory Hydra 等下游的 SQL 实现不在本仓库。它们若已用 `UPDATE ... WHERE active=true` 或 `SELECT FOR UPDATE` 则不受影响；本报告的双花结论对 MemoryStore 有 PoC 铁证，对"遵循当前接口文档的朴素 SQL 实现"是基于代码路径的推断，未接入真实数据库验证。
2. **HTTP 层与部署拓扑未测**：PoC 直接驱动 handler，未经过 `NewAccessRequest` 的 HTTP 解析与客户端认证；多实例、反向代理重试、HTTP/2 多路复用下的实际窗口分布未测量。理论上多实例会让进程内锁方案彻底失效，反而更凸显存储 CAS 的必要性。
3. **设备码/JTI/PAR/PKCE 的同源缺陷仅做了静态推断**：代码模式一致，但未为它们各自编写并发 PoC；设备码还有速率限制策略（`DeviceRateLimitStrategy`）可能改变利用概率，未评估其作为补偿控制的充分性。
4. **时间与时钟假设**：过期判定依赖各节点 `time.Now()` 一致（`strategy_hmacsha_plain.go:99-105`）；时钟漂移对双花窗口的影响未量化。
5. **HMAC 策略的并发安全仅部分验证**：`HMACStrategy.Generate` 自带 mutex（`token/hmac/hmacsha.go:34,48`），PoC 中未观测到令牌签名碰撞；但极端熵配置（`GetTokenEntropy` 被调低）下的碰撞概率不在本次分析范围。
6. **PoC 中的深拷贝与屏障是测试装置**：用于隔离共享指针/共享 map 的噪声并确定性地撑开窗口；它们模拟的是 SQL 存储的自然行为，但真实网络延迟下的窗口形态（随机而非均匀）未做统计建模。
7. **历史背景无法追溯**：本地为浅克隆（仅 1 个提交 `a5f0b09`），无法用 git history 判断当前两阶段拆分与无条件 Invalidate 是有意设计还是回归；`PersistAuthorizeCodeGrantSession`（旧的单方法原子持久化，仅存于 mock）暗示早期接口曾把多步操作收敛为一次存储调用，此点需上游历史确认。

---

## 附：关键源码索引

| 主题 | 位置 |
|---|---|
| 授权码签发（active=true） | `handler/oauth2/flow_authorize_code_auth.go:79-98`；`storage/memory.go:249-255` |
| 兑换校验阶段读（事务外） | `handler/oauth2/flow_authorize_code_token.go:32` |
| 重放检测与令牌撤销 | `handler/oauth2/flow_authorize_code_token.go:33-52`；`storage/memory.go:265-267` |
| 兑换签发阶段二次读（事务外） | `handler/oauth2/flow_authorize_code_token.go:126` |
| 事务边界与无条件失效 | `handler/oauth2/flow_authorize_code_token.go:155-188`（失效在 `:167`） |
| 无条件 Invalidate 实现 | `storage/memory.go:272-283` |
| 存储接口契约（无 CAS 语义） | `handler/oauth2/storage.go:19-34` |
| 事务可选机制 | `storage/transactional.go:20-58`（MemoryStore 未实现） |
| 刷新流程的冲突处理对照 | `handler/oauth2/flow_refresh.go:217-222`；`errors.go:30-36` |
| 过期判定（应用层） | `handler/oauth2/strategy_hmacsha_plain.go:97-108`；默认寿命 `config_default.go:384-390` |
| 令牌随机性 | `token/hmac/hmacsha.go:47-85` |
| 设备码同源模式 | `handler/rfc8628/token_handler.go:66,96,108,158` |
| JTI check-then-mark | `handler/rfc7523/handler.go:96,290` |
| PAR Get-then-Delete | `authorize_request_handler.go:303-316` |
| PKCE Get-then-Delete | `handler/pkce/handler.go:135-151` |
| 串行重放回归测试 | `integration/authorize_code_grant_test.go:150-183` |
| 事务回滚 mock 测试 | `handler/oauth2/flow_authorize_code_token_test.go:444-680` |
