# 协议说明

本文说明 SDK 与 IAM 之间的协议约定：SDK 依赖 IAM 的哪些行为、Access Token 的格式、被调用方必须做的八项校验和错误响应。它对应 IAM 的《Token 验证规范》**1.1**，是那份规范面向公开仓库的摘要：不含任何部署信息，示例里的地址和标识都是占位值。规范有修改时，本文和 `iam.SpecVersion` 同步更新。

SDK 只通过下面列出的协议端点与 IAM 交互，不访问 IAM 的数据库和管理接口。

## 1. 端点

端点地址全部来自 Discovery 文档 `<issuer>/.well-known/openid-configuration`，SDK 不写死任何路径。Discovery 的 `issuer` 必须与配置的 Issuer 逐字符相等。

| Discovery 成员 | 用途 | 使用它的模块 |
| --- | --- | --- |
| `jwks_uri` | 验签公钥（RS256） | 登录、被调用方 |
| `authorization_endpoint` | 授权码流程 | 登录 |
| `token_endpoint` | 换 Token、刷新、Client Credentials | 登录、调用方 |
| `userinfo_endpoint` | 读取用户资料 | 登录（可选） |
| `end_session_endpoint` | RP 发起的登出 | 登录 |
| `revocation_endpoint` | 撤销自己申请的 Token（RFC 7009） | 登录、调用方（可选） |
| `introspection_endpoint` | 查询 Token 状态（RFC 7662） | 被调用方（可选） |

Discovery 还有一个扩展成员 `iam_resource_prefix`（资源标识的前缀）。SDK 不使用它：资源标识整体由业务配置。

## 2. IAM 的协议约束

| 约束 | SDK 的做法 |
| --- | --- |
| 两种 Client 分开：OIDC 应用只能用 `authorization_code` 和 `refresh_token`，服务凭证只能用 `client_credentials` | 登录和调用方各用各的 Client ID 与凭证 |
| 客户端认证只有 `client_secret_basic` 和 `private_key_jwt`，一次请求只能用一种；`client_secret_post` 不被接受 | 只实现这两种 |
| `private_key_jwt` 断言：RS256；`iss` 和 `sub` 等于 Client ID；`aud` 是 Token 端点地址；必须有 `exp`（寿命不超过 5 分钟）和不重复的 `jti` | 每次请求重新签发，有效期 60 秒 |
| 授权请求只接受 `response_type=code`；PKCE S256 和 `state` 必填；请求 `openid` 时 `nonce` 必填；`redirect_uri` 显式传递并与登记值逐字节一致 | 自动生成并校验 |
| 授权响应无论成功还是错误都带 `iss`（RFC 9207） | 回调必须校验 `iss` |
| `client_credentials` 必须带且只能带一个 `resource`（RFC 8707）；`scope` 可以省略；不签发 Refresh Token | 每个目标单独取 Token |
| Token 有效期随目标和权限变化 | 以响应的 `expires_in` 为准 |
| Token 端点对失败和被拒的申请按 Client ID 和来源地址限流，超限返回 429 和 `Retry-After` | 不原样重试被拒的申请 |
| Refresh Token 每次刷新都轮换；旧值再次使用会撤销整条刷新链 | 刷新串行，新值一次写入 |
| 已签发的 Access Token 在到期前一直有效；授权撤销、凭证停用、用户禁用只影响之后的申请 | 不承诺即时撤销 |
| 协议错误是 `{"error", "error_description"}`；每个响应带 `X-Request-ID` | 放进 `*iam.OAuthError` |

## 3. Access Token 的格式

Access Token 是 JWS Compact 格式的 JWT（RFC 9068）。

头部：

```json
{ "alg": "RS256", "kid": "<签名密钥的标识>", "typ": "at+jwt" }
```

载荷（系统 Token 的例子）：

```json
{
  "iss": "https://iam.example.com",
  "sub": "<调用方的 Client ID>",
  "aud": "<目标应用的资源标识>",
  "exp": 1794816900,
  "iat": 1794816000,
  "jti": "9b1d6f2c-4c3e-4b0a-8b7e-2f1a9c0d5e6f",
  "client_id": "<调用方的 Client ID>",
  "scope": "order.read",
  "principal_type": "service"
}
```

| 声明 | 含义 |
| --- | --- |
| `iss` | 签发者：IAM 的 Issuer |
| `sub` | 主体。系统 Token 是调用方的 Client ID；用户委托 Token 是用户 ID |
| `aud` | 受众：**一个字符串**，目标应用的资源标识。IAM 从不签发多个受众的 Token |
| `exp`、`iat` | 过期时间、签发时间，Unix 秒 |
| `jti` | Token 的唯一编号 |
| `client_id` | 申请这个 Token 的 Client：服务凭证，或代表用户的 OIDC 应用 |
| `scope` | 空格分隔的权限代码，只包含目标应用的权限 |
| `principal_type` | 主体类型：`service` 表示调用方系统自身，`user` 表示一个用户。这是 IAM 自定义的声明 |
| `sid`、`auth_time` | 只有用户委托 Token 才有：用户的登录会话编号和认证时间 |

三种 Access Token 的受众和权限互不混用：

| Token | 取得方式 | `aud` | `sub` / `principal_type` | 被调用方 |
| --- | --- | --- | --- | --- |
| 系统 Token | 服务凭证，`client_credentials` + `resource` | 目标的资源标识 | Client ID / `service` | 接受 |
| 用户委托 Token | OIDC 应用，授权码 + `resource` | 目标的资源标识 | 用户 ID / `user` | 接受 |
| 登录 Token | OIDC 应用，授权码，不带 `resource` | `<issuer>/oidc/userinfo` | 用户 ID / `user` | 拒绝（`aud` 不是本应用） |

ID Token 的头部 `typ` 是 `JWT`，`aud` 是 OIDC 应用的 Client ID。它只供登录的应用验证“谁登录了”，不能当作 Access Token。

## 4. 逐项校验

被调用方从 `Authorization: Bearer <token>` 请求头（gRPC 是 `authorization` 元数据）取出 Token，**按下面的顺序**校验。Token 只从这里读取，不接受 URL 参数里的 Token。

| # | 校验项 | 要求 | 不通过时 |
| --- | --- | --- | --- |
| 1 | `alg` | JWS Compact 格式，`alg` 必须是 `RS256`。允许的算法是固定的，不由 Token 决定；`none`、`HS256` 等一律拒绝 | 401 `invalid_token` |
| 2 | `typ` | `at+jwt` 或 `application/at+jwt`，不区分大小写。这一项挡住 ID Token | 401 `invalid_token` |
| 3 | 签名与 `kid` | 必须有 `kid`，用 JWKS 里 `kid` 相同的公钥验签。公钥只来自配置的 Issuer，不采信头部的 `jku`、`jwk`、`x5u` | 401 `invalid_token` |
| 4 | `iss` | 与配置的 Issuer 逐字符相等，不做大小写、末尾斜杠之类的归一化 | 401 `invalid_token` |
| 5 | `aud` | 单个字符串，与本应用的资源标识逐字节相等。数组形式不接受，即使其中包含本应用 | 401 `invalid_token` |
| 6 | `exp`、`iat` | 都必须存在。当前时间不晚于 `exp` 加时钟容差；`iat` 不晚于当前时间加时钟容差。时钟容差不超过 60 秒 | 401 `invalid_token` |
| 7 | `scope` | 接口要求的每一项权限都在里面。比较整个权限代码，不做前缀或通配匹配 | 403 `insufficient_scope` |
| 8 | `principal_type` | 是接口接受的主体类型 | 403 `insufficient_scope` |

- 第 1 到第 6 项回答“这个 Token 在这里是否有效”，第 7、8 项回答“这个有效的 Token 能不能用这个接口”。一个 Token 同时有两类问题时返回 401：先完成前六项，再看后两项。
- 每个受保护的接口都声明要求的权限和接受的主体类型。没有声明的接口默认拒绝。
- 八项全部通过之后，才能把 Token 里的任何内容当作事实使用：先看 `principal_type`，再解释 `sub`。

### 验签公钥的缓存

- 公钥必须缓存，不得每个请求都访问 IAM。SDK 每 10 分钟在后台刷新一次。
- 遇到缓存里没有的 `kid`，重新下载一次 JWKS 再判断。IAM 轮换签名密钥时，新密钥在启用之前就发布在 JWKS 里，启用之后新 Token 立即用新密钥签名。
- 下载失败、或下载后仍然没有这个 `kid` 时，30 秒内不再下载，防止有人用伪造的 `kid` 把请求放大到 IAM 上。
- IAM 暂时不可达时继续使用缓存的公钥，最长 24 小时。
- 密钥退役后从 JWKS 里消失，用它签名的 Token 在缓存刷新之后验证失败。
- 一把公钥都没有时，SDK 返回 503，而不是 401：这不是调用方的 Token 的问题。

## 5. 错误响应

### HTTP

遵循 RFC 6750。`realm` 是本应用的资源标识。

没有 Token：

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="urn:example:app:order"
```

Token 无效（第 1 到第 6 项）：

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="urn:example:app:order", error="invalid_token", error_description="token expired"
Content-Type: application/json
Cache-Control: no-store

{"error":"invalid_token","error_description":"token expired"}
```

权限不足或主体类型不被接受（第 7、8 项）：

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer realm="urn:example:app:order", error="insufficient_scope", error_description="the token lacks order.write", scope="order.write"
Content-Type: application/json
Cache-Control: no-store

{"error":"insufficient_scope","error_description":"the token lacks order.write"}
```

- `error` 只使用 `invalid_token` 和 `insufficient_scope` 两个值。调用方靠它决定是重新申请 Token（401）还是去检查授权（403）。
- `insufficient_scope` 时，`scope` 给出这个接口要求的全部权限。
- 响应不回显 Token。响应体的格式可以由业务替换，`WWW-Authenticate` 头必须保留。
- 通过 Token 验证之后的业务拒绝（租户不匹配、数据无权访问、业务规则不允许）使用业务自己的错误码，不使用这两个值。

### gRPC

| 情况 | 状态码 |
| --- | --- |
| 没有 Token；Token 无效（第 1 到第 6 项） | `Unauthenticated` |
| 权限不足；主体类型不被接受；方法没有声明访问规则（第 7、8 项） | `PermissionDenied` |
| 没有可用的验签公钥 | `Unavailable` |

- Token 放在元数据 `authorization` 里，值是 `Bearer <token>`。
- 状态消息是 `<error>: <error_description>`，不含 Token 的内容。
- trailer 元数据 `www-authenticate` 的值与 HTTP 的 `WWW-Authenticate` 相同，调用方可以从中读出 `error` 和 `scope`。

### 调用方怎样处理

| 目标的响应 | 处理 |
| --- | --- |
| 401 `invalid_token`（gRPC：`Unauthenticated`） | 丢弃缓存的 Token，重新申请一次再重试；仍然失败就报错，不循环重试 |
| 403 `insufficient_scope`（gRPC：`PermissionDenied`） | 授权配置的问题，重试没有用 |
| 其他 | 目标自己的业务错误，按目标的接口文档处理 |

## 6. 授权变更何时生效

IAM 签发的是短期的、可以离线验证的 Token。授权被修改或撤销、凭证被停用、用户被禁用，都只影响之后的 Token 申请；已经签发的 Token 在到期前仍然有效。只有调用方主动撤销的 Token，可以通过内省看到。

被调用方需要立即阻断某个调用方时，在自己的应用里按 `client_id` 拒绝（SDK 的 `VerifierConfig.Authorize`）。
