# iam-go-sdk

Go 业务工程接入 IAM 的 SDK。它把每个工程都要重复实现的协议逻辑封装起来，业务工程只需要传入配置、注册中间件或调用一个接入点：

| 场景 | 入口 | SDK 完成的事 |
| --- | --- | --- |
| 用户登录 | `iam.NewLogin` | 授权码 + PKCE、`state` / `nonce`、回调校验、ID Token 校验、本地会话、刷新、登出 |
| 调用方 | `iam.NewCaller` | 用服务凭证取系统 Token、缓存、到期前续取、失败退避、出站请求自动带 Token |
| 被调用方 | `iam.NewVerifier` | 按《Token 验证规范》离线验证 Token、按接口检查权限和主体类型、RFC 6750 错误响应 |

- 模块路径：`github.com/nixuw/iam-go-sdk`
- Go 版本：1.26.11 或更高
- 实现的《Token 验证规范》版本：**1.1**（常量 `iam.SpecVersion`）
- 协议约定的公开说明：[docs/protocol.md](docs/protocol.md)

## 包

| 包 | 用途 | 第三方依赖 |
| --- | --- | --- |
| `iam`（模块根） | 核心：三个场景的全部逻辑 | 只有 go-jose v4 |
| `iamfiber` | Fiber v2 的处理器和中间件 | Fiber v2 |
| `iamhttp` | net/http 的处理器和中间件，适用于 ServeMux、chi 等 | 无 |
| `iamgrpc` | gRPC 的服务端拦截器和调用凭证 | grpc |
| `iamtest` | 单元测试用的本地假 Issuer | 无 |

核心不依赖任何 Web 框架和 gRPC。业务工程只引入自己用到的适配：只引用 `iam` 时，工程的 `go.mod` 和 `go.sum` 里不会出现 Fiber 和 gRPC；引用 `iamfiber` 不会带进 gRPC，反之亦然。（`go mod graph` 会列出本模块 `go.mod` 的全部依赖边，这是模块级的声明，不会被下载和编译。）

```bash
go get github.com/nixuw/iam-go-sdk
```

## 快速接入

下面的配置从环境变量读取只是举例。SDK 自己不读环境变量和配置文件，值从哪里来由业务工程决定。完整可运行的工程在 [examples/](examples/)。

### 用户登录（Fiber v2）

在 IAM 控制台登记一个类型为“Web 后端”的 OIDC 应用，得到 Client ID 和 Secret（或登记自己的公钥）。

```go
login, err := iam.NewLogin(ctx, iam.LoginConfig{
	Issuer:      os.Getenv("IAM_ISSUER"),                          // 例如 https://iam.example.com
	ClientID:    os.Getenv("IAM_CLIENT_ID"),                       // OIDC 应用的 Client ID
	Credential:  iam.ClientSecret(os.Getenv("IAM_CLIENT_SECRET")), // 或 iam.PrivateKeyJWT(kid, key)
	RedirectURL: os.Getenv("APP_CALLBACK_URL"),                    // 与登记的回调地址逐字节一致
	SessionKey:  []byte(os.Getenv("APP_SESSION_KEY")),             // 至少 32 字节的随机值
})
if err != nil {
	log.Fatal(err) // 错误会指明是哪一项配置
}
auth := iamfiber.Login(login)

app := fiber.New()
app.Get("/login", auth.Start)       // 发起登录：跳转到 IAM
app.Get("/callback", auth.Callback) // 回调：校验、换 Token、建立本地会话，回到原页面
app.Get("/logout", auth.Logout)     // 登出：清除本地会话，再跳转到 IAM 的登出端点

// 没登录的页面请求跳转到 /login，API 请求返回 401
app.Get("/profile", auth.Require(), func(c *fiber.Ctx) error {
	user := iamfiber.User(c)
	// user.Issuer + user.Subject 是用户的唯一键，用它映射本地账号
	return c.JSON(fiber.Map{"sub": user.Subject, "name": user.Name, "email": user.Email})
})
```

### 调用方

在 IAM 控制台为应用创建服务凭证，并向目标应用的负责人申请“系统调用”授权。

```go
caller, err := iam.NewCaller(ctx, iam.CallerConfig{
	Issuer:     os.Getenv("IAM_ISSUER"),
	ClientID:   os.Getenv("IAM_SVC_CLIENT_ID"), // 服务凭证的 Client ID，不是登录用的那个
	Credential: iam.PrivateKeyJWT(os.Getenv("IAM_SVC_KEY_ID"), privateKey),
})
if err != nil {
	return err
}

// 每个目标建一个出站客户端。它只会把面向这个目标的 Token 发给这个目标。
orders := caller.HTTPClient(iam.Target{
	Resource: os.Getenv("ORDER_RESOURCE"), // 目标应用的资源标识
	Scopes:   []string{"order.read"},      // 按最小权限指定
})

resp, err := orders.Get(os.Getenv("ORDER_API_URL") + "/api/orders/42") // 标准的 *http.Client
if err != nil {
	var oe *iam.OAuthError
	if errors.As(err, &oe) {
		// IAM 拒绝签发 Token，例如 invalid_target（没有授权）。
		// RequestID 可以交给 IAM 管理员，在 Token 申请记录里定位这一次申请。
		log.Printf("token request refused: %s (request id %s)", oe.Code, oe.RequestID)
	}
	return err
}
```

`caller` 在进程里创建一次、长期复用。私钥用 `iam.ParsePrivateKeyPEM` 从 PEM 解析，也可以传任何实现了 `crypto.Signer` 的 RSA 密钥（KMS、HSM）。

### 被调用方

在 IAM 控制台为应用勾选“服务提供方”角色，定义 API 权限。

```go
verifier, err := iam.NewVerifier(ctx, iam.VerifierConfig{
	Issuer:   os.Getenv("IAM_ISSUER"),
	Audience: os.Getenv("IAM_RESOURCE"), // 本应用的资源标识，以 IAM 应用详情页显示的为准
})
if err != nil {
	log.Fatal(err)
}
guard := iamfiber.Guard(verifier)

// 每个对外接口声明两件事：要求的权限、接受的主体类型
app.Get("/api/orders/:id",
	guard.Require(iam.Rule{
		Scopes:     []string{"order.read"},
		Principals: []string{iam.PrincipalService, iam.PrincipalUser},
	}),
	func(c *fiber.Ctx) error {
		who := iamfiber.Caller(c) // 校验通过后的调用者身份
		if who.PrincipalType == iam.PrincipalUser {
			// 用户委托：who.Subject 是用户 ID，who.ClientID 是代表用户发起调用的应用
		} else {
			// 系统调用：who.ClientID 是调用方的服务凭证，没有用户
		}
		// 从这里开始是业务自己的判断：租户、数据范围、业务规则
		return c.JSON(fiber.Map{"id": c.Params("id")})
	})
```

请求进入业务处理函数之前的结果：

| 请求 | 结果 |
| --- | --- |
| 没有带 Token | 401，`WWW-Authenticate` 里只有 `realm` |
| Token 过期、签名无效、`aud` 不是本应用，或者拿 ID Token 来调用 | 401 `invalid_token` |
| Token 有效但缺少接口要求的权限，或主体类型不被接口接受 | 403 `insufficient_scope`，带接口要求的 `scope` |
| 一把验签公钥都没有（IAM 一直不可达） | 503 |
| 全部通过 | 进入业务处理函数 |

### gRPC

```go
// 调用方：连接绑定到一个目标，每次调用自动带上面向它的 Token
target := iam.Target{Resource: os.Getenv("ORDER_RESOURCE"), Scopes: []string{"order.read"}}
conn, err := grpc.NewClient(os.Getenv("ORDER_GRPC_ADDR"),
	grpc.WithTransportCredentials(tlsCredentials),
	grpc.WithPerRPCCredentials(iamgrpc.Credentials(caller, target)),
	grpc.WithChainUnaryInterceptor(iamgrpc.UnaryClientInterceptor(caller, target)), // 目标拒绝 Token 时换新 Token 重试一次
)

// 被调用方：按方法声明访问规则。没有列出的方法默认拒绝。
rules := iamgrpc.Rules{
	"/order.v1.OrderService/GetOrder":    {Scopes: []string{"order.read"}, Principals: []string{iam.PrincipalService, iam.PrincipalUser}},
	"/order.v1.OrderService/CreateOrder": {Scopes: []string{"order.write"}, Principals: []string{iam.PrincipalService}},
}
srv := grpc.NewServer(
	grpc.ChainUnaryInterceptor(iamgrpc.UnaryServerInterceptor(verifier, rules)),
	grpc.ChainStreamInterceptor(iamgrpc.StreamServerInterceptor(verifier, rules)),
)
// 处理函数里用 iamgrpc.Caller(ctx) 取调用者身份
```

Token 放在 `authorization` 元数据里（`Bearer <token>`）。状态码：没有 Token 或 Token 无效是 `Unauthenticated`，权限不足、主体类型不被接受或方法没有声明规则是 `PermissionDenied`，公钥不可用是 `Unavailable`；trailer 元数据 `www-authenticate` 带有与 HTTP 相同的质询值。健康检查等不需要 Token 的方法用 `iamgrpc.WithPublicMethods(...)` 显式放行。

### net/http、chi、Gin、Echo

`iamhttp` 提供与 `iamfiber` 等价的处理器和中间件，中间件的形态是 `func(http.Handler) http.Handler`：

```go
auth := iamhttp.Login(login)
mux.HandleFunc("GET /login", auth.Start)
mux.HandleFunc("GET /callback", auth.Callback)
mux.HandleFunc("GET /logout", auth.Logout)
mux.Handle("GET /profile", auth.Require()(profile)) // iamhttp.User(r)

guard := iamhttp.Guard(verifier)
mux.Handle("GET /api/orders/{id}", guard.Require(rule)(getOrder)) // iamhttp.Caller(r)
```

chi 直接使用：`r.With(guard.Require(rule)).Get("/api/orders/{id}", getOrder)`。

Gin、Echo 等框架没有单独的适配，用两个与框架无关的接入点即可：

- 被调用方：`verifier.VerifyHeader(ctx, 请求头 Authorization 的值, rule)`（或 `verifier.Verify(ctx, token, rule)`），返回调用者身份或 `*iam.BearerError`。
- 登录：`login.AuthCodeURL` 生成授权地址，`login.Exchange` 处理回调并返回身份与 Token；会话由工程自己维护。

以 Gin 的被调用方中间件为例：

```go
func Guard(v *iam.Verifier, rule iam.Rule) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := v.VerifyHeader(c.Request.Context(), c.GetHeader("Authorization"), rule)
		var be *iam.BearerError
		switch {
		case err == nil:
			c.Request = c.Request.WithContext(iam.ContextWithIdentity(c.Request.Context(), id))
			c.Next() // 处理函数里用 iam.IdentityFromContext(c.Request.Context())
		case errors.As(err, &be):
			if challenge := be.WWWAuthenticate(); challenge != "" {
				c.Header("WWW-Authenticate", challenge) // 这个响应头必须保留
			}
			c.AbortWithStatusJSON(be.Status, gin.H{"error": be.Code, "error_description": be.Description})
		default:
			c.AbortWithStatus(http.StatusForbidden) // VerifierConfig.Authorize 的业务拒绝
		}
	}
}
```

自带会话的工程接入登录：

```go
// 发起登录
req, err := login.AuthCodeURL(ctx, iam.AuthOptions{ReturnTo: "/dashboard"})
session.Set("iam_pending", req.Pending) // 保存在服务端、与这个浏览器绑定，用一次就删除
redirect(req.URL)

// 回调
result, err := login.Exchange(ctx, &pending, r.URL.Query())
// result.User 是登录用户；result.Tokens 里的 IDToken 留给登出，RefreshToken 用 login.Refresh 刷新
```

## 配置项

每个场景只要求它需要的配置项。缺项或不合法时，创建实例立即返回 `*iam.ConfigError`，`Field` 是配置项的名字。

| 配置项 | 字段 | 必填 | 适用 | 说明 |
| --- | --- | --- | --- | --- |
| Issuer | `Issuer` | 是 | 全部 | 与 Discovery 的 `issuer`、Token 的 `iss` 逐字符相等，SDK 不做任何归一化。默认要求 HTTPS |
| Client ID | `ClientID` | 是 | 登录、调用方 | 登录用 OIDC 应用的 Client ID，调用方用服务凭证的 Client ID，分别配置 |
| 客户端认证 | `Credential` | 是 | 登录、调用方 | `iam.ClientSecret` / `iam.ClientSecretFunc`（`client_secret_basic`），`iam.PrivateKeyJWT` / `iam.PrivateKeyJWTFunc`（`private_key_jwt`）。用凭证在 IAM 登记的那一种 |
| 回调地址 | `RedirectURL` | 是 | 登录 | 与登记值逐字节一致 |
| 登出回跳地址 | `PostLogoutRedirectURL` | 否 | 登录 | 与登记值一致；不配置时停留在平台的“已退出”页 |
| 登录范围 | `Scopes` | 否 | 登录 | 只能是 `openid`、`profile`、`email`、`offline_access`，默认 `openid profile` |
| 读取 UserInfo | `FetchUserInfo` | 否 | 登录 | 登录后再从 UserInfo 读取最新资料，并核对 `sub` 一致 |
| 会话密钥 | `SessionKey` / `SessionKeys` | 使用内置会话时必填 | 登录 | 至少 32 字节。签名会话 Cookie，并加密存进会话存储的数据。`SessionKeys` 是取值函数，用于不重启更换 |
| 会话存储 | `SessionStore` | 否 | 登录 | 默认是进程内存储；多实例部署时换成共享存储 |
| 会话有效期上限 | `SessionMaxAge` | 否 | 登录 | 默认 8 小时 |
| 会话 Cookie 名 | `SessionCookieName` | 否 | 登录 | 默认 `iam_session` |
| 本应用的资源标识 | `Audience` | 是 | 被调用方 | 以 IAM 应用详情页显示的为准，SDK 不拼接、不内置前缀 |
| 目标的资源标识和权限 | `iam.Target` | 是 | 调用方 | 每个目标一组；`BaseURL` 可选，用来把出站客户端限制在目标的地址上 |
| 时钟容差 | `Leeway` | 否 | 登录、被调用方 | 默认 60 秒，上限 60 秒 |
| 校验后的业务判断 | `Authorize` | 否 | 被调用方 | Token 通过全部校验之后调用，返回错误即拒绝 |
| 内省 | `Introspection` | 否 | 被调用方 | 已登记在本应用上的服务凭证；只对 `Rule.Introspect` 为 true 的接口生效 |
| 允许 HTTP 的 Issuer | `AllowInsecureIssuer` | 否 | 全部 | 默认关闭，只用于联调环境 |
| 允许不带 Secure 的 Cookie | `AllowInsecureCookie` | 否 | 登录 | 默认关闭，只用于本机 http 开发 |
| 允许在明文连接上发送 Token | `AllowInsecureTransport` | 否 | 调用方 | 默认关闭 |
| 启动时 IAM 不可达 | `TolerateStartupFailure` | 否 | 全部 | 默认启动失败；开启后启动成功，之后按需重试 |
| HTTP 客户端 | `HTTPClient` | 否 | 全部 | 访问 IAM 用。用于代理、自定义 CA、链路追踪，或把 Issuer 域名指向集群内地址。默认超时 10 秒 |
| 日志 | `Logger` | 否 | 全部 | `*slog.Logger`，默认不输出 |

端点地址不是配置项：全部由 Issuer 经 Discovery 得出。每个环境一套配置，不同环境的 Issuer、凭证和资源标识不通用。

## 行为说明

### 用户登录

- **一次性参数。** 每次登录生成新的 `state`、`nonce` 和 PKCE（S256）参数，保存在服务端，通过一个签名的 Cookie 与发起登录的浏览器绑定，回调时取出即销毁。同一个浏览器的多个标签页可以并行登录。
- **回调。** 依次校验 `state`、校验 `iss` 等于配置的 Issuer、处理错误回调、用授权码换 Token。`access_denied`、`login_required`、`consent_required` 等错误回调以 `*iam.OAuthError` 交给 `WithErrorHandler` 设置的处理函数，由业务决定如何展示或回退；不设置时返回 JSON 错误。
- **ID Token。** 校验签名（RS256、JWKS、`kid`）、`iss`、`aud` 等于本应用的 Client ID、`exp` 和 `iat`、`nonce`；传了 `max_age` 时检查 `auth_time`；有 `at_hash` 时核对。任何一项不通过，登录失败。
- **本地会话。** 会话 Cookie 是 `HttpOnly; Secure; SameSite=Lax`，里面只有签名的会话编号。Token 只保存在服务端，不交给浏览器脚本。
- **保护中间件。** 未登录的页面请求（浏览器导航）跳转到登录路径（默认 `/login`，用 `WithLoginPath` 修改），登录后回到原页面，只允许回到本站地址；未登录的 API 请求返回 401，不跳转。
- **刷新。** 应用开启了 Refresh Token 时，会话的 Access Token 到期后，下一个请求会触发刷新：成功后新的 Refresh Token 一次写入替换旧值；IAM 返回 `invalid_grant`（用户被禁用、在平台退出、撤销同意）时本地会话结束，要求重新登录；IAM 暂时不可达时会话保留，稍后再试。
- **登出。** 先清除本地会话；持有 Refresh Token 时调用撤销端点；再带 `id_token_hint`、`post_logout_redirect_uri` 和 `state` 跳转到登出端点。
- **多实例。** 同一会话的并发刷新在进程内排队；跨实例靠会话存储的 `CompareAndSwap` 保证只有一个实例兑换 Refresh Token。IAM 的 Refresh Token 每次刷新都轮换，旧值再次使用会撤销整条刷新链并且没有宽限期，所以**共享会话存储必须提供原子的比较并交换**（见 `iam.SessionStore`）。
- **平台侧退出。** IAM 没有 Back-Channel Logout：用户在平台退出或被禁用后，本地会话最迟在下一次刷新失败时结束（开启刷新时不超过 Access Token 的有效期），否则在会话有效期上限到达时结束。

v1 不提供：用户委托 Token 的获取（授权请求带 `resource`）；SPA、原生应用和命令行程序的登录。

### 调用方

- **缓存与续取。** 按（凭证、目标、权限集合）缓存 Token，用响应的 `expires_in` 计算到期时间，不解析 Token。剩余有效期不足 60 秒或不足五分之一时在后台续取，调用不等待；并发的申请合并成一次。
- **失败处理。**
  - `invalid_client`、`invalid_target`、`invalid_scope`、`unauthorized_client`、`invalid_request`：不原样重试。同一个申请在退避期内（10 秒起，逐次翻倍，最长 5 分钟）不再发往 IAM，期间直接返回上一次的错误；全部目标合计的被拒申请每分钟不超过 6 次，远低于 IAM 对 Client ID 的限流阈值。凭证本身被拒时，更换凭证后立即恢复。
  - 429：在 `Retry-After` 之前不发任何申请。
  - 503、5xx 和网络错误：带抖动的指数退避重试。
  - IAM 不可用期间，缓存里未过期的 Token 继续使用。
- **出站客户端。** 默认只在 https 上发送 Token；重定向到其他源时不带 Token；目标返回 401 `invalid_token` 时丢弃缓存、换新 Token 重试一次（只在请求可以重放时）；仍然失败或请求不可重放时返回匹配 `iam.ErrInvalidToken` 的错误；目标返回 403 `insufficient_scope` 时不重试，返回匹配 `iam.ErrInsufficientScope` 的错误。
- **凭证热更新。** `ClientSecretFunc` 和 `PrivateKeyJWTFunc` 在每次申请时取当前值，配合 IAM 的重叠轮换，不需要重启。
- **不转发。** SDK 不提供把收到的 Token 转发给下游的能力。需要调用下游时，用自己的服务凭证为下游申请新的 Token。系统 Token 不携带用户身份：IAM 不支持 Token Exchange，调用链中间的服务不能把用户身份以 Token 的形式传给下游；下游需要知道是哪个用户时，按它的接口约定作为业务参数传递。

### 被调用方

- **八项校验**，顺序见 [docs/protocol.md](docs/protocol.md)。第 1 到第 6 项不通过是 401，第 7、8 项不通过是 403；先完成前六项，再看后两项。
- **默认拒绝。** 权限和主体类型都必须显式声明。两者缺任何一个的规则（包括零值 `iam.Rule{}`）拒绝一切请求。
- **公钥缓存。** 公钥只来自配置的 Issuer 的 JWKS，不采信 Token 头部的 `jku`、`jwk`、`x5u`。每 10 分钟在后台刷新；遇到未知 `kid` 时重新下载一次，下载失败或仍然没有这个 `kid` 时 30 秒内不再下载；IAM 不可达时继续使用缓存的公钥，最长 24 小时。
- **调用者身份。** 先看 `PrincipalType`，再解释 `Subject`。
- **业务拒绝。** `VerifierConfig.Authorize` 返回的错误以 `iam.ErrDenied` 包装返回，HTTP 适配默认回 403（不带 `WWW-Authenticate`），不使用 `invalid_token` 和 `insufficient_scope`。
- **错误响应的格式。** `WithErrorHandler` 可以替换响应体；Token 错误的状态码和 `WWW-Authenticate` 头由 SDK 固定，处理函数改不掉。
- **内省。** 默认关闭。只有调用方主动撤销 Token 这一种情况离线验证看不到；需要识别它的接口把 `Rule.Introspect` 设为 true。结果按 Token 缓存 30 秒；内省不可用时这些接口返回 503。
- **不提供即时撤销。** 已签发的 Token 在到期前一直有效；授权撤销、凭证停用、用户禁用只影响之后的申请。需要立即阻断某个调用方时，用 `Authorize` 按 `ClientID` 拒绝。

## 错误说明

错误都通过返回值给出，用 `errors.Is` / `errors.As` 判断类别。

| 类别 | 判断 | 说明 |
| --- | --- | --- |
| 配置错误 | `errors.Is(err, iam.ErrConfig)`，`*iam.ConfigError` | `Field` 指明是哪一项 |
| IAM 返回的协议错误 | `*iam.OAuthError` | `Code`、`Description`、`StatusCode`、`RequestID`（响应头 `X-Request-ID`）、`RetryAfter` |
| 网络错误 | `errors.Is(err, iam.ErrNetwork)`，`*iam.NetworkError` | IAM 不可达，或响应不是协议响应 |
| 没有 Token | `errors.Is(err, iam.ErrNoToken)`，`*iam.BearerError` | 401，只有 `realm` |
| Token 无效 | `errors.Is(err, iam.ErrInvalidToken)` | 被调用方：`*iam.BearerError`，401；登录：ID Token 校验失败 |
| 权限不足 | `errors.Is(err, iam.ErrInsufficientScope)`，`*iam.BearerError` | 403，`Scope` 是接口要求的权限 |
| 暂时无法验证 | `errors.Is(err, iam.ErrUnavailable)` | 503：没有可用的公钥，或内省不可用 |
| 业务拒绝 | `errors.Is(err, iam.ErrDenied)` | `Authorize` 返回了错误 |
| 回调不可信 | `errors.Is(err, iam.ErrInvalidCallback)` | `state` 不匹配、`iss` 不对、没有授权码 |
| 需要重新登录 | `errors.Is(err, iam.ErrLoginRequired)` | 没有有效会话，或刷新返回 `invalid_grant` |
| 明文连接 | `errors.Is(err, iam.ErrInsecureTransport)` | 出站客户端拒绝在明文连接上发送 Token |
| 目标不符 | `errors.Is(err, iam.ErrTargetMismatch)` | 请求地址不在 `Target.BaseURL` 之内 |

Token 端点的错误码（`OAuthError.Code`）与处理：

| `Code` | 含义 | 处理 |
| --- | --- | --- |
| `invalid_client` | 凭证不对、已过期或已停用；认证方式与登记的不一致 | 核对凭证；不要重试 |
| `invalid_target` | 资源标识不对；目标已停用；没有对目标的生效授权 | 核对资源标识；向目标应用的负责人申请或续期授权 |
| `invalid_scope` | 申请的权限不在授权范围内 | 核对权限和授权 |
| `unauthorized_client` | 用 OIDC 应用申请系统 Token，或用服务凭证登录 | 登录用 OIDC 应用，调用用服务凭证 |
| `invalid_grant` | 授权码已用过或过期；Refresh Token 已失效 | 重新发起登录 |
| `temporarily_unavailable`（429） | 失败或被拒的申请太多 | 按 `RetryAfter` 等待，并修掉原因 |

## 安全注意事项

- Secret、私钥和会话密钥只放在服务端的密钥管理里，不进代码仓库、镜像和日志；每个环境用各自的凭证。SDK 不把它们写入磁盘、日志和错误信息；日志里也不会出现 Token、断言、授权码和 `code_verifier`。
- 放宽安全默认值的三个开关（`AllowInsecureIssuer`、`AllowInsecureCookie`、`AllowInsecureTransport`）只用于联调和本机开发。
- 用 `Issuer` + `Subject` 作为用户的唯一键，不要用邮箱或用户名。
- ID Token 和登录得到的 Access Token 不能用来调用业务 API；被调用方会拒绝它们。
- 被调用方通过校验之后，仍然要做自己的租户、数据范围和业务规则检查；访问日志里记录 `ClientID`、`Subject`、`PrincipalType` 和 `TokenID`，不要记录 Token。
- 收到的 Token 不转发给下游。
- 本地会话的有效期不要超过平台的 SSO 会话。
- 服务器必须做时间同步；时钟容差不超过 60 秒。

## 测试

业务工程的单元测试不需要真实的 IAM。`iamtest` 是一个本地假 Issuer：提供 Discovery 和 JWKS，签发指定内容的测试 Token，并实现了 SDK 用到的协议端点。

```go
func TestOrdersAPI(t *testing.T) {
	iss := iamtest.NewIssuer(t)
	verifier, err := iam.NewVerifier(ctx, iam.VerifierConfig{
		Issuer: iss.URL(), Audience: "urn:example:app:orders",
		HTTPClient: iss.HTTPClient(), // 信任假 Issuer 的证书
	})
	// ……用 verifier 搭好被测的路由……

	ok := iss.ServiceToken("urn:example:app:orders", "svc_example_caller", "order.read")
	expired := iss.AccessToken(iamtest.Token{Audience: "urn:example:app:orders", IssuedAt: time.Now().Add(-time.Hour)})
	// 用 ok、expired 调用被测接口，断言 200、401……
}
```

还可以：`iss.UserToken` 签发用户委托 Token；`iss.RotateKey` / `iss.RetireKey` 模拟密钥轮换；`iss.SetDown(true)` 模拟 IAM 不可达；`iss.AddServiceClient` 和 `iss.Grant` 登记服务凭证与授权，让 `iam.NewCaller` 能取到 Token；`iss.AddLoginClient` 和 `iss.SignIn` 让登录流程不经过任何页面直接完成。

## 协议与 IAM 特有的约定

SDK 遵循的开放标准：OAuth 2.0（RFC 6749）、PKCE（RFC 7636）、OpenID Connect Core / Discovery / RP-Initiated Logout、JWT Access Token（RFC 9068）、Bearer Token（RFC 6750）、Resource Indicators（RFC 8707）、JWT 客户端断言（RFC 7523）、授权响应的 `iss`（RFC 9207）、撤销（RFC 7009）、内省（RFC 7662）。

IAM 特有的约定只有三处，详见 [docs/protocol.md](docs/protocol.md)：

1. 声明 `principal_type`：`service` 或 `user`。
2. Discovery 的扩展成员 `iam_resource_prefix`。SDK 不使用它：资源标识整体由业务配置。
3. 《Token 验证规范》的校验项与结果映射。

SDK 不假设 IAM 没有的能力存在：Token Exchange、mTLS 客户端认证、Back-Channel Logout、即时撤销、Device Flow、动态客户端注册、Implicit 和密码模式、`client_secret_post`、RS256 以外的签名算法、多个 `resource` 或多受众的 Token。

## 开发

```bash
make vet     # gofmt 没有输出，go vet 通过
make build   # CGO_ENABLED=0 go build -trimpath ./...
make unit    # 单元测试：本地假 Issuer
make e2e     # 端到端测试：连接真实的 IAM，见 docs/e2e.md
```

源码注释用英文，工程文档用中文。依赖里与 IAM 同名的库使用相同的主版本（Fiber v2、go-jose v4）。

## 版本

语义化版本；同一个主版本内保持兼容。每个版本的发布说明写明所实现的《Token 验证规范》版本，见 [CHANGELOG.md](CHANGELOG.md)。

## 许可证

[Apache License 2.0](LICENSE)。
