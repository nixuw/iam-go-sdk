# 变更记录

版本号遵循语义化版本。每个版本写明所实现的《Token 验证规范》版本。

## 1.0.0（未发布）

实现《Token 验证规范》**1.1**。

首个版本：

- **基础**：配置校验；Discovery；JWKS 缓存；可替换的 HTTP 客户端；可用 `errors.Is` / `errors.As` 区分的错误；`slog` 日志，不输出任何 Token 和凭证。
- **用户登录**（`iam.NewLogin`）：授权码 + PKCE（S256）、`state`、`nonce`；回调校验 `state` 和 `iss`；ID Token 校验；内置本地会话（可替换会话存储）；保护中间件；刷新（并发合并、跨实例租约）；登出；只用协议部分的 `AuthCodeURL` / `Exchange`。
- **调用方**（`iam.NewCaller`）：`client_secret_basic` 和 `private_key_jwt`；按目标和权限集合缓存、到期前续取、并发合并；失败退避；绑定目标的 HTTP 客户端和 gRPC 调用凭证；凭证热更新；撤销。
- **被调用方**（`iam.NewVerifier`）：八项校验；按接口声明访问规则，默认拒绝；RFC 6750 错误响应；手动校验入口；校验后的业务判断；可选的内省。
- **适配**：`iamfiber`（Fiber v2）、`iamhttp`（net/http）、`iamgrpc`（gRPC）。
- **测试辅助与示例**：`iamtest` 本地假 Issuer；六个示例工程。

依赖基线：Go 1.26.11、go-jose v4.1.6、Fiber v2.52.6、grpc v1.83.1。

v1 不包含：用户委托 Token 的获取；SPA、原生应用和命令行程序的登录；Gin、Echo 等框架的专用适配。
