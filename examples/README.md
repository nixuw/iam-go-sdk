# 示例

六个可以直接运行的小工程，每个只演示一件事。配置全部从环境变量读取，仓库里只有占位值。

| 目录 | 场景 | 框架 |
| --- | --- | --- |
| [login-fiber](login-fiber/) | 用户登录 | Fiber v2 |
| [caller](caller/) | 调用方：调用 HTTP 接口 | net/http 客户端 |
| [caller-grpc](caller-grpc/) | 调用方：调用 gRPC 接口 | gRPC |
| [provider-fiber](provider-fiber/) | 被调用方 | Fiber v2 |
| [provider-nethttp](provider-nethttp/) | 被调用方 | net/http |
| [provider-grpc](provider-grpc/) | 被调用方 | gRPC |

每个示例里，业务一侧为接入新增的代码夹在 `// iam:start` 和 `// iam:end` 之间，不超过 20 行；读取配置的代码在 `loadConfig` 里。

## 环境变量

| 变量 | 用到它的示例 | 说明 |
| --- | --- | --- |
| `IAM_ISSUER` | 全部 | IAM 的 Issuer，例如 `https://iam.example.com` |
| `LISTEN_ADDR` | 服务类示例 | 监听地址，默认 `127.0.0.1:8080` 到 `8083` |
| `IAM_CLIENT_ID`、`IAM_CLIENT_SECRET` | login-fiber | OIDC 应用（类型“Web 后端”）的 Client ID 和 Secret |
| `APP_BASE_URL` | login-fiber | 应用的对外地址。回调地址是它加 `/callback`，登出回跳地址是它加 `/`，两者都要在 IAM 里登记 |
| `APP_SESSION_KEY` | login-fiber | 会话密钥，至少 32 字节 |
| `IAM_RESOURCE` | provider-* | 本应用的资源标识，以 IAM 应用详情页显示的为准 |
| `IAM_SVC_CLIENT_ID` | caller、caller-grpc | 服务凭证的 Client ID |
| `IAM_SVC_CLIENT_SECRET` | caller、caller-grpc | 服务凭证的 Secret（`client_secret_basic`） |
| `IAM_SVC_KEY_ID`、`IAM_SVC_PRIVATE_KEY_FILE` | caller | 已登记公钥的 `kid` 和私钥的 PEM 文件（`private_key_jwt`），设置后代替 Secret |
| `ORDER_RESOURCE` | caller、caller-grpc | 目标应用的资源标识 |
| `ORDER_API_URL` | caller | 目标的 HTTP 地址 |
| `ORDER_GRPC_ADDR` | caller-grpc | 目标的 gRPC 地址 |
| `IAM_ALLOW_INSECURE` | 全部 | 设为 `true` 时允许 http 的 Issuer、不带 Secure 的 Cookie 和明文连接。只用于联调环境 |

被调用方示例使用权限代码 `order.read` 和 `order.write`，所以它们对应的应用编码是 `order`。换成自己的应用时，把规则里的权限代码改成自己定义的。

## 运行

被调用方（三选一）：

```bash
IAM_ISSUER=https://iam.example.com IAM_RESOURCE=urn:iam:app:order go run ./examples/provider-fiber
```

调用方：

```bash
IAM_ISSUER=https://iam.example.com \
IAM_SVC_CLIENT_ID=<服务凭证的 Client ID> IAM_SVC_CLIENT_SECRET=<Secret> \
ORDER_RESOURCE=urn:iam:app:order ORDER_API_URL=https://order.example.com \
go run ./examples/caller
```

用户登录：

```bash
IAM_ISSUER=https://iam.example.com \
IAM_CLIENT_ID=<OIDC 应用的 Client ID> IAM_CLIENT_SECRET=<Secret> \
APP_BASE_URL=https://portal.example.com APP_SESSION_KEY=<至少 32 字节的随机值> \
go run ./examples/login-fiber
```

然后用浏览器打开 `APP_BASE_URL` 下的 `/profile`。

## gRPC 示例里的 `orderv1`

两个 gRPC 示例用到的 `internal/orderv1` 是手写的服务定义，形态与 `protoc-gen-go-grpc` 生成的代码相同，这样示例不需要安装 protoc。在自己的工程里，它就是生成的代码。

## 测试

每个示例目录下有一个用本地假 Issuer（`iamtest`）跑通的测试，随 `make unit` 运行。`make e2e` 会把这些示例编译成程序，对接真实的 IAM 运行，见 [docs/e2e.md](../docs/e2e.md)。
