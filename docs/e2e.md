# 端到端测试

测试分两层：

| 命令 | 连接什么 | 内容 |
| --- | --- | --- |
| `make unit` | 本地假 Issuer（`iamtest`） | 全部单元测试、三个适配的场景测试、示例的测试、仓库检查 |
| `make e2e` | 真实的 IAM | `e2e/` 目录：SDK 和示例工程对接真实的 IAM |

`e2e/` 只说协议：它用 SDK 和编译好的示例程序访问 IAM 的协议端点，不引用 IAM 的任何代码。它需要一份**夹具文件**，描述一套真实的 IAM 以及为这次运行登记好的应用。

```bash
make e2e IAM_E2E_FIXTURE=/path/to/fixture.json
```

没有设置 `IAM_E2E_FIXTURE` 时命令直接失败，不会静默跳过。

## 场景

| 测试 | 验收项 | 内容 |
| --- | --- | --- |
| `TestLoginExample` | AC-03 | 示例 `login-fiber`：登录、回调、取得用户身份、访问受保护页面、登出并回跳 |
| `TestSignInProtocol` | AC-04、LOGIN-07、LOGIN-09 | 协议层的登录；`state`、`iss`、`nonce` 不匹配时登录失败；并发刷新只发一次请求；平台退出后刷新被拒 |
| `TestSystemTokens` | AC-06、AC-07、AC-08 | 两种凭证取系统 Token，`aud` 是目标的资源标识；缓存；没有授权的目标不被反复申请 |
| `TestProviderChecklist` | AC-09、AC-14 | 用 IAM 真实签发的 Token 和由它们改造的伪造 Token，逐项检查 SDK 的中间件和 Fiber、net/http、gRPC 三个被调用方示例 |
| `TestSameVerdictAsIAM` | AC-12 | 同一批 Token，SDK 与 IAM 的示例资源服务结论一致 |
| `TestIntrospectionAndRevocation` | VERIFY-08 | 调用方撤销 Token，内省能看到，离线验证看不到 |
| `TestExamplesTogether` | AC-13、AC-14 | 示例 `caller`、`caller-grpc` 调用被调用方示例 |
| `TestOfflineValidation` | AC-10 | 25 次验证只下载一次 JWKS；未知 `kid` 不会放大；IAM 激活新密钥后新旧 Token 都通过；断开 IAM 后仍可验证 |

需要“操作员”的场景（登录、密钥轮换）在夹具没有 `control_url` 时跳过。

## 夹具文件

```json
{
  "issuer": "https://iam.example.com",
  "allow_insecure": false,
  "login": {
    "client_id": "<OIDC 应用的 Client ID>",
    "client_secret": "<Secret>",
    "base_url": "https://portal.example.com",
    "username": "<测试用户的登录名>",
    "subject": "<测试用户的用户 ID>",
    "name": "<显示名>",
    "email": "<邮箱>"
  },
  "caller_secret": { "client_id": "<服务凭证>", "client_secret": "<Secret>" },
  "caller_key": { "client_id": "<服务凭证>", "key_id": "<kid>", "private_key_pem": "<PEM>" },
  "provider": {
    "resource": "<应用 order 的资源标识>",
    "introspection": { "client_id": "<服务凭证>", "client_secret": "<Secret>" },
    "sample_rs_url": "<IAM 的示例资源服务地址>"
  },
  "other_resource": "<另一个应用的资源标识>",
  "no_grant_resource": "<没有任何授权的应用的资源标识>",
  "tokens": { "user_delegated": "<用户委托 Token>" },
  "control_url": "<操作员地址>"
}
```

要在 IAM 里登记的内容：

| 夹具字段 | 在 IAM 里登记 |
| --- | --- |
| `login` | 一个测试用户；一个“Web 后端”类型的 OIDC 应用，`client_secret_basic`，登录范围 `openid profile email`，免同意，开启 Refresh Token。回调地址是 `base_url` + `/callback`，登出回调是 `base_url` + `/`。测试会在 `base_url` 的主机和端口上启动示例 `login-fiber` |
| `provider` | 一个服务提供方应用，编码 `order`（示例使用权限代码 `order.read`、`order.write`）。两项权限的适用主体都勾选系统调用和用户委托。`introspection` 是登记在这个应用上、可内省它的 Token 的服务凭证 |
| `caller_secret` | 一个 `client_secret_basic` 服务凭证：对 `order` 有 `order.read`、`order.write` 的系统调用授权，对 `other_resource` 有任意一项权限的授权 |
| `caller_key` | 一个 `private_key_jwt` 服务凭证：对 `order` 有 `order.read`、`order.write` 的系统调用授权 |
| `other_resource`、`no_grant_resource` | 另外两个服务提供方应用，各定义一项权限。后者不配置任何授权 |
| `tokens.user_delegated` | 上面的 OIDC 应用代表测试用户取得的、面向 `order` 的用户委托 Token（`order.read order.write`）。需要一条“用户委托”授权 |
| `allow_insecure` | Issuer 和测试用的地址是 http 时设为 true（一次性的测试环境） |

可选字段：

- `provider.sample_rs_url`：IAM 的示例资源服务，受众是 `provider.resource`，`GET /items` 要求 `order.read`（系统调用、用户委托），`GET /items/write` 要求 `order.write`（系统调用）。没有时跳过 `TestSameVerdictAsIAM`。
- `control_url`：操作员，见下。

## 操作员

有些步骤要由人来做：用户在浏览器里登录和确认退出，管理员激活新的签名密钥。自动化运行时由一个 HTTP 服务代替人完成，夹具的 `control_url` 指向它。请求和响应都是 JSON：

| 请求 | 请求体 | 响应 | 含义 |
| --- | --- | --- | --- |
| `POST /user-agent/authorize` | `{"browser": "<名字>", "url": "<授权地址>", "username": "<登录名>"}` | `{"location": "<IAM 重定向到的地址>"}` | 名为 `browser` 的浏览器打开授权地址，用户登录并同意。同名的浏览器共享 IAM 的登录会话 |
| `POST /user-agent/logout` | `{"browser": "<名字>", "url": "<登出地址>"}` | `{"location": "<IAM 重定向到的地址，可能为空>"}` | 用户打开登出地址并确认退出 |
| `POST /signing-keys/rotate` | `{}` | `{"kid": "<新密钥的 kid>"}` | 管理员生成并激活一把新的签名密钥 |

## 由 IAM 工程运行

IAM 工程自带这个操作员和全部登记：它的端到端测试里有一个互操作场景，启动一套临时的 IAM、建好上表的数据、写出夹具文件，然后在 SDK 的目录里运行 `go test -tags e2e ./e2e/...`。在 IAM 工程的 `backend/` 目录下：

```bash
make e2e-sdk SDK_DIR=/path/to/iam-go-sdk
```

这是 `make e2e` 在开发环境里的常用跑法；发布前对已部署的 IAM 做验收时，按上一节手工登记并编写夹具文件。
