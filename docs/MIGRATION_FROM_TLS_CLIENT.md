# 从 `github.com/bogdanfinn/tls-client` 迁移到 `re-tlsclient`

> 适用对象：已经在用 [`bogdanfinn/tls-client`](https://github.com/bogdanfinn/tls-client)（`tls_client.HttpClient` + `tls_client.NewHttpClient(...)`）的 Go 项目，想换成 `re-tlsclient` 拿到更顺手的 API、80+ 自填 profile（覆盖到 Chrome 148 / Edge 148 / Firefox 151 / Safari 26.4 / Opera 131 / OkHttp 5）以及反向代理 + WebSocket 反代 + 严格指纹模式等开箱即用能力。

本文用对照表 + 例子给你展示怎么改。

---

## 1. 一句话总结差异

| 维度 | `bogdanfinn/tls-client` | `re-tlsclient` |
|---|---|---|
| 入口 | `tls_client.NewHttpClient(logger, opts...)` | `fp.NewClient(ctx, fp.ClientOption{...})` |
| `ctx` 类型 | `context.Context` | `g.Ctx`（`github.com/gogf/gf/v2/frame/g`，是 `context.Context` 的薄包装，可直接 `g.Ctx(ctx)` 转换） |
| Request 构造 | 用户自己 `http.NewRequest` 后 `client.Do(req)` | 内置 `Get / Post / DO`，也支持外部 `Do(*http.Request)` |
| Header / 顺序 | 需要用户自己控制 | `DefaultHeaders()` + `ApplyHeaderOrdering()` 自动按 spec 排序 |
| Cookie | 内部默认 `CookieJar{}`（不持久） | `jar.NewJar()` + `SetCookiesByMap` / `Clear` |
| 代理 | `WithProxyUrl(...)` | `ClientOption.Proxy`（创建时）+ `RequestOption.Proxy`（单次临时代理自动还原） |
| WebSocket | `tls_client.NewWebsocket(...)` 之后 `ws.Connect(ctx)` | `Client.NewWebsocket(ctx, url, option)`，**单步**完成 |
| WebSocket 反代 | ❌ | ✅ `Client.WebsocketProxy(ctx, upstreamURL)` |
| 反向代理 Transport | 需自己写 `RoundTrip` 把 `net/http.Request` ↔ `fhttp.Request` 互转 | `transport.New(c)` 一个调用 |
| 严格指纹模式 | ❌（要自己撸） | ✅ `ClientOption.StrictFingerprint` + `PassthroughHeaders` 白名单 |
| 响应头级超时 | ❌（要么总超时、要么不限） | ✅ `ClientOption.ResponseHeaderTimeoutSeconds` |
| 单一请求自动重试 | ❌ | ✅ `RequestOption.MaxRetry` |
| 内置 profile 池 | ~70 个（Chrome 103~146、Firefox 102~148、Safari iOS 15~26、OkHttp 4.x 等） | 70 个**内置** + **80+ 自填**（Chrome 132~148、Edge 122~148、Firefox 142~151、Safari 16.5~26.4、Opera 116~131、OkHttp 3.x/5） |
| `goSpiderSpec` 字符串支持 | ❌ | ✅ `ClientOption.Spec` 字段（`spec` 子包提供解析/构建） |

---

## 2. 项目结构（5 个子包）

`re-tlsclient` 不是单包，而是一个**模块化的 5 子包项目**。你按需 import：

| 子包 | import 路径 | 提供什么 | 典型场景 |
|---|---|---|---|
| `fp` | `github.com/xiaozhou26/re-tlsclient/fp` | `Client` / `NewClient` / `Get` / `Post` / `DO` / `NewWebsocket` / `WebsocketProxy` | 业务主入口，几乎所有人都会 import |
| `profile` | `github.com/xiaozhou26/re-tlsclient/profile` | `GetExtraProfile(name)` / `ListExtraProfileNames()` / `ExtraProfiles`（80+ 自填 profile 映射） | 直接按名字取一个 `profiles.ClientProfile` 给 `tls-client` 用 |
| `spec` | `github.com/xiaozhou26/re-tlsclient/spec` | `ParseGoSpiderSpec(s)` / `BuildProfile(s)` / `IsGREASE` | 处理 `TLS_HEX@H1_HEX@H2_HEX` 字符串；通常通过 `ClientOption.Spec` 间接用 |
| `jar` | `github.com/xiaozhou26/re-tlsclient/jar` | `Jar` / `NewJar()` / `SetCookiesByMap` / `Clear` | 需要在请求间共享 / 预置 cookie 时 |
| `transport` | `github.com/xiaozhou26/re-tlsclient/transport` | `FingerprintTransport` / `New(c, manageCookies...)` | 把 client 挂到 `httputil.ReverseProxy.Transport` |

**依赖图**（无环）：

```
  tests
   ↓
   fp  ←—— transport
   ↓ ↑         ↑
 profile  jar  spec
```

---

## 3. 改 `go.mod` 依赖

```diff
 require (
-    github.com/bogdanfinn/tls-client v1.15.1
+    re-tlsclient v1.0.6
 )

 require (
+    github.com/bogdanfinn/tls-client v1.15.1   // indirect
+    github.com/bogdanfinn/fhttp v0.6.8        // indirect
+    github.com/bogdanfinn/utls v1.7.7-barnius // indirect
+    github.com/bogdanfinn/websocket v1.5.5-barnius // indirect
+    github.com/gogf/gf/v2 v2.10.0             // indirect
+    github.com/gorilla/websocket v1.5.3       // indirect
+    golang.org/x/crypto v0.46.0               // indirect
+    golang.org/x/net v0.48.0                  // indirect
 )
```

如果是本地 path 替换：

```go
// go.mod
require re-tlsclient v1.0.6

replace re-tlsclient => ../re-tlsclient
```

`go mod tidy` 之后 `tls-client` / `fhttp` / `utls` 等会自动变成 `// indirect`（因为你不再直接 import 它们，而是通过 `re-tlsclient`）。

---

## 4. 代码对照

### 4.1 创建客户端

**`tls-client` 写法**：

```go
package main

import (
    "context"
    "io"

    tls_client "github.com/bogdanfinn/tls-client"
    "github.com/bogdanfinn/tls-client/profiles"
)

func main() {
    jar := tls_client.NewCookieJar()

    client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(),
        tls_client.WithClientProfile(profiles.Chrome_131),
        tls_client.WithTimeoutSeconds(15),
        tls_client.WithCookieJar(jar),
        tls_client.WithProxyUrl("http://127.0.0.1:7890"),
        tls_client.WithInsecureSkipVerify(),
    )
    if err != nil {
        panic(err)
    }
    defer client.CloseIdleConnections()
    _ = context.Background
    _ = io.ReadAll
}
```

**`re-tlsclient` 写法**：

```go
package main

import (
    "context"

    "github.com/gogf/gf/v2/frame/g"
    "github.com/xiaozhou26/re-tlsclient/fp"
    "github.com/xiaozhou26/re-tlsclient/jar"
)

func main() {
    ctx := g.Ctx(context.Background())

    client, err := fp.NewClient(ctx, fp.ClientOption{
        TimeoutSeconds: 15,
        ClientProfile:  "Chrome_131",      // tls-client 内置 PascalCase
        CookieJar:      jar.NewJar(),      // jar 子包
        Proxy:          "http://127.0.0.1:7890",
        // InsecureSkipVerify:  true,     // 见下方"6. 还没覆盖的选项"
    })
    if err != nil {
        panic(err)
    }
    defer client.Close()
}
```

### 4.2 发请求

**`tls-client` 写法**：

```go
req, _ := http.NewRequest("GET", "https://httpbin.org/get", nil)
req.Header.Set("User-Agent", "...")
req.Header.Set("X-Custom", "1")

resp, err := client.Do(req)
if err != nil { /* ... */ }
defer resp.Body.Close()
body, _ := io.ReadAll(resp.Body)
fmt.Println(resp.StatusCode, string(body))
```

**`re-tlsclient` 写法**：

```go
// 简单 GET
resp, err := client.Get(ctx, "https://httpbin.org/get")

// 带 header / 单次代理 / 重试
resp, err := client.Get(ctx, "https://httpbin.org/get", fp.RequestOption{
    Headers:  map[string]string{"X-Custom": "1"},
    Proxy:    "http://127.0.0.1:7890",  // 临时覆盖，结束后自动还原
    MaxRetry: 2,                         // 失败重试 2 次（共 3 次）
})

// POST JSON
resp, err = client.Post(ctx, "https://httpbin.org/post", fp.RequestOption{
    Json:    map[string]any{"name": "alice", "age": 30},
    Headers: map[string]string{"X-Trace": "abc"},
})

// 任意 method（PUT/PATCH/DELETE）
resp, err = client.DO(ctx, "PUT", "https://api.example.com/users/1", fp.RequestOption{
    Json: map[string]any{"name": "bob"},
})
```

### 4.3 反向代理

**`tls-client` 写法**（要手写 RoundTrip）：

```go
type rt struct{ c tls_client.HttpClient }
func (r *rt) RoundTrip(req *http.Request) (*http.Response, error) {
    // 把 net/http.Request 拷到 fhttp.Request，Do 完再拷回来
    // 80 行起步...
}
proxy := &httputil.ReverseProxy{Transport: &rt{c: client}}
```

**`re-tlsclient` 写法**：

```go
import (
    "net/http/httputil"
    "github.com/xiaozhou26/re-tlsclient/fp"
    "github.com/xiaozhou26/re-tlsclient/transport"
)

proxy := &httputil.ReverseProxy{
    Director: func(req *http.Request) {
        req.URL.Scheme = "https"
        req.URL.Host = "target-api.example.com"
        req.Host = "target-api.example.com"
    },
    Transport: transport.New(client),         // 客户端 Cookie 透传，Set-Cookie 也透传
    // Transport: transport.New(client, true), // 由本项目 CookieJar 统一接管
}
http.ListenAndServe(":8080", proxy)
```

> 跟旧版的 `client.Transport(true)` 不一样——`client.Transport()` 已经删了，因为会形成 `fp` ↔ `transport` 循环 import。改用 `transport.New(c, manageCookies...)` 工厂函数。

### 4.4 WebSocket 指纹

**`tls-client` 写法**：

```go
ws, err := tls_client.NewWebsocket(tls_client.NewNoopLogger(),
    tls_client.WithTlsClient(client),
    tls_client.WithUrl("wss://echo.websocket.events"),
    tls_client.WithHeaders(http.Header{
        "Origin": []string{"https://example.com"},
    }),
    tls_client.WithHandshakeTimeoutMilliseconds(8000),
)
if err != nil { panic(err) }
conn, err := ws.Connect(context.Background())
if err != nil { panic(err) }
defer conn.Close()
```

**`re-tlsclient` 写法**：

```go
conn, err := client.NewWebsocket(ctx, "wss://echo.websocket.events", fp.WebsocketOption{
    Headers:            map[string]string{"Origin": "https://example.com"},
    HandshakeTimeoutMs: 8000,
})
if err != nil { panic(err) }
defer conn.Close()
```

### 4.5 WebSocket 反向代理

**`tls-client` 写法**：❌ 没有。

**`re-tlsclient` 写法**：

```go
http.Handle("/ws", client.WebsocketProxy(ctx, "wss://upstream.example.com/ws"))
http.ListenAndServe(":8080", nil)
```

### 4.6 用 goSpiderSpec 字符串

**`tls-client` 写法**：要自己解析。

**`re-tlsclient` 写法**：

```go
// 方式 A：通过 ClientOption.Spec 传（最常用）
client, _ := fp.NewClient(ctx, fp.ClientOption{
    Spec: "TLS_HEX@H1_HEX@H2_HEX",  // goSpiderSpec 格式
})

// 方式 B：自己解析 / 自己构造成 profile 再塞回去
import "github.com/xiaozhou26/re-tlsclient/spec"

spec, _ := spec.ParseGoSpiderSpec(rawSpec)
fmt.Println(spec.TLS.ServerName(), spec.TLS.Protocols())
m := spec.Map()  // map[string]any，便于打印

prof, h, pseudo, order, err := spec.BuildProfile(rawSpec)
_ = prof; _ = h; _ = pseudo; _ = order
```

### 4.7 严格指纹模式（StrictFingerprint + 白名单）

`re-tlsclient` 独有的能力——反代场景下**完全使用 gospec 的 header**覆盖客户端同名项，并通过白名单透传 `Authorization` 等动态 header。

```go
client, _ := fp.NewClient(ctx, fp.ClientOption{
    Spec:              "...",
    StrictFingerprint: true,
    PassthroughHeaders: []string{"Authorization", "X-Custom-Token"},
})
// 之后 transport.New(client) / client.Do / client.NewWebsocket 三条路径都会遵守此模式
```

### 4.8 CookieJar

**`tls-client` 写法**：

```go
jar := tls_client.NewCookieJar()
client, _ := tls_client.NewHttpClient(..., tls_client.WithCookieJar(jar))
// 只能 SetCookies(u, []*fhttp.Cookie) 一条条塞
```

**`re-tlsclient` 写法**：

```go
import "github.com/xiaozhou26/re-tlsclient/jar"

j := jar.NewJar()
j.SetCookiesByMap("https://example.com", map[string]string{
    "session": "xyz",
    "uid":     "1001",
})
client, _ := fp.NewClient(ctx, fp.ClientOption{CookieJar: j})

// 调 j.Clear() 一键清空（tls-client 原生没暴露）
```

### 4.9 直接拿一个 ExtraProfile（绕过 Client）

如果想绕过 `fp.NewClient`、直接拿一个 `profiles.ClientProfile` 喂给 `tls-client`：

```go
import (
    tls_client "github.com/bogdanfinn/tls-client"
    "github.com/xiaozhou26/re-tlsclient/profile"
)

prof, ok := profile.GetExtraProfile("chrome_148")
if !ok { panic("unknown profile") }

client, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(),
    tls_client.WithClientProfile(prof),
)
```

---

## 5. e2e 迁移测试（项目自带）

`tests/migrate_test.go` 是一份**自包含的端到端迁移对照测试**——用 `httptest` 起本地 server，**不依赖外网**。两份写法同时跑，断言行为一致：

```
ok  	github.com/xiaozhou26/re-tlsclient/tests	0.267s
```

包含的子测试：

| 子测试 | 验证什么 |
|---|---|
| `TestMigration_LocalServer/old:tls-client` | 原 `bogdanfinn/tls-client` 写法能跑通（基准线） |
| `TestMigration_LocalServer/new:re-tlsclient` | 本项目 `fp.NewClient + DO` 写法能跑通，UA / Method / Body 一致 |
| `TestMigration_ExtraProfile` | `ExtraProfile: "chrome_148"` 走通 |
| `TestMigration_JarUse` | `jar.SetCookiesByMap` 注入 `Cookie` 头；`Clear` 后不再发 |
| `TestMigration_HeaderOrder` | 默认 header 合并逻辑 |
| `TestMigration_TransportRoundTrip` | `transport.New(c)` 走通 `RoundTrip` 到本地 server |

跑：

```bash
go test ./tests/...
```

直接复制 `migrate_test.go` 作为你项目里的回归测试也行。

---

## 6. 还没覆盖到的 `tls-client` 选项

`re-tlsclient` 是 `tls-client` 之上的**业务封装**，没把 `tls-client` 全部 option 暴露出来。下表是已知还没直接对应的——多数都能通过 `Spec` 字符串或改 `fp/client.go` 加上。

| `tls-client` option | `re-tlsclient` 对应 | 备注 |
|---|---|---|
| `WithTimeoutSeconds(n)` | `ClientOption.TimeoutSeconds` | ✅ |
| `WithResponseHeaderTimeoutSeconds(n)` | `ClientOption.ResponseHeaderTimeoutSeconds` | ✅；`re-tlsclient` 默认就是只对"响应头"限时 |
| `WithRandomTLSExtensionOrder()` | **始终开启** | 强制 |
| `WithForceHttp1()` | `ClientOption.ForceHttp1` | ✅ |
| `WithNotFollowRedirects()` | `ClientOption.NotFollowRedirects` | ✅ |
| `WithCookieJar(jar)` | `ClientOption.CookieJar` | ✅ 接受 `*jar.Jar`（包装过的） |
| `WithProxyUrl(url)` | `ClientOption.Proxy` | ✅ |
| `WithInsecureSkipVerify()` | ⚠️ 暂未暴露 | 待加；目前要绕过证书校验请自己 fork |
| `WithDebug()` | `ClientOption.Debug` | ✅ |
| `WithDefaultHeaders(h)` | `ClientOption.DefaultHeaders` | ✅ |
| `WithClientProfile(p)` | `ClientOption.ClientProfile`（PascalCase） | ✅ |
| ❌ | `ClientOption.ExtraProfile` | ✅ `re-tlsclient` 独有的 80+ 自填 profile（wreq-util 风格小写名） |
| ❌ | `ClientOption.Spec` | ✅ `re-tlsclient` 独有的 goSpiderSpec 字符串支持 |
| `WithCertificatePins([][]byte)` | ⚠️ 暂未暴露 | 计划下个版本加 |
| `WithTransportOptions(...)` | ❌ | 直接走 `transport.New(c)` 时可定制 |
| `WithWebsocketOptions(...)` | `WebsocketOption` | ✅ |
| `WithClientHelloSpec(...)`（新版） | ⚠️ 暂未暴露 | 要自填 `ClientHelloSpec` 时用 `Spec` 字符串或 `ExtraProfile` |

---

## 7. 常见迁移坑

### 7.1 `ctx` 类型不匹配

`re-tlsclient` 全 API 用 `g.Ctx`（`gogf/gf/v2`），传入 `context.Context` 时要包一层：

```go
import "github.com/gogf/gf/v2/frame/g"

ctx := g.Ctx(context.Background())  // 显式包装
client.Get(ctx, url)                  // 不会拒绝 context.Context，但 g.Ctx 携带 trace
```

不包装也能编译通过——`g.Ctx` 是 `context.Context` 的子类型，但**反过来** `context.Context` 不能直接当 `g.Ctx` 用。

### 7.2 `tls-client` 的 `DefaultClientProfile` 不是 `Chrome_131`

`tls-client` 默认 `Chrome_146`（1.15.1）。`re-tlsclient` 默认 `Okhttp4Android12`——这是个**有意决定**，避免和移动端请求混淆。要还原 tls-client 默认：

```go
client, _ := fp.NewClient(ctx, fp.ClientOption{
    ClientProfile: "Chrome_146",
})
```

### 7.3 反代 Transport 要从 transport 子包取

`client.Transport(...)` 已经是历史了——`fp` 不再 import `transport`（避免循环）。改用：

```go
import "github.com/xiaozhou26/re-tlsclient/transport"

proxy := &httputil.ReverseProxy{
    Transport: transport.New(c),          // 客户端 Cookie 透传
    // Transport: transport.New(c, true), // 由 jar 统一接管
}
```

`manageCookies` 的语义和旧版一致：`false`=客户端 Cookie 透传 + Set-Cookie 透传；`true`=客户端 Cookie 丢弃 + Set-Cookie 屏蔽 + jar 接管。

### 7.4 `WithInsecureSkipVerify` 暂时没暴露

`re-tlsclient` 没在 `ClientOption` 里加这个字段。要跳过证书校验请改 `fp/client.go` 的 `NewClient`，在 `tls_client.NewHttpClient(...)` 之前补一个 `tls_client.WithInsecureSkipVerify()`（要先把 `tls_client.WithInsecureSkipVerify` 放回 `import`）。后续版本会加上。

### 7.5 profile 名大小写

- `ClientOption.ClientProfile`：**PascalCase**（`Chrome_131`、`Okhttp4Android13`）
- `ClientOption.ExtraProfile`：**小写**（`chrome_148`、`firefox_151`、`okhttp_5`）

如果名字写错，`NewClient` 不会报错——它会静默回落到 `Okhttp4Android12` 默认。**写测试断言你拿到的 profile**：

```go
import "github.com/xiaozhou26/re-tlsclient/fp"

spec, _ := client.HttpClient.GetClientHelloSpec()
fmt.Println(len(spec.CipherSuites))  // 期望 >= 5
```

### 7.6 不要再 import `tls-client` 子包

`re-tlsclient` 替你挡住了 `tls-client` / `fhttp` / `utls` 的导出符号。业务代码里再 import `github.com/bogdanfinn/tls-client` 会让"迁移"的意义打折——所有需求都能用 `github.com/xiaozhou26/re-tlsclient/*` 子包覆盖。

唯一例外：直接拿 `profile.ExtraProfiles[name]` 喂给旧代码时（见 4.9）。

---

## 8. 一键迁移检查表

- [ ] 替换 `import "github.com/bogdanfinn/tls-client"` → `import "github.com/xiaozhou26/re-tlsclient/fp"`（按需再 `import "github.com/xiaozhou26/re-tlsclient/jar"` / `transport` / `spec` / `profile`）
- [ ] 改 `tls_client.NewHttpClient(logger, opts...)` → `fp.NewClient(ctx, fp.ClientOption{...})`
- [ ] 把 `context.Background()` 包成 `g.Ctx(context.Background())`
- [ ] 把 `WithClientProfile(profiles.Chrome_131)` → `ClientProfile: "Chrome_131"`
- [ ] 想要更新指纹？把 `ClientProfile` 换成 `ExtraProfile: "chrome_148"`
- [ ] `tls_client.NewCookieJar()` → `jar.NewJar()`，set-cookie 改用 `j.SetCookiesByMap(url, map)`
- [ ] 用 `client.Get / Post / DO` 替换 `http.NewRequest` + `client.Do` 模板
- [ ] 反代场景把 `client.Transport(true)` 替换为 `transport.New(c, true)`，挂到 `httputil.ReverseProxy.Transport`
- [ ] WebSocket 用 `client.NewWebsocket(ctx, url, ...)` 一行
- [ ] WebSocket 反代用 `client.WebsocketProxy(ctx, upstreamURL)` 一行
- [ ] `go mod tidy` 后跑 `go test ./...`（顺带把 `tests/migrate_test.go` 复制过去当回归）
- [ ] 跑通后建议加一个 `TestNewClient_GetClientHelloSpec` 断言 profile 没被静默回落

---

## 9. 反馈

迁移过程中碰到任何问题或想要补的 option，在 issue 里贴 `re-tlsclient` 这个名字 + 子包名（`fp` / `jar` / `transport` / `spec` / `profile`）+ 对应字段名，我看到就回。
