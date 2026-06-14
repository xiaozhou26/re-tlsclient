# Bug: Chrome 147/146 profile 导致 ChatGPT API 请求 unexpected EOF

## 环境

- 库：`github.com/xiaozhou26/re-tlsclient@v1.0.2`
- 对比库：`github.com/bogdanfinn/tls-client@v1.15.0`
- 目标：`https://chatgpt.com/backend-api/f/conversation/prepare`
- 场景：使用 `profiles.Chrome_147` 或 `profiles.Chrome_146` 发送 POST 请求

## 问题描述

使用 `re-tlsclient` 的 `Chrome_147`/`Chrome_146` profile 请求 ChatGPT API 时，服务端直接关闭连接，返回 `unexpected EOF`：

```
Post "https://chatgpt.com/backend-api/f/conversation/prepare": unexpected EOF
```

**同样的请求**，使用 `bogdanfinn/tls-client` 的 `Chrome_146` profile 可以正常工作（200 OK）。

## 根因分析

对比两个库的 `Chrome_146`/`Chrome_147` profile 的 TLS ClientHello 扩展顺序，发现 **3 处关键差异**：

### 差异 1：缺少 `GenericExtension{Id: 0xca34}` (trust_anchors)

| | bogdanfinn/tls-client (正常) | re-tlsclient (异常) |
|---|---|---|
| 0xca34 | ✅ `&tls.GenericExtension{Id: 0xca34, Data: []byte{0x00, 0x00}}` | ❌ 缺失 |

这是 Chrome 在 [TLSEXT_TYPE_trust_anchors](https://source.chromium.org/search?q=TLSEXT_TYPE_trust_anchors)（extension id `0xca34`），从 Chrome 146 开始引入。Cloudflare/ChatGPT 可能通过该扩展的存在性来校验客户端指纹真实性，缺失会导致指纹不匹配被拒绝。

**位置**：`profiles/wreq_profiles.go` 的 `makeChromeTLSType6()` / `makeChromeTLSType7()`

### 差异 2：TLS 扩展顺序不一致

bogdanfinn/tls-client 的 Chrome_146 扩展顺序（关键片段）：

```
1. UtlsGREASEExtension
2. KeyShareExtension          ← KeyShare 在 SNI 之前
3. SNIExtension
4. ApplicationSettingsExtensionNew
5. RenegotiationInfoExtension
6. SupportedCurvesExtension
7. UtlsCompressCertExtension
8. SessionTicketExtension
9. StatusRequestExtension
10. ExtendedMasterSecretExtension
11. SupportedVersionsExtension ← 在 SignatureAlgorithms 之前
12. SignatureAlgorithmsExtension
13. SCTExtension
14. SupportedPointsExtension   ← 在 ALPN 之前
15. BoringGREASEECH
16. ALPNExtension
17. PSKKeyExchangeModesExtension
18. GenericExtension{0xca34}   ← trust_anchors
19. UtlsGREASEExtension
```

re-tlsclient 的 `makeChromeTLSType6()`/`makeChromeTLSType7()` 扩展顺序：

```
1. UtlsGREASEExtension
2. ApplicationSettingsExtensionNew  ← ALPS 移到最前
3. SupportedVersionsExtension
4. SCTExtension
5. BoringGREASEECH
6. KeyShareExtension          ← KeyShare 移到后面
7. SignatureAlgorithmsExtension
8. SupportedCurvesExtension
9. UtlsCompressCertExtension
10. ExtendedMasterSecretExtension
11. SessionTicketExtension
12. SNIExtension               ← SNI 移到后面
13. RenegotiationInfoExtension
14. PSKKeyExchangeModesExtension
15. SupportedPointsExtension
16. StatusRequestExtension
17. ALPNExtension              ← ALPN 移到后面
18. UtlsGREASEExtension
19. UtlsPreSharedKeyExtension
❌ 缺少 GenericExtension{0xca34}
```

扩展顺序是 JA3/JA4 指纹的核心组成部分。Cloudflare 等 WAF 会检测扩展顺序，顺序不对 = 指纹不匹配 = 请求被拒绝。

### 差异 3：`UtlsPreSharedKeyExtension` vs 缺失 PSK

| | bogdanfinn/tls-client | re-tlsclient |
|---|---|---|
| PSK 扩展 | ❌ 无（Chrome_146 non-PSK profile） | ✅ `&tls.UtlsPreSharedKeyExtension{}` |

re-tlsclient 的 `makeChromeTLSType6()`/`makeChromeTLSType7()` 始终包含 `UtlsPreSharedKeyExtension`，而 bogdanfinn 的非 PSK 版 Chrome_146 不包含此扩展。ChatGPT 可能检测到非 PSK 握手中出现了 PSK 扩展，判定为指纹异常。

## 影响范围

所有使用 `makeChromeTLSType6()` 和 `makeChromeTLSType7()` 构建的 profile 均受影响，包括：

- Chrome_124, Chrome_126 ~ Chrome_148
- 所有 Edge profile（使用 `makeChromeTLSType7`）
- 所有 Opera profile（使用 `makeChromeTLSType7`）

## 建议修复

1. **添加 `GenericExtension{Id: 0xca34}`**：在 `makeChromeTLSType6()`/`makeChromeTLSType7()` 中，`PSKKeyExchangeModesExtension` 之后、最后一个 `UtlsGREASEExtension` 之前添加：
   ```go
   &tls.GenericExtension{Id: 0xca34, Data: []byte{0x00, 0x00}}, // trust_anchors
   ```

2. **修正扩展顺序**：参考 bogdanfinn/tls-client 的 Chrome_146 profile，将 `makeChromeTLSType6()`/`makeChromeTLSType7()` 的扩展顺序调整为与真实 Chrome 一致：
   ```go
   func makeChromeTLSType7(curves []tls.CurveID, keyShares []tls.KeyShare) []tls.TLSExtension {
       return []tls.TLSExtension{
           &tls.UtlsGREASEExtension{},
           &tls.KeyShareExtension{KeyShares: copyKeyShares(keyShares)},
           &tls.SNIExtension{},
           &tls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
           &tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
           &tls.SupportedCurvesExtension{Curves: curves},
           &tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}},
           &tls.SessionTicketExtension{},
           &tls.StatusRequestExtension{},
           &tls.ExtendedMasterSecretExtension{},
           &tls.SupportedVersionsExtension{Versions: []uint16{
               tls.GREASE_PLACEHOLDER, tls.VersionTLS13, tls.VersionTLS12,
           }},
           &tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: chromeSigAlgs},
           &tls.SCTExtension{},
           &tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
           tls.BoringGREASEECH(),
           &tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
           &tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
           &tls.GenericExtension{Id: 0xca34, Data: []byte{0x00, 0x00}}, // trust_anchors
           &tls.UtlsGREASEExtension{},
       }
   }
   ```

3. **移除不应存在的 `UtlsPreSharedKeyExtension`**：在 non-PSK 版本的 profile（如 Chrome_146、Chrome_147）中，不应包含 `UtlsPreSharedKeyExtension`。只有 PSK 版本（如 Chrome_146_PSK）才应包含。可以考虑将 `UtlsPreSharedKeyExtension` 作为参数传入 `makeChromeTLSType6()`/`makeChromeTLSType7()`，由调用方决定是否添加。

## 验证方法

```go
package main

import (
    "fmt"
    "io"
    "net/http"

    tls_client "github.com/xiaozhou26/re-tlsclient"
    "github.com/xiaozhou26/re-tlsclient/profiles"
    fhttp "github.com/bogdanfinn/fhttp"
)

func main() {
    client, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(),
        tls_client.WithClientProfile(profiles.Chrome_147),
        tls_client.WithTimeoutSeconds(30),
    )

    req, _ := fhttp.NewRequest(fhttp.MethodPost,
        "https://chatgpt.com/backend-api/f/conversation/prepare",
        strings.NewReader(`{}`))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36")
    req.Header.Set("Accept", "*/*")
    req.Header.Set("oai-language", "en-US")
    req.Header.Set("origin", "https://chatgpt.com")
    req.Header.Set("referer", "https://chatgpt.com/")

    resp, err := client.Do(req)
    if err != nil {
        fmt.Println("ERROR:", err) // 修复前: unexpected EOF
        return
    }
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    fmt.Println("Status:", resp.StatusCode)
    fmt.Println("Body:", string(body[:200]))
}
```

修复前输出：`ERROR: Post "...": unexpected EOF`
修复后期望：`Status: 401` 或 `Status: 200`（取决于是否带有效 token）
