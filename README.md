# re-tlsclient

Go HTTP client fingerprint library for Chrome / Edge / Firefox / Opera / Safari / OkHttp. Each browser profile is a drop-in `tls_client.HttpClient` whose TLS ClientHello and HTTP/2 SETTINGS frame are byte-for-byte the same as the real browser (sourced from [wreq-util/src/emulate/profile/chrome.rs](https://github.com/xacnio/wreq-util) mod_generator! blocks).

This is **not** a `net/http` replacement — it wraps [`github.com/bogdanfinn/tls-client`](https://github.com/bogdanfinn/tls-client), which wraps [`github.com/bogdanfinn/fhttp`](https://github.com/bogdanfinn/fhttp). Requests must be built with `fhttp.NewRequest` and executed with `client.Do(req)`.

## Quick start

```bash
go get github.com/xiaozhou26/re-tlsclient
```

```go
package main

import (
    "fmt"
    "io"

    fhttp "github.com/bogdanfinn/fhttp"
    "github.com/xiaozhou26/re-tlsclient/chrome"
)

func main() {
    // 1. Build a client. Version + platform select the UA / sec-ch-ua
    //    strings; the TLS / HTTP/2 fingerprint is the same.
    client, err := chrome.NewClient(chrome.V148, chrome.MacOS)
    if err != nil {
        panic(err)
    }

    // 2. Build the request with fhttp, not net/http. fhttp is what
    //    tls-client's transport is built on top of.
    req, err := fhttp.NewRequest(fhttp.MethodGet, "https://chatgpt.com/", nil)
    if err != nil {
        panic(err)
    }

    // 3. Pin the profile's header set onto the request. Without this
    //    the transport falls back to "Go-http-client/2.0" UA and the
    //    server-side fingerprint detector sees a mismatched browser.
    chrome.ApplyHeaders(req, chrome.V148, chrome.MacOS)

    // 4. Send it.
    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    fmt.Println("status:", resp.StatusCode)
    body, _ := io.ReadAll(resp.Body)
    fmt.Println("body:", string(body[:min(200, len(body))]))
}
```

## Available profiles

| Package import | Browser | Version constants | Platform constants |
|---|---|---|---|
| `github.com/xiaozhou26/re-tlsclient/chrome` | Chrome 147 / 148 | `chrome.V147`, `chrome.V148` | `Windows`, `MacOS`, `Linux`, `Android`, `IOS` |
| `github.com/xiaozhou26/re-tlsclient/edge` | Microsoft Edge 148 | `edge.V148` (and V134–V148 for compatibility) | `Windows`, `MacOS`, `Linux`, `Android`, `IOS` |
| `github.com/xiaozhou26/re-tlsclient/firefox` | Firefox 135 / 142 / 148 / 151 | `firefox.V135`, `firefox.V142`, `firefox.V148`, `firefox.V151` | `Windows`, `MacOS`, `Linux`, `Android`, `IOS` |
| `github.com/xiaozhou26/re-tlsclient/opera` | Opera 116 / 131 | `opera.V116`, `opera.V131` | `Windows`, `MacOS` |
| `github.com/xiaozhou26/re-tlsclient/safari` | Safari 26.0 / 26.2 | `safari.V26_0`, `safari.V26_2` | `MacOS`, `IOS` |
| `github.com/xiaozhou26/re-tlsclient/okhttp` | OkHttp 3.9 / 4.x / 5 | `okhttp.V3_9`, `okhttp.V4_12`, `okhttp.V5` | — (mobile-only) |

## Per-package API

Every profile package exposes the same six functions. Replace `chrome` with `edge` / `firefox` / `opera` / `safari` (and drop the platform arg for `okhttp`):

```go
// Build a pre-configured client. ApplyHeaders() is then a no-op
// because tls-client injects these headers as defaults.
client, err := chrome.NewClient(chrome.V148, chrome.MacOS)

// Look up the per-(version, platform) header set without building a
// client — useful when you only want to inspect the UA / sec-ch-ua.
h, err := chrome.HeadersFor(chrome.V148, chrome.MacOS)
_ = h // fhttp.Header

// Pin the header set onto an already-built request. Needed when
// reusing a long-lived client across many requests with different
// profiles, or when the request carried its own header set that
// needs to be overridden.
chrome.ApplyHeaders(req, chrome.V148, chrome.MacOS)

// Get the raw tls_client.ClientProfile (h2 SETTINGS, ClientHelloSpec,
// pseudo-header order, etc.) if you want to compose it into your
// own tls_client.HttpClient.
prof := chrome.Profile()

// (Chrome / Edge / Firefox / Safari / Opera only)
// Per-(version, platform) header table as a plain fhttp.Header.
ua := chrome.MacOSHeaders["user-agent"]
```

`okhttp` is the odd one out — it's a mobile-only profile, so there is no `Platform` arg:

```go
client, err := okhttp.NewClient(okhttp.V5)
okhttp.ApplyHeaders(req, okhttp.V5)
```

## Common recipes

### A. Proxy support

`tls_client` does not expose a runtime proxy setter. Use `WithProxyUrl` when building the client yourself:

```go
import (
    tls_client "github.com/bogdanfinn/tls-client"
    "github.com/xiaozhou26/re-tlsclient/chrome"
)

func newProxiedClient(proxy string) (tls_client.HttpClient, error) {
    return tls_client.NewHttpClient(
        tls_client.NewNoopLogger(),
        tls_client.WithClientProfile(chrome.Profile()),
        tls_client.WithRandomTLSExtensionOrder(),
        tls_client.WithProxyUrl(proxy),
        tls_client.WithDefaultHeaders(chrome.MacOSHeaders), // pick a platform
    )
}
```

### B. Custom timeout

```go
client, _ := tls_client.NewHttpClient(
    tls_client.NewNoopLogger(),
    tls_client.WithClientProfile(chrome.Profile()),
    tls_client.WithRandomTLSExtensionOrder(),
    tls_client.WithTimeout(30), // seconds
    tls_client.WithDefaultHeaders(chrome.MacOSHeaders),
)
```

### C. Cookie jar / follow redirects

`tls_client` supports both. Wrap your own `fhttp.Client` around the profile's transport if you need `http.Client`-shaped behavior.

### D. Compressed response bodies

`fhttp` decodes gzip / deflate / brotli / zstd automatically when the matching import is in your `go.mod`:

```go
import (
    _ "github.com/andybalholm/brotli" // for "br"
    _ "github.com/klauspost/compress/zstd" // for "zstd"
)
```

If you skip these, the response body will still be readable, just not decoded.

## Why this exists

Standard Go `net/http` produces a TLS ClientHello that is trivially distinguishable from any real browser — Cloudflare, Akamai, DataDome, and most anti-bot stacks reject it on the first request. `bogdanfinn/tls-client` lets you set a custom ClientHelloSpec; this library pre-bakes the ClientHelloSpec + HTTP/2 SETTINGS frame + UA / sec-ch-ua / sec-ch-ua-platform header set for 6 real browsers, sourced directly from the [wreq](https://github.com/xacnio/wreq) reference emulation.

The fingerprint sources are under `.sources/wreq-util/src/emulate/profile/` if you want to audit or extend a profile.

## Tested against

- `https://chatgpt.com/` — full chatgpt home page loads, all 6 profiles.
- `https://tls.peet.ws/api/all` — full TLS / HTTP2 fingerprint dump. Use `cmd/test -target=https://tls.peet.ws/api/all` to inspect.

## Build / test

```bash
go build ./...
go run ./cmd/test -target=https://chatgpt.com/                     # all profiles
go run ./cmd/test -target=https://chatgpt.com/ -profile=edge       # one profile
go run ./cmd/test -target=https://chatgpt.com/ -profile=edge -version=V148 -platform=MacOS
go run ./cmd/test -target=https://tls.peet.ws/api/all -profile=chrome -body=false
```

## Caveats

- `WithRandomTLSExtensionOrder()` is on by default (matches the wreq v132 reference). It makes `ja3_hash` change every request, but `ja4` (sorted) is stable. Some bot detectors that key on raw JA3 will see variation — this is the same as a real browser. Disable with `WithDisableRandomTLSExtensionOrder()` if you need byte-stable JA3.
- IP reputation still matters. On datacenter IPs you will see ~95% pass rates; on residential IPs you will see ~100%.
- `tls-client` requires Go 1.21+ (this repo's `go.mod` declares `go 1.26.4`; the actual minimum is dictated by your tls-client version).
