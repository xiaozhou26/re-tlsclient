# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A Go HTTP client fingerprint library. Each browser package (`chrome/`, `edge/`, `firefox/`, `opera/`, `safari/`, `okhttp/`) wraps `bogdanfinn/tls-client` (which itself wraps `bogdanfinn/fhttp`) with pre-baked `ClientHelloSpec` + HTTP/2 SETTINGS frame + UA / `sec-ch-ua*` header sets that match a real browser, byte-for-byte. Profiles are sourced from `.sources/wreq-util/src/emulate/profile/<browser>.rs` — treat that directory as the source of truth and the Go files in each package as a transcription of it.

This is **not** a `net/http` replacement. Outgoing requests must be built with `fhttp.NewRequest` and executed with `client.Do(req)`. If you write code using `http.NewRequest` the fingerprint pipeline will silently misbehave.

## Build / run

```bash
go build ./...
go run ./cmd/test -target=https://chatgpt.com/                     # exercise all 6 profiles
go run ./cmd/test -target=https://tls.peet.ws/api/all -profile=chrome -body=false
go run ./cmd/test -target=https://chatgpt.com/ -profile=edge -version=V148 -platform=MacOS
```

There are no unit tests. The verification harness is `cmd/test` — it hits a real URL with each profile and reports status / time / proto / `cf-ray`. A 403 with "Just a moment..." in the body = Cloudflare challenge = fingerprint rejected. `tls.peet.ws/api/all` is the diagnostic target for inspecting the actual JA3/JA4/HTTP2 fingerprint emitted.

## Per-package API (uniform across all 6)

Every browser package exposes the same surface. Substitute `chrome` for any other browser name:

```go
client, err := chrome.NewClient(chrome.V148, chrome.MacOS)  // (version, platform)
h, err    := chrome.HeadersFor(chrome.V148, chrome.MacOS)   // fhttp.Header
chrome.ApplyHeaders(req, chrome.V148, chrome.MacOS)         // pin headers onto a request
prof      := chrome.Profile()                               // raw tls_client.ClientProfile
ua        := chrome.MacOSHeaders["user-agent"]              // per-platform header table
```

`okhttp` is the odd one out — mobile-only, no `Platform` arg: `okhttp.NewClient(okhttp.V5)`.

## Architecture: how the 5 functions fit together

1. **`NewClient`** is the entry point. It calls `headersFor(v, p)`, then constructs a `tls_client.HttpClient` with `WithClientProfile(Profile())` + `WithRandomTLSExtensionOrder()` + `WithDefaultHeaders(...)`. The default-headers set covers only the fingerprint-sensitive keys (`sec-ch-ua*`, `user-agent`, `accept`, `accept-encoding`, `accept-language`) — NOT `sec-fetch-*` or `priority`, which the caller may want to vary per request.

2. **`Profile()`** returns a `profiles.ClientProfile`. The interesting parts:
   - `ClientHelloID` — every package reuses a string like `"Chrome_v148_Custom"` so the wire-format is identical across versions; the `specFactory` produces the actual spec.
   - `Settings` / `SettingsOrder` — HTTP/2 SETTINGS frame keys + the order tls-client emits them. **Order matters** for the fingerprint; the four settings blocks (Chrome/Edge/Firefox/Opera) all set the same 4 keys but in different orderings.
   - `PseudoHeaderOrder` — `[":method", ":authority", ":scheme", ":path"]` for Chrome/Edge/Opera. Firefox uses a different order.
   - `ConnectionFlow` — 15728640 for the Chrome stack.
   - The `http3*` params are all nil/0/false; this library only does HTTP/2 over TLS.

3. **`specFactory`** is where most of the fingerprint work lives. It returns a `utls.ClientHelloSpec` with `CipherSuites`, `CompressionMethods`, and `Extensions` arrays built by hand to match wreq's `tls_options!(N, ...)` macro output. Things to know when editing:
   - `permute_extensions=true` (the default in modern profiles) is achieved globally via `WithRandomTLSExtensionOrder()` on the client — but the spec still needs a `&utls.UtlsGREASEExtension{}` at position 0 as a valid prefix for the shuffle.
   - GREASE placeholders appear in `CipherSuites[0]`, the supported-curves / supported-versions / key-share indices, and a final trailing `UtlsGREASEExtension` at the end of `Extensions`.
   - `enable_ech_grease=true` is a separate `utls.BoringGREASEECH()` extension — don't omit it; the master commit that passes chatgpt.com includes it.
   - `alps_use_new_codepoint=true` (Chrome / Edge) → `ApplicationSettingsExtensionNew`. Opera / Firefox use `alps_use_new_codepoint=false` → `ApplicationSettingsExtension` (not New).
   - `pre_shared_key=true` → `PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}}`.

4. **`ApplyHeaders`** exists because `WithDefaultHeaders` only fills in *missing* headers — it does not overwrite. So a request that already has a `User-Agent` (e.g. set by `fhttp` defaults) will keep it. Call `ApplyHeaders(req, v, p)` on every request before `client.Do(req)` if you want to guarantee the pinned header set. `cmd/test` does this via an interface assertion — see the `headerApplyingClient` wrapper in `cmd/test/test.go`.

5. **Header tables** (`WindowsHeaders`, `MacOSHeaders`, etc.) are exported as `fhttp.Header` maps. The Version constant selects which UA / `sec-ch-ua` strings to use; the Platform constant selects which row. **The TLS / HTTP/2 fingerprint is identical across all (version, platform) combinations within a single browser package** — only the headers change.

## Adding a new browser version

1. Find the version's `mod_generator!` block in `.sources/wreq-util/src/emulate/profile/<browser>.rs` — copy the `header_initializer_with_zstd_priority` (or equivalent) UA / `sec-ch-ua*` strings verbatim.
2. Add the `Version` constant.
3. Add a `<Browser><Version><Platform>Headers` `fhttp.Header` literal, plus a case in `headersFor` and a row in the per-platform header table if it's a new version of an existing platform.
4. If the wreq block changes the TLS/HTTP2 stack (e.g. new `tls_options!` constants), update `specFactory`, `Profile()` settings order, and `ConnectionFlow` accordingly. If only the header set changed, no TLS work needed.
5. Verify with `go run ./cmd/test -target=https://tls.peet.ws/api/all -profile=<browser> -version=<new> -platform=<p> -body=false` and compare the `ja4` / `h2` fingerprint to a real browser capture.

## Common recipes

- **Proxy** — `tls-client` has no runtime proxy setter. Build the client yourself with `tls_client.WithProxyUrl(proxy)` alongside `WithClientProfile(<browser>.Profile())` and `WithDefaultHeaders(<browser>.MacOSHeaders)`. See README "Common recipes" section A.
- **Custom timeout** — `tls_client.WithTimeout(seconds)`.
- **brotli / zstd decoding** — `fhttp` decodes automatically only if the decoder package is in `go.mod`. Already present here: `github.com/andybalholm/brotli`. Add `_ "github.com/klauspost/compress/zstd"` for zstd. Without these, bodies are still readable, just not decoded.
- **Stable JA3** — `WithRandomTLSExtensionOrder()` is on by default, so `ja3_hash` changes per request (matches a real browser). `ja4` is stable because it's sorted. To get byte-stable JA3, switch to `WithDisableRandomTLSExtensionOrder()` and re-test — the fingerprint may then differ from real Chrome.
