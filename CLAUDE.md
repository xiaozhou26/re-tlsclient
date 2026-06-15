# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`xiaozhou26/re-tlsclient` — a Go library for making HTTP requests with browser-realistic TLS fingerprints. It impersonates real browser TLS handshakes (JA3/JA4 fingerprints, HTTP/2 settings order, pseudo-header order) so requests are indistinguishable from actual browsers.

## Common Commands

```bash
# Build the library
go build ./...

# Run all tests (integration tests hit live endpoints)
go test ./tests/ -v

# Run a single test by name
go test ./tests/ -run TestName -v

# Run only unit tests in root package
go test ./... -run TestInt64ToInt

# Run tests for a specific area
go test ./tests/ -run TestJa3 -v                    # JA3 fingerprint tests
go test ./tests/ -run TestConfig -v                  # Config validation tests
go test ./tests/ -run TestHeader -v                  # Header order tests

# Build CFFI shared library (cross-platform)
cd cffi_dist && bash build.sh
```

## Architecture

### Package Layout

- **Root (`package tls_client`)** — the library itself. All public API lives here.
- **`profiles/`** — browser fingerprint profiles (80+ profiles: Chrome, Firefox, Safari, Edge, Opera, OkHttp). `ClientProfile` struct bundles TLS ClientHelloID, HTTP/2+3 settings, pseudo-header order, and connection flow control.
- **`bandwidth/`** — `BandwidthTracker` interface and implementations for tracking read/write bytes.
- **`cffi_src/`** — CFFI bridge layer. Converts JSON input into Go types, manages client sessions.
- **`cffi_dist/`** — CGo shared library (`-buildmode=c-shared`) with exported C functions (`request`, `destroySession`, etc.). Includes `build.sh` for cross-compilation and example consumers in Python, Node.js, C#, TypeScript.
- **`tests/`** — integration tests (separate `tests` package). Most tests hit live TLS fingerprint-checking endpoints.

### Core Flow

1. **Client creation**: `NewHttpClient(logger, ...options)` → applies functional options (`With*` functions from `client_options.go`) → builds `httpClientConfig` → `buildFromConfig` creates the `httpClient` wrapping a custom `http.Client`.

2. **Request execution**: `Do(req)` → runs pre-request hooks → delegates to `roundTripper.RoundTrip()`.

3. **TLS fingerprinting** (`roundtripper.go`): The `roundTripper` performs TLS handshakes via `utls.UClient` using the selected browser profile's `ClientHelloSpec`. It negotiates HTTP/2 or HTTP/3 via ALPN, caches connections/transports, and optionally races protocols via `protocolRacer` (Chrome-like Happy Eyeballs: H3 starts immediately, H2 delayed 300ms).

4. **Proxy support** (`connect.go`): `directDialer`, `connectDialer` (HTTP CONNECT), SOCKS4/SOCKS5 dialers with HTTP/1.1 and HTTP/2 CONNECT tunnel support.

### Key Design Patterns

- **Functional options**: All configuration uses `HttpClientOption` (`func(config *httpClientConfig)`) with `With*` constructors in `client_options.go`.
- **Profile system**: `profiles.MappedTLSClients` maps `HttpClientProfileID` constants to `ClientProfile` structs. Each profile bundles TLS + HTTP/2 + HTTP/3 fingerprint data. The default profile is `Chrome_147`.
- **JA3/JA4**: `ja3.go` converts JA3 strings to `tls.ClientHelloSpec` factories. `ja4.go` computes JA4 fingerprints from JA3 specs.
- **Hook system**: `PreRequestHookFunc` and `PostResponseHookFunc` allow intercepting the request lifecycle. Return `ErrContinueHooks` for non-fatal errors.
- **CFFI session management**: `cffi_src/factory.go` maintains a global map of client sessions keyed by UUID. All CFFI functions accept/return JSON strings via `*C.char`.

### Key Dependencies (custom forks)

- `github.com/bogdanfinn/fhttp` — HTTP client/server with HTTP/2 settings order control
- `github.com/bogdanfinn/utls` — uTLS for custom TLS ClientHello construction
- `github.com/bogdanfinn/quic-go-utls` — QUIC with uTLS integration
- `github.com/bogdanfinn/websocket` — WebSocket with TLS fingerprint preservation

### Mapper Tables

`mapper.go` contains string-to-TLS-constant maps used by JA3 parsing and CFFI: `H2SettingsMap`, `H3SettingsMap`, `tlsVersions`, `signatureAlgorithms`, `curves`, etc. These are the authoritative lookup tables for translating human-readable names to numeric TLS parameters.

## Testing Notes

- Tests in `tests/` are integration tests that make real HTTP requests to external endpoints (e.g., TLS fingerprint checking services). They require network access.
- `tests/client_test_utils.go` contains shared test helpers and the test client factory pattern.
- `tests/config_validation_test.go` has pure unit tests that don't need network.
- Test assertions use `github.com/stretchr/testify`.
