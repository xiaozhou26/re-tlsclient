# re-tlsclient

A Go library for making HTTP requests with browser-realistic TLS fingerprints.

Forked from [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client), with fingerprints ported from [wreq-util](https://github.com/0x676e67/wreq-util).

### What is TLS Fingerprinting?

Servers can detect which browser/client is making a request by inspecting the TLS ClientHello message — this is called TLS Fingerprinting. Simply changing the User-Agent header is not enough. This library lets you mimic real browser TLS handshakes (JA3/JA4 fingerprints, HTTP/2 settings order, pseudo-header order, extension permutation) so your requests are indistinguishable from actual browsers.

### Features

- ✅ **HTTP/1.1, HTTP/2, HTTP/3** — Full protocol support with automatic negotiation
- ✅ **Protocol Racing** — Chrome-like "Happy Eyeballs" for HTTP/2 vs HTTP/3
- ✅ **TLS Fingerprinting** — 99+ browser profiles: Chrome, Firefox, Safari, Edge, Opera, OkHttp
- ✅ **JA3/JA4 Fingerprint Computation** — Compute and validate fingerprints
- ✅ **HTTP/3 Fingerprinting** — Accurate QUIC/HTTP/3 fingerprints
- ✅ **WebSocket Support** — Maintain TLS fingerprinting over WebSocket connections
- ✅ **Custom Header Ordering** — Control the order of HTTP headers
- ✅ **Proxy Support** — HTTP CONNECT, SOCKS4, SOCKS5 proxies
- ✅ **Cookie Jar Management** — Built-in cookie handling
- ✅ **Certificate Pinning** — Enhanced security with custom certificate validation
- ✅ **Bandwidth Tracking** — Monitor upload/download bandwidth
- ✅ **Hook System** — Pre-request and post-response hooks
- ✅ **Language Bindings** — Use from JavaScript (Node.js), Python, C#, TypeScript via FFI

### Install

```bash
go get xiaozhou26/re-tlsclient
```

### Quick Usage

```go
package main

import (
	"fmt"
	"io"
	"log"

	http "github.com/bogdanfinn/fhttp"
	tls_client "xiaozhou26/re-tlsclient"
	"xiaozhou26/re-tlsclient/profiles"
)

func main() {
	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(profiles.Chrome_147),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		log.Println(err)
		return
	}

	req, err := http.NewRequest(http.MethodGet, "https://tls.peet.ws/api/all", nil)
	if err != nil {
		log.Println(err)
		return
	}

	req.Header = http.Header{
		"accept":          {"*/*"},
		"accept-language": {"de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"},
		"user-agent":      {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"},
		http.HeaderOrderKey: {
			"accept",
			"accept-language",
			"user-agent",
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()

	log.Println(fmt.Sprintf("status code: %d", resp.StatusCode))

	readBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println(string(readBytes))
}
```

### Available Browser Profiles

| Browser | Versions | Count |
|---------|----------|-------|
| Chrome | 100-148 | 31 |
| Edge | 131-148 | 16 |
| Safari | 18.x, 26.x (macOS + iOS) | 8 |
| Firefox | 109-151 | 17 |
| OkHttp | 4, 5 | 2 |
| Opera | 116-131 | 16 |

Use via `profiles.MappedTLSClients["chrome_147"]` or directly as `profiles.Chrome_147`.

### Architecture

```
├── *.go                  # Main library (package tls_client)
├── profiles/             # Browser fingerprint profiles (wreq-based)
├── bandwidth/            # Bandwidth tracking
├── cffi_src/             # CFFI bridge layer
├── cffi_dist/            # Shared library build + examples (Python, Node, C#, TS)
├── tests/                # Integration tests
└── example/              # Go usage examples
```

### Credits

- Original work: [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client)
- Fingerprint data: [wreq-util](https://github.com/0x676e67/wreq-util)
- TLS engine: [bogdanfinn/utls](https://github.com/bogdanfinn/utls) (fork of [refraction-networking/utls](https://github.com/refraction-networking/utls))
- HTTP/2: [bogdanfinn/fhttp](https://github.com/bogdanfinn/fhttp)
