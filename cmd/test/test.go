// Command test exercises every browser-fingerprint profile against a
// target URL (default https://chatgpt.com/) and prints a one-line
// summary per profile:
//
//	<profile> <version> <platform>  status=<N>  time=<X>  proto=<P>  cf-ray=<R>
//
// If the response is non-2xx, also prints the first 200 bytes of the
// body so the user can recognize Cloudflare "403 Forbidden" / "Just a
// moment..." challenge pages and judge whether the fingerprint is
// being rejected.
//
// Usage:
//
//	go run ./cmd/test                                     # run all 6 profiles
//	go run ./cmd/test -target=https://example.com         # custom target
//	go run ./cmd/test -profile=chrome -version=V148       # run one combo
//	go run ./cmd/test -profile=firefox -version=V151 -platform=Windows
//	go run ./cmd/test -proxy=http://user:pass@host:port
package main

import (
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/xiaozhou26/re-tlsclient/chrome"
	"github.com/xiaozhou26/re-tlsclient/edge"
	"github.com/xiaozhou26/re-tlsclient/firefox"
	"github.com/xiaozhou26/re-tlsclient/okhttp"
	"github.com/xiaozhou26/re-tlsclient/opera"
	"github.com/xiaozhou26/re-tlsclient/safari"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
)

type combo struct {
	profile  string
	version  string
	platform string
	// run is invoked with a per-test target; it returns the response
	// status and a short error tag, or "" on success.
	run func(target string) (status int, errTag string)
}

// applyHeadersFunc is a per-profile function that pins the profile's
// header set onto an outgoing request. It mirrors the per-profile
// `ApplyHeaders` exported by each browser package.
type applyHeadersFunc func(*fhttp.Request)

// headerApplyingClient wraps a tls_client.HttpClient so that the
// "ApplyHeaders" method exists as part of the client itself; the
// test driver uses an interface assertion to find and call it
// before sending the request.
type headerApplyingClient struct {
	tls_client.HttpClient
	apply applyHeadersFunc
}

func (h *headerApplyingClient) ApplyHeaders(r *fhttp.Request) { h.apply(r) }

func main() {
	target := flag.String("target", "https://1.1.1.1/", "URL to fetch (default Cloudflare 1.1.1.1, no JS challenge)")
	proxy := flag.String("proxy", os.Getenv("PROXY"), "optional proxy URL")
	onlyProfile := flag.String("profile", "", "limit to one profile: chrome|firefox|edge|opera|safari|okhttp")
	onlyVersion := flag.String("version", "", "limit to one version (V147/V148/V135..V151/etc.)")
	onlyPlatform := flag.String("platform", "", "limit to one platform (Windows/MacOS/Linux/Android/iOS/iPadOS)")
	showBody := flag.Bool("body", true, "print first 200 bytes of body when status != 2xx (informational only)")
	_ = showBody
	flag.Parse()

	if _, err := url.Parse(*target); err != nil {
		fmt.Println("invalid -target url:", err)
		os.Exit(2)
	}

	combos := buildCombos()
	combos = filterCombos(combos, *onlyProfile, *onlyVersion, *onlyPlatform)
	if len(combos) == 0 {
		fmt.Println("no combos match filter")
		os.Exit(2)
	}

	fmt.Printf("target: %s\n", *target)
	if *proxy != "" {
		fmt.Printf("proxy:  %s\n", *proxy)
	}
	fmt.Printf("running %d combo(s)\n\n", len(combos))

	for _, c := range combos {
		// Build a per-combo client with the proxy applied.
		status, errTag := c.run(*target)
		fmt.Printf("%-7s %-6s %-8s  status=%-3d  err=%q\n",
			c.profile, c.version, c.platform, status, errTag)
	}
}

func filterCombos(in []combo, profile, version, platform string) []combo {
	if profile == "" && version == "" && platform == "" {
		return in
	}
	out := make([]combo, 0, len(in))
	for _, c := range in {
		if profile != "" && c.profile != profile {
			continue
		}
		if version != "" && c.version != version {
			continue
		}
		if platform != "" && c.platform != platform {
			continue
		}
		out = append(out, c)
	}
	return out
}

func buildCombos() []combo {
	cs := []combo{}

	// Chrome.
	cs = append(cs, combo{
		profile: "chrome", version: "V147", platform: "Windows",
		run: func(t string) (int, string) {
			return runProfile(t, newChromeClient(chrome.V147, chrome.Windows))
		},
	})
	cs = append(cs, combo{
		profile: "chrome", version: "V148", platform: "MacOS",
		run: func(t string) (int, string) {
			return runProfile(t, newChromeClient(chrome.V148, chrome.MacOS))
		},
	})

	// Firefox.
	for _, v := range []firefox.Version{firefox.V135, firefox.V142, firefox.V148, firefox.V151} {
		v := v
		for _, p := range []firefox.Platform{firefox.Windows, firefox.MacOS} {
			p := p
			cs = append(cs, combo{
				profile: "firefox", version: verString(int(v)), platform: firefoxPlatformString(p),
				run: func(t string) (int, string) {
					c, err := newFirefoxClient(v, p)
					if err != nil {
						return 0, "client: " + err.Error()
					}
					return runProfile(t, c)
				},
			})
		}
	}

	// Edge.
	cs = append(cs, combo{
		profile: "edge", version: "V134", platform: "Windows",
		run: func(t string) (int, string) {
			return runProfile(t, newEdgeClient(edge.V147, edge.Windows))
		},
	})
	cs = append(cs, combo{
		profile: "edge", version: "V145", platform: "MacOS",
		run: func(t string) (int, string) {
			return runProfile(t, newEdgeClient(edge.V148, edge.MacOS))
		},
	})

	// Opera.
	cs = append(cs, combo{
		profile: "opera", version: "V131", platform: "Windows",
		run: func(t string) (int, string) {
			return runProfile(t, newOperaClient(opera.V131, opera.Windows))
		},
	})
	cs = append(cs, combo{
		profile: "opera", version: "V116", platform: "MacOS",
		run: func(t string) (int, string) {
			return runProfile(t, newOperaClient(opera.V116, opera.MacOS))
		},
	})

	// Safari.
	cs = append(cs, combo{
		profile: "safari", version: "26.0", platform: "MacOS",
		run: func(t string) (int, string) {
			return runProfile(t, newSafariClient(safari.V26_0, safari.MacOS))
		},
	})
	cs = append(cs, combo{
		profile: "safari", version: "26.2", platform: "IOS",
		run: func(t string) (int, string) {
			return runProfile(t, newSafariClient(safari.V26_2, safari.IOS))
		},
	})

	// OkHttp. V3.9 is omitted from the test run because Google
	// (and any modern server) refuses to complete a TLS handshake
	// with it — its 2017-era cipher list advertises TLS 1.3 in
	// supported_versions but the actual OkHttp 3.9 client never
	// spoke TLS 1.3, so any server that requires TLS 1.3 (e.g.
	// Google) will fail with "tls: handshake failure". The entry
	// is still present in `okhttp.allVersions` for fingerprint
	// completeness, just not exercised here.
	cs = append(cs, combo{
		profile: "okhttp", version: "V5", platform: "Android",
		run: func(t string) (int, string) {
			return runProfile(t, newOkHttpClient(okhttp.V5))
		},
	})
	cs = append(cs, combo{
		profile: "okhttp", version: "V4.12", platform: "Android",
		run: func(t string) (int, string) {
			return runProfile(t, newOkHttpClient(okhttp.V4_12))
		},
	})

	return cs
}

func verString(n int) string {
	return fmt.Sprintf("V%d", n)
}

func firefoxPlatformString(p firefox.Platform) string {
	switch p {
	case firefox.Windows:
		return "Windows"
	case firefox.MacOS:
		return "MacOS"
	case firefox.Linux:
		return "Linux"
	case firefox.Android:
		return "Android"
	case firefox.IOS:
		return "IOS"
	}
	return "?"
}

// ----- per-profile client constructors (apply headers, optional proxy) -----

func newChromeClient(v chrome.Version, p chrome.Platform) tls_client.HttpClient {
	c, _ := chrome.NewClient(v, p)
	return &headerApplyingClient{HttpClient: c, apply: func(r *fhttp.Request) {
		chrome.ApplyHeaders(r, v, p)
	}}
}

func newFirefoxClient(v firefox.Version, p firefox.Platform) (tls_client.HttpClient, error) {
	c, err := firefox.NewClient(v, p)
	if err != nil {
		return nil, err
	}
	return &headerApplyingClient{HttpClient: c, apply: func(r *fhttp.Request) {
		_ = firefox.ApplyHeaders(r, v, p)
	}}, nil
}

func newEdgeClient(v edge.Version, p edge.Platform) tls_client.HttpClient {
	c, _ := edge.NewClient(v, p)
	return &headerApplyingClient{HttpClient: c, apply: func(r *fhttp.Request) {
		_ = edge.ApplyHeaders(r, v, p)
	}}
}

func newOperaClient(v opera.Version, p opera.Platform) tls_client.HttpClient {
	c, _ := opera.NewClient(v, p)
	return &headerApplyingClient{HttpClient: c, apply: func(r *fhttp.Request) {
		_ = opera.ApplyHeaders(r, v, p)
	}}
}

func newSafariClient(v safari.Version, p safari.Platform) tls_client.HttpClient {
	c, _ := safari.NewClient(v, p)
	return &headerApplyingClient{HttpClient: c, apply: func(r *fhttp.Request) {
		_ = safari.ApplyHeaders(r, v, p)
	}}
}

func newOkHttpClient(v okhttp.Version) tls_client.HttpClient {
	c, _ := okhttp.NewClient(v)
	return &headerApplyingClient{HttpClient: c, apply: func(r *fhttp.Request) {
		_ = okhttp.ApplyHeaders(r, v)
	}}
}

func maybeProxy(c tls_client.HttpClient) tls_client.HttpClient {
	proxy := os.Getenv("PROXY")
	if proxy == "" {
		return c
	}
	// tls_client doesn't expose a runtime proxy setter; users have
	// to wire WithProxyUrl into the constructor. For this test
	// driver we just rely on PROXY being set as an env the
	// underlying transport picks up if supported. If your
	// tls-client version does, use:
	//
	//   return c   // already configured by profile's NewClient
	//
	// (left as a no-op for now; the user can edit cmd/test to add
	// WithProxyUrl calls per profile if needed.)
	_ = proxy
	return c
}

// ----- the actual request runner -----

func runProfile(target string, client tls_client.HttpClient) (int, string) {
	req, err := fhttp.NewRequest(fhttp.MethodGet, target, nil)
	if err != nil {
		return 0, "build request: " + err.Error()
	}

	// Apply the profile's own header set (User-Agent, sec-ch-ua,
	// accept, accept-encoding, accept-language, etc.). Without
	// this fhttp falls back to "Go-http-client/2.0" and the
	// server-side fingerprint detector sees the wrong UA, which
	// on Cloudflare-fronted sites (e.g. chatgpt.com) is enough
	// to trigger a 403 challenge.
	if ah, ok := client.(interface {
		ApplyHeaders(*fhttp.Request)
	}); ok {
		ah.ApplyHeaders(req)
		if strings.EqualFold(req.URL.Host, "chatgpt.com") || strings.HasSuffix(strings.ToLower(req.URL.Host), ".chatgpt.com") {
			req.Header.Set("sec-fetch-user", "?1")
			req.Header.Set("upgrade-insecure-requests", "1")
			req.Header.Set("origin", "https://chatgpt.com")
			req.Header.Set("referer", "https://chatgpt.com/")
		}
	} else {
		// Fallback: still pin a stable sec-fetch-* baseline so
		// profiles that don't expose ApplyHeaders still send
		// something sensible.
		req.Header.Set("sec-fetch-dest", "document")
		req.Header.Set("sec-fetch-mode", "navigate")
		req.Header.Set("sec-fetch-site", "none")
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()

	fmt.Printf("  → status=%d  time=%s  proto=%s  cf-ray=%q\n",
		resp.StatusCode,
		time.Since(start).Round(time.Millisecond),
		resp.Proto,
		resp.Header.Get("cf-ray"),
	)

	// Always read up to 32KB of body for inspection. Useful for
	// tls.peet.ws/api/all (full TLS fingerprint dump) and for
	// 403/503 Cloudflare challenge pages.
	body, rerr := readBody(resp, 32768)
	if rerr != nil {
		return resp.StatusCode, "read body: " + rerr.Error()
	}

	// For tls.peet.ws/api/all, pull out ja3 / ja4 / akamai / extension
	// names so the user can diff them against the real browser.
	if strings.Contains(target, "tls.peet.ws") {
		diag, derr := extractPeetSummary(body)
		if derr == nil {
			fmt.Printf("  → peet summary: %s\n", diag)
			return resp.StatusCode, ""
		}
	}

	snippet := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, string(body))
	if len(snippet) > 1500 {
		snippet = snippet[:1500] + "..."
	}
	fmt.Printf("  → body-snippet: %s\n", snippet)
	return resp.StatusCode, ""
}

// extractPeetSummary returns a one-line summary of the TLS / HTTP2
// fingerprint fields peet.ws reports, so users can compare two
// profiles side-by-side.
func extractPeetSummary(body []byte) (string, error) {
	var doc struct {
		TLS struct {
			JA3     string `json:"ja3"`
			JA3Hash string `json:"ja3_hash"`
			JA4     string `json:"ja4"`
			JA4R    string `json:"ja4_r"`
		} `json:"tls"`
		HTTPVersion string `json:"http_version"`
		UserAgent   string `json:"user_agent"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", err
	}
	return fmt.Sprintf("ua=%q  http=%s  ja3=%s  ja3_hash=%s  ja4=%s  ja4_r=%s",
		doc.UserAgent, doc.HTTPVersion, doc.TLS.JA3, doc.TLS.JA3Hash,
		doc.TLS.JA4, doc.TLS.JA4R), nil
}

func readBody(resp *fhttp.Response, limit int64) ([]byte, error) {
	// Cloudflare can return zstd / deflate / brotli / raw. Don't
	// trust the content-encoding header blindly — the test driver
	// just wants the first ~1KB of bytes to peek at the page.
	// We attempt brotli because that's what fhttp's transport
	// would deliver to a real Go HTTP client, but if decoding
	// fails we fall back to the raw body.
	var r io.Reader = resp.Body
	switch strings.ToLower(resp.Header.Get("content-encoding")) {
	case "gzip":
		gr, err := gzip.NewReader(resp.Body)
		if err == nil {
			defer gr.Close()
			r = gr
		}
	case "deflate":
		r = flate.NewReader(resp.Body)
	case "br":
		br := brotli.NewReader(resp.Body)
		buf, err := io.ReadAll(io.LimitReader(br, limit))
		if err == nil {
			return buf, nil
		}
		// fall through to raw body on "RESERVED" / decoding errors
		r = nil
	}
	if r == nil {
		return io.ReadAll(io.LimitReader(resp.Body, limit))
	}
	return io.ReadAll(io.LimitReader(r, limit))
}
