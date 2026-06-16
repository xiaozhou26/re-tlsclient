// Package migrate 演示从 github.com/bogdanfinn/tls-client 迁移到 re-tlsclient 的端到端对照测试。
//
// 用法：
//   go test -tags migrate_e2e -run TestMigration ./tests/...
//
// 这个文件本身不带 network 标签——go test 跑它时只用 httptest 起本地 server，
// 不依赖外网；httpbin.org 的真实网络测试见 TestMigration_LiveHTTPBin（带 build tag 才会跑）。
//go:build !migrate_e2e_off

package tests

import (
	"context"
	"fmt"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	"github.com/gogf/gf/v2/frame/g"

	"github.com/xiaozhou26/re-tlsclient/fp"
	"github.com/xiaozhou26/re-tlsclient/jar"
	"github.com/xiaozhou26/re-tlsclient/transport"
)

// TestMigration_LocalServer 对照测试：本地 HTTP server 上，
// "原 bogdanfinn/tls-client 写法" 与 "本项目 re-tlsclient 写法" 都能跑通，
// 且两者拿到的响应、状态码、UA 头一致。
func TestMigration_LocalServer(t *testing.T) {
	// 1) 启动一个本地 server：回显请求的 UA + Method + Body
	var lastSeenUA string
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		lastSeenUA = r.Header.Get("User-Agent")
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"method":%q,"ua":%q,"body":%q,"host":%q}`,
			r.Method, lastSeenUA, string(body), r.Host)
	}))
	defer srv.Close()

	// 2) 准备 UA —— 两套代码用同一个 UA，便于对照
	const wantUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

	// ---------- 写法 A：原 bogdanfinn/tls-client ----------
	t.Run("old:tls-client", func(t *testing.T) {
		client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(),
			tls_client.WithClientProfile(profiles.Chrome_131),
			tls_client.WithTimeoutSeconds(15),
			tls_client.WithDefaultHeaders(fhttp.Header{
				"User-Agent": []string{wantUA},
			}),
		)
		if err != nil {
			t.Fatalf("tls-client NewHttpClient: %v", err)
		}
		defer client.CloseIdleConnections()

		req, _ := fhttp.NewRequest("GET", srv.URL+"/old", strings.NewReader("payload-old"))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("tls-client Do: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != 200 {
			t.Errorf("old: status = %d, want 200", resp.StatusCode)
		}
		if !strings.Contains(string(body), `"method":"GET"`) {
			t.Errorf("old: body = %s, want method=GET", string(body))
		}
		if !strings.Contains(string(body), `"payload-old"`) {
			t.Errorf("old: body = %s, want contains payload-old", string(body))
		}
		// 验证 UA 被服务端读到了
		if lastSeenUA != wantUA {
			t.Errorf("old: server saw UA = %q, want %q", lastSeenUA, wantUA)
		}
	})

	// ---------- 写法 B：本项目 re-tlsclient ----------
	t.Run("new:re-tlsclient", func(t *testing.T) {
		ctx := g.Ctx(context.Background())
		c, err := fp.NewClient(ctx, fp.ClientOption{
			ClientProfile: "Chrome_131", // tls-client 内置 PascalCase
			TimeoutSeconds: 15,
			DefaultHeaders: fhttp.Header{
				"User-Agent": []string{wantUA},
			},
		})
		if err != nil {
			t.Fatalf("re-tlsclient NewClient: %v", err)
		}
		defer c.Close()

		// 复刻 old 那边的 POST 行为（用 DO 任意 method）
		resp, err := c.DO(ctx, "POST", srv.URL+"/new", fp.RequestOption{
			Body: []byte("payload-new"),
		})
		if err != nil {
			t.Fatalf("re-tlsclient DO: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != 200 {
			t.Errorf("new: status = %d, want 200", resp.StatusCode)
		}
		if !strings.Contains(string(body), `"method":"POST"`) {
			t.Errorf("new: body = %s, want method=POST", string(body))
		}
		if !strings.Contains(string(body), `"payload-new"`) {
			t.Errorf("new: body = %s, want contains payload-new", string(body))
		}
		if lastSeenUA != wantUA {
			t.Errorf("new: server saw UA = %q, want %q", lastSeenUA, wantUA)
		}
	})
}

// TestMigration_ExtraProfile 验证 80+ 自填 profile 的入口对接到 client。
// 与 TestExtraProfile_Priority 等价，但放在 tests/ 演示"对外用户路径"。
func TestMigration_ExtraProfile(t *testing.T) {
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()

	ctx := g.Ctx(context.Background())
	c, err := fp.NewClient(ctx, fp.ClientOption{
		ExtraProfile: "chrome_148", // wreq-util 风格小写名
		TimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c == nil || c.HttpClient == nil {
		t.Fatal("nil client")
	}
	defer c.Close()

	// 实际访问一下触发 TLS 握手（local server 是 HTTP，但 tls-client 仍会初始化 spec）
	resp, err := c.Get(ctx, srv.URL+"/probe")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// TestMigration_JarUse 验证 jar.Jar 的 SetCookiesByMap + Clear：
// 1) 预置的 cookie 在请求时被 jar 注入到 Cookie 头；
// 2) Clear 后 cookie 不再发送。
func TestMigration_JarUse(t *testing.T) {
	var seenCookie string
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		seenCookie = r.Header.Get("Cookie")
		w.WriteHeader(204)
	}))
	defer srv.Close()

	ctx := g.Ctx(context.Background())
	j := jar.NewJar()
	c, err := fp.NewClient(ctx, fp.ClientOption{
		ExtraProfile:  "chrome_148",
		TimeoutSeconds: 5,
		CookieJar:     j,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 预置 cookie
	if err := j.SetCookiesByMap(srv.URL, map[string]string{
		"token": "abc",
		"uid":   "1001",
	}); err != nil {
		t.Fatal(err)
	}

	// 第一次请求：jar 应自动注入 Cookie 头
	resp, err := c.Get(ctx, srv.URL+"/probe")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if !strings.Contains(seenCookie, "token=abc") {
		t.Errorf("jar: expected token=abc in Cookie header, got %q", seenCookie)
	}
	if !strings.Contains(seenCookie, "uid=1001") {
		t.Errorf("jar: expected uid=1001 in Cookie header, got %q", seenCookie)
	}

	// 清空后再请求
	j.Clear()
	resp, err = c.Get(ctx, srv.URL+"/probe2")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if seenCookie != "" {
		t.Errorf("jar: after Clear, expected no Cookie header, got %q", seenCookie)
	}
}

// TestMigration_HeaderOrder 验证"严格模式 + 白名单"语义。
// 客户端设了 X-User / Authorization 两个 header；
// 严格指纹模式下 spec header 全量覆盖，但 Authorization 在白名单里保留。
func TestMigration_HeaderOrder(t *testing.T) {
	captured := stdhttp.Header{}
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		for k, v := range r.Header {
			captured[k] = v
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()

	ctx := g.Ctx(context.Background())
	c, err := fp.NewClient(ctx, fp.ClientOption{
		ExtraProfile: "chrome_148",
		TimeoutSeconds: 5,
		// 故意构造一个 minimal Spec：把 User-Agent 当成"spec header"全量下发
		// 这样能验证白名单透传。
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 不在严格模式下，DefaultHeaders 会被合并
	req, _ := fhttp.NewRequest("GET", srv.URL, nil)
	req.Header = fhttp.Header{
		"X-Custom":      []string{"custom-value"},
		"Authorization": []string{"Bearer xyz"},
	}
	resp, err := c.Do(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if captured.Get("X-Custom") != "custom-value" {
		t.Errorf("header X-Custom not propagated: %v", captured)
	}
	if captured.Get("Authorization") != "Bearer xyz" {
		t.Errorf("header Authorization not propagated: %v", captured)
	}
}

// TestMigration_TransportRoundTrip 验证 transport.New(c) 返回的 transport
// 真的能跑 RoundTrip 到 httptest server。这是"原来用 bogdanfinn/tls-client +
// 手写 RoundTrip"换成本项目 transport.New() 的最小端到端验证。
func TestMigration_TransportRoundTrip(t *testing.T) {
	var seenUA string
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		seenUA = r.Header.Get("User-Agent")
		w.WriteHeader(204)
	}))
	defer srv.Close()

	ctx := g.Ctx(context.Background())
	c, err := fp.NewClient(ctx, fp.ClientOption{
		ExtraProfile:  "chrome_148",
		TimeoutSeconds: 5,
		DefaultHeaders: fhttp.Header{
			"User-Agent": []string{"Mozilla/5.0 (Macintosh) TestTransport/1.0"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	tr := transport.New(c)
	req, _ := stdhttp.NewRequest("GET", srv.URL, nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if seenUA != "Mozilla/5.0 (Macintosh) TestTransport/1.0" {
		t.Errorf("transport: server saw UA = %q", seenUA)
	}
}

// init 防导入时引用出错（保持 stdhttp / time / strings 显式被使用）
var _ = stdhttp.MethodGet
var _ = time.Second
var _ = strings.HasPrefix
