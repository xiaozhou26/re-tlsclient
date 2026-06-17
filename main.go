// Command re-tlsclient demonstrates accessing chat.openai.com with the
// Chrome 148 fingerprint defined in ./chrome.
package main

import (
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/xiaozhou26/re-tlsclient/chrome"

	"github.com/andybalholm/brotli"
	fhttp "github.com/bogdanfinn/fhttp"
)

func main() {
	target := "https://chatgpt.com/"
	if v := os.Getenv("TARGET"); v != "" {
		target = v
	}

	if _, err := url.Parse(target); err != nil {
		fmt.Println("invalid TARGET url:", err)
		os.Exit(2)
	}

	client, err := chrome.NewClient(chrome.V148, chrome.MacOS)
	if err != nil {
		fmt.Println("init client:", err)
		os.Exit(1)
	}

	req, err := fhttp.NewRequest(fhttp.MethodGet, target, nil)
	if err != nil {
		fmt.Println("build request:", err)
		os.Exit(1)
	}

	// Always pin Chrome 147's header set on the outgoing request.
	chrome.ApplyHeaders(req, chrome.V148, chrome.MacOS)

	// chatgpt's home page is a SPA: ask for the "real" content negotiated by
	// the page itself, and accept compressed bodies.
	req.Header.Set("sec-fetch-dest", "document")
	req.Header.Set("sec-fetch-mode", "navigate")
	req.Header.Set("sec-fetch-site", "none")
	req.Header.Set("sec-fetch-user", "?1")
	req.Header.Set("upgrade-insecure-requests", "1")
	req.Header.Set("origin", "https://chatgpt.com")
	req.Header.Set("referer", "https://chatgpt.com/")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("do:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fmt.Printf("status=%d  time=%s  proto=%d.%d  proto_str=%s\n",
		resp.StatusCode,
		time.Since(start).Round(time.Millisecond),
		resp.ProtoMajor, resp.ProtoMinor,
		resp.Proto,
	)
	fmt.Println("server:", resp.Header.Get("server"))
	fmt.Println("location:", resp.Header.Get("location"))
	fmt.Println("content-type:", resp.Header.Get("content-type"))
	fmt.Println("content-encoding:", resp.Header.Get("content-encoding"))
	fmt.Println("cf-ray:", resp.Header.Get("cf-ray"))
	fmt.Println("set-cookie:", resp.Header.Get("set-cookie"))

	body, err := readBody(resp)
	if err != nil {
		fmt.Println("read body:", err)
		os.Exit(1)
	}

	preview := string(body)
	if len(preview) > 1200 {
		preview = preview[:1200] + "...(truncated)"
	}
	fmt.Println(preview)
}

func readBody(resp *fhttp.Response) ([]byte, error) {
	var r io.Reader = resp.Body
	switch strings.ToLower(resp.Header.Get("content-encoding")) {
	case "gzip":
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		defer gr.Close()
		r = gr
	case "br":
		r = brotli.NewReader(resp.Body)
	case "deflate":
		r = flate.NewReader(resp.Body)
	}
	return io.ReadAll(r)
}
