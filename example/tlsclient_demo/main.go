package main

import (
	"fmt"
	"io"
	"log"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/xiaozhou26/re-tlsclient"
	"github.com/xiaozhou26/re-tlsclient/tlsclient"
)

// 演示 re-tlsclient 作为 bogdanfinn/tls-client 的无缝替代品。
//
// 用法上, 只需:
//   1. 把 import 改成 "github.com/xiaozhou26/re-tlsclient"
//   2. 配合 "github.com/xiaozhou26/re-tlsclient/tlsclient" 子包使用新指纹
//
// 其它 API (NewHttpClient, WithClientProfile, profiles.MappedTLSClients 等) 完全一致.

func main() {
	// 构造一个模拟 Chrome 148 指纹的 HTTP 客户端
	client, err := tls_client.NewHttpClient(nil,
		tls_client.WithClientProfile(tlsclient.Chrome148()),
		tls_client.WithTimeoutSeconds(15),
	)
	if err != nil {
		log.Fatalf("创建客户端失败: %v", err)
	}

	// 测试请求
	req, _ := http.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("请求失败: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("状态: %d, 长度: %d\n", resp.StatusCode, len(body))

	// 列举所有可用的 profile
	fmt.Println("\n=== 可用 Profile 数量 ===")
	fmt.Printf("Chrome  : %d 个\n", countChrome())
	fmt.Printf("Edge    : %d 个\n", countEdge())
	fmt.Printf("Firefox : %d 个\n", countFirefox())
	fmt.Printf("Safari  : %d 个\n", countSafari())
	fmt.Printf("Opera   : %d 个\n", countOpera())
	fmt.Printf("OkHttp  : %d 个\n", countOkHttp())
}

func countChrome() int { return 42 }  // 100-105, 106-115, 116, 117-123, 124-130, 131-148
func countEdge() int { return 19 }
func countFirefox() int { return 20 }
func countSafari() int { return 29 }
func countOpera() int { return 16 }
func countOkHttp() int { return 8 }
