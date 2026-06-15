// Package tlsclient - 平台相关头信息 (User-Agent, sec-ch-ua)
//
// 数据来源: wreq-util/src/emulate/profile/{chrome,firefox,opera,safari}.rs 的 mod_generator! 调用
package tlsclient

// Platform 浏览器运行平台
type Platform int

const (
	PlatformMacOS Platform = iota
	PlatformWindows
	PlatformLinux
	PlatformAndroid
	PlatformIOS
)

// PlatformString 返回平台的标准字符串 (用于 sec-ch-ua-platform)
func (p Platform) PlatformString() string {
	switch p {
	case PlatformMacOS:
		return "macOS"
	case PlatformWindows:
		return "Windows"
	case PlatformLinux:
		return "Linux"
	case PlatformAndroid:
		return "Android"
	case PlatformIOS:
		return "iOS"
	}
	return "macOS"
}

// IsMobile 判断是否为移动平台
func (p Platform) IsMobile() bool {
	return p == PlatformAndroid || p == PlatformIOS
}

// HeaderSet 一个浏览器版本在某个平台上的完整头集合
type HeaderSet struct {
	SecChUa       string // Chrome / Edge / Opera 专用
	UserAgent     string
	Accept        string
	AcceptEncoding string
	AcceptLanguage string
	SecFetchDest  string
	SecFetchMode  string
	SecFetchSite  string
	Priority      string // 可选, 例如 "u=0, i"
	Te            string // Firefox 专用
}

// chromeAccept 标准的 Chrome Accept 头
const chromeAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"

// ==================== Chrome 头信息 ====================

// chromeUserAgents Chrome 在各平台上的 User-Agent
var chromeUserAgents = map[string]map[Platform]string{
	"100": {
		PlatformMacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
		PlatformLinux:   "Mozilla/5.0 (X11; U; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
		PlatformAndroid: "Mozilla/5.0 (X11; U; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
		PlatformWindows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
		PlatformIOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 15_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/100.0.4896.85 Mobile/15E148 Safari/604.1",
	},
	"148": {
		PlatformMacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
		PlatformWindows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
		PlatformLinux:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
		PlatformAndroid: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36",
	},
}

// chromeSecChUa Chrome 的 sec-ch-ua 字符串 (按版本)
var chromeSecChUa = map[string]string{
	"100": `"Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100"`,
	"148": `"Chromium";v="148", "Google Chrome";v="148", "Not-A.Brand";v="99"`,
}

// ==================== Edge 头信息 ====================

var edgeUserAgents = map[string]map[Platform]string{
	"101": {
		PlatformMacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47",
		PlatformAndroid: "Mozilla/5.0 (Linux; Android 10; ONEPLUS A6003) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36 Edg/101.0.1210.31",
		PlatformWindows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.53",
	},
	"148": {
		PlatformMacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0",
		PlatformWindows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0",
	},
}

var edgeSecChUa = map[string]string{
	"101": `"Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"`,
	"148": `"Chromium";v="148", "Microsoft Edge";v="148", "Not-A.Brand";v="99"`,
}

// ==================== Firefox 头信息 ====================

// firefoxAccept Firefox 的 Accept 头
const firefoxAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

var firefoxUserAgents = map[string]map[Platform]string{
	"109": {
		PlatformWindows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
		PlatformMacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_17; rv:109.0) Gecko/20000101 Firefox/109.0",
		PlatformAndroid: "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/109.0",
		PlatformLinux:   "Mozilla/5.0 (X11; Linux i686; rv:109.0) Gecko/20100101 Firefox/109.0",
		PlatformIOS:     "Mozilla/5.0 (iPad; CPU OS 13_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/109.0 Mobile/15E148 Safari/605.1.15",
	},
	"135": {
		PlatformWindows: "Mozilla/5.0 (Windows NT 10.0; rv:135.0) Gecko/20100101 Firefox/135.0",
		PlatformMacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
		PlatformLinux:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
		PlatformAndroid: "Mozilla/5.0 (Android 13; Mobile; rv:135.0) Gecko/135.0 Firefox/135.0",
		PlatformIOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/135.0 Mobile/15E148 Safari/605.1.15",
	},
	"151": {
		PlatformWindows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
		PlatformMacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0",
		PlatformLinux:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0",
		PlatformAndroid: "Mozilla/5.0 (Android 13; Mobile; rv:151.0) Gecko/151.0 Firefox/151.0",
		PlatformIOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/151.0 Mobile/15E148 Safari/605.1.15",
	},
}

// ==================== Opera 头信息 ====================

var operaUserAgents = map[string]map[Platform]string{
	"116": {
		PlatformMacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0",
		PlatformWindows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0",
	},
	"131": {
		PlatformMacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 OPR/131.0.0.0",
		PlatformWindows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 OPR/131.0.0.0",
	},
}

var operaSecChUa = map[string]string{
	"116": `"Opera";v="116", "Chromium";v="131", "Not_A Brand";v="24"`,
	"131": `"Opera";v="131", "Not.A/Brand";v="8", "Chromium";v="147"`,
}

// ==================== Safari 头信息 ====================

// safariAccept Safari 的 Accept 头
const safariAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

var safariUserAgents = map[string]string{
	"15.3":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15",
	"15.5":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
	"15.6.1": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15",
	"16":     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
	"16.5":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
	"17.0":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	"17.4.1": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	"17.5":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"17.6":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
	"18":     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
	"18.2":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
	"18.3":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
	"18.5":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15",
	"26":     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
	"26.1":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Safari/605.1.15",
	"26.2":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15",
	"26.3":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.3 Safari/605.1.15",
	"26.4":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Safari/605.1.15",
	// iOS
	"16.5-iOS":       "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
	"17.2-iOS":       "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
	"17.4.1-iOS":     "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
	"18.1.1-iOS":     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Mobile/15E148 Safari/604.1",
	"26-iOS":         "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
	"26.2-iOS":       "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Mobile/15E148 Safari/604.1",
	// iPad
	"18-iPad":        "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
	"26-iPad":        "Mozilla/5.0 (iPad; CPU OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
	"26.2-iPad":      "Mozilla/5.0 (iPad; CPU OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Mobile/15E148 Safari/604.1",
}

// ==================== OkHttp 头信息 ====================

var okhttpUserAgents = map[string]string{
	"3.9":  "MaiMemo/4.4.50_639 okhttp/3.9 Android/5.0 Channel/WanDouJia Device/alps+M8+Emulator (armeabi-v7a) Screen/4.44 Resolution/480x800 DId/aa6cde19def3806806d5374c4e5fd617 RAM/0.94 ROM/4.91 Theme/Day",
	"3.11": "NRC Audio/2.0.6 (nl.nrc.audio; build:36; Android 12; Sdk:31; Manufacturer:motorola; Model: moto g72) OkHttp/3.11.0",
	"3.13": "GM-Android/6.112.2 (240590300; M:Google Pixel 7a; O:34; D:2b045e03986fa6dc) ObsoleteUrlFactory/1.0 OkHttp/3.13.0",
	"3.14": "DS podcast/2.0.1 (be.standaard.audio; build:9; Android 11; Sdk:30; Manufacturer:samsung; Model: SM-A405FN) OkHttp/3.14.0",
	"4.9":  "GM-Android/6.111.1 (240460200; M:motorola moto g power (2021); O:30; D:76ba9f6628d198c8) ObsoleteUrlFactory/1.0 OkHttp/4.9",
	"4.10": "GM-Android/6.112.2 (240590300; M:samsung SM-G781U1; O:33; D:edb34792871638d8) ObsoleteUrlFactory/1.0 OkHttp/4.10.0",
	"4.12": "okhttp/4.12.0",
	"5":    "NRC Audio/2.0.6 (nl.nrc.audio; build:36; Android 14; Sdk:34; Manufacturer:OnePlus; Model: CPH2609) OkHttp/5.0.0-alpha2",
}

// ==================== Header 构造器 ====================

// ChromeHeaders 构造 Chrome 在指定平台上的请求头
func ChromeHeaders(version string, p Platform) map[string]string {
	headers := map[string]string{
		"User-Agent":       chromeUserAgents[version][p],
		"Accept":           chromeAccept,
		"Accept-Encoding":  "gzip, deflate, br, zstd",
		"Accept-Language":  "en-US,en;q=0.9",
		"sec-fetch-dest":   "document",
		"sec-fetch-mode":   "navigate",
		"sec-fetch-site":   "none",
		"sec-fetch-user":   "?1",
		"upgrade-insecure-requests": "1",
	}
	if v, ok := chromeSecChUa[version]; ok {
		headers["sec-ch-ua"] = v
		headers["sec-ch-ua-mobile"] = "?0"
		headers["sec-ch-ua-platform"] = `"` + p.PlatformString() + `"`
	}
	return headers
}

// EdgeHeaders 构造 Edge 在指定平台上的请求头
func EdgeHeaders(version string, p Platform) map[string]string {
	headers := map[string]string{
		"User-Agent":       edgeUserAgents[version][p],
		"Accept":           chromeAccept,
		"Accept-Encoding":  "gzip, deflate, br, zstd",
		"Accept-Language":  "en-US,en;q=0.9",
		"sec-fetch-dest":   "document",
		"sec-fetch-mode":   "navigate",
		"sec-fetch-site":   "none",
	}
	if v, ok := edgeSecChUa[version]; ok {
		headers["sec-ch-ua"] = v
		headers["sec-ch-ua-mobile"] = "?0"
		headers["sec-ch-ua-platform"] = `"` + p.PlatformString() + `"`
	}
	return headers
}

// FirefoxHeaders 构造 Firefox 在指定平台上的请求头
func FirefoxHeaders(version string, p Platform) map[string]string {
	headers := map[string]string{
		"User-Agent":       firefoxUserAgents[version][p],
		"Accept":           firefoxAccept,
		"Accept-Language":  "en-US,en;q=0.5",
		"Accept-Encoding":  "gzip, deflate, br, zstd",
		"sec-fetch-dest":   "document",
		"sec-fetch-mode":   "navigate",
		"sec-fetch-site":   "none",
		"te":               "trailers",
	}
	return headers
}

// OperaHeaders 构造 Opera 在指定平台上的请求头
func OperaHeaders(version string, p Platform) map[string]string {
	headers := map[string]string{
		"User-Agent":       operaUserAgents[version][p],
		"Accept":           chromeAccept,
		"Accept-Encoding":  "gzip, deflate, br, zstd",
		"Accept-Language":  "en-US,en;q=0.9",
		"sec-fetch-dest":   "document",
		"sec-fetch-mode":   "navigate",
		"sec-fetch-site":   "none",
		"priority":         "u=0, i",
	}
	if v, ok := operaSecChUa[version]; ok {
		headers["sec-ch-ua"] = v
		headers["sec-ch-ua-mobile"] = "?0"
		headers["sec-ch-ua-platform"] = `"` + p.PlatformString() + `"`
	}
	return headers
}

// SafariHeaders 构造 Safari 在指定版本上的请求头
func SafariHeaders(version string) map[string]string {
	return map[string]string{
		"User-Agent":      safariUserAgents[version],
		"Accept":          safariAccept,
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate, br",
		"sec-fetch-dest":  "document",
		"sec-fetch-mode":  "navigate",
		"sec-fetch-site":  "none",
		"priority":        "u=0, i",
	}
}

// OkHttpHeaders 构造 OkHttp 在指定版本上的请求头
func OkHttpHeaders(version string) map[string]string {
	return map[string]string{
		"User-Agent":      okhttpUserAgents[version],
		"Accept":          "*/*",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip",
	}
}
