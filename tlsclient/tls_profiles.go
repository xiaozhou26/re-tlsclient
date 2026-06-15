// Package tlsclient 提供基于 bogdanfinn/tls-client 的浏览器指纹库。
//
// 设计理念: 使用 JA3 字符串 + 元数据数组 动态构建 profiles.ClientProfile。
// 灵感来自 xiaozhou26/tlsclient, 数据来源于 wreq-util Rust 项目 (3.0.0-rc.12)。
//
// 支持 96 个浏览器变体, 涵盖:
//   - Chrome 100-148
//   - Edge 101-148
//   - Firefox 109-151
//   - Safari 15.3-26.4 (含 iOS / iPad)
//   - Opera 116-131
//   - OkHttp 3.9-5
package tlsclient

import (
	"github.com/bogdanfinn/fhttp/http2"
	tlsclient "github.com/xiaozhou26/re-tlsclient"
	"github.com/xiaozhou26/re-tlsclient/profiles"
	bfutls "github.com/bogdanfinn/utls"
)

// ==================== 共享元数据常量 ====================
//
// 这些数组在多个 profile 间复用, 避免重复定义。

// chromeSigAlgs Chrome 系列的签名算法列表 (8 项, 全部启用 rsa_pss + ecdsa_secp)
var chromeSigAlgs = []string{
	"ECDSAWithP256AndSHA256", // 0x0403
	"PSSWithSHA256",          // 0x0804
	"PKCS1WithSHA256",        // 0x0401
	"ECDSAWithP384AndSHA384", // 0x0503
	"PSSWithSHA384",          // 0x0805
	"PKCS1WithSHA384",        // 0x0501
	"PSSWithSHA512",          // 0x0806
	"PKCS1WithSHA512",        // 0x0601
}

// firefoxSigAlgs Firefox 的签名算法列表 (11 项, 包含 SHA1)
var firefoxSigAlgs = []string{
	"ECDSAWithP256AndSHA256", // 0x0403
	"ECDSAWithP384AndSHA384", // 0x0503
	"ECDSAWithP521AndSHA512", // 0x0603
	"PSSWithSHA256",          // 0x0804
	"PSSWithSHA384",          // 0x0805
	"PSSWithSHA512",          // 0x0806
	"PKCS1WithSHA256",        // 0x0401
	"PKCS1WithSHA384",        // 0x0501
	"PKCS1WithSHA512",        // 0x0601
	"ECDSAWithSHA1",          // 0x0203
	"PKCS1WithSHA1",          // 0x0201
}

// firefoxDelegatedCred Firefox 的 delegated_credentials 列表 (4 项)
var firefoxDelegatedCred = []string{
	"ECDSAWithP256AndSHA256",
	"ECDSAWithP384AndSHA384",
	"ECDSAWithP521AndSHA512",
	"ECDSAWithSHA1",
}

// firefoxCurves FFDHE + 标准曲线 (Firefox 109+)
var firefoxCurves = []string{
	"X25519", "P-256", "P-384", "P-521", "ffdhe2048", "ffdhe3072",
}

// firefoxCurvesMLKEM X25519MLKEM768 + FFDHE (Firefox 133+)
var firefoxCurvesMLKEM = []string{
	"X25519MLKEM768", "X25519", "P-256", "P-384", "P-521", "ffdhe2048", "ffdhe3072",
}

// firefoxKeyShares X25519 + P-256 (Firefox 128 之前)
var firefoxKeyShares = []string{"X25519", "P-256"}

// firefoxKeySharesMLKEM X25519MLKEM768 + X25519 + P-256 (Firefox 133+)
var firefoxKeySharesMLKEM = []string{"X25519MLKEM768", "X25519", "P-256"}

// chromeKeyShareMLKEM X25519MLKEM768 (Chrome 132+)
var chromeKeyShareMLKEM = []string{"X25519MLKEM768"}

// chromeKeyShareKyberDraft X25519Kyber768Draft00 (Chrome 124-130)
var chromeKeyShareKyberDraft = []string{"X25519Kyber768Draft00"}

// chromeVersions TLS 1.3 + 1.2 (Chrome 默认)
var chromeVersions = []string{"1.3", "1.2"}

// firefoxVersions TLS 1.3 + 1.2 (Firefox 默认)
var firefoxVersions = []string{"1.3", "1.2"}

// alpnH2 HTTP/2 + HTTP/1.1 (大多数浏览器)
var alpnH2 = []string{"h2", "http/1.1"}

// alpsH2 ALPS 仅启用 h2
var alpsH2 = []string{"h2"}

// echSuites 标准 ECH candidate cipher suites (3 个)
var echSuites = []tlsclient.CandidateCipherSuites{
	{KdfId: "HKDF_SHA256", AeadId: "AEAD_AES_128_GCM"},
	{KdfId: "HKDF_SHA256", AeadId: "AEAD_AES_256_GCM"},
	{KdfId: "HKDF_SHA256", AeadId: "AEAD_CHACHA20_POLY1305"},
}

// echPayloads 标准 ECH candidate payload 长度
var echPayloads = []uint16{128, 223}

// ==================== 共享 HTTP/2 配置 ====================

// chromeHTTP2Settings Chrome/Edge/Opera 共享的 HTTP/2 SETTINGS
var chromeHTTP2Settings = map[http2.SettingID]uint32{
	http2.SettingHeaderTableSize:   65536,
	http2.SettingEnablePush:        0,
	http2.SettingInitialWindowSize: 6291456,
	http2.SettingMaxHeaderListSize: 262144,
}

var chromeHTTP2SettingsOrder = []http2.SettingID{
	http2.SettingHeaderTableSize,
	http2.SettingEnablePush,
	http2.SettingInitialWindowSize,
	http2.SettingMaxHeaderListSize,
}

// chromePseudoOrder Chrome 系列的伪头部顺序
var chromePseudoOrder = []string{
	":method", ":authority", ":scheme", ":path",
}

// chromeConnFlow Chrome 系列的连接流控窗口
var chromeConnFlow = uint32(15663105)

// firefoxHTTP2Settings Firefox 的 HTTP/2 SETTINGS
var firefoxHTTP2Settings = map[http2.SettingID]uint32{
	http2.SettingHeaderTableSize:   65536,
	http2.SettingEnablePush:        0,
	http2.SettingInitialWindowSize: 131072,
	http2.SettingMaxFrameSize:      16384,
}

var firefoxHTTP2SettingsOrder = []http2.SettingID{
	http2.SettingHeaderTableSize,
	http2.SettingEnablePush,
	http2.SettingInitialWindowSize,
	http2.SettingMaxFrameSize,
}

// firefoxPseudoOrder Firefox 的伪头部顺序 (与 Chrome 不同)
var firefoxPseudoOrder = []string{
	":method", ":path", ":authority", ":scheme",
}

var firefoxConnFlow = uint32(12517377)

// safariHTTP2Settings Safari 的 HTTP/2 SETTINGS
var safariHTTP2Settings = map[http2.SettingID]uint32{
	http2.SettingHeaderTableSize:      4096,
	http2.SettingEnablePush:           0,
	http2.SettingMaxConcurrentStreams: 100,
	http2.SettingInitialWindowSize:    2097152,
	http2.SettingMaxFrameSize:         16384,
}

var safariHTTP2SettingsOrder = []http2.SettingID{
	http2.SettingHeaderTableSize,
	http2.SettingEnablePush,
	http2.SettingMaxConcurrentStreams,
	http2.SettingInitialWindowSize,
	http2.SettingMaxFrameSize,
	http2.SettingMaxHeaderListSize,
}

// safariPseudoOrder Safari 26 的伪头部顺序
var safariPseudoOrder = []string{
	":method", ":scheme", ":authority", ":path",
}

var safariConnFlow = uint32(10551295)

// okhttpHTTP2Settings OkHttp 的 HTTP/2 SETTINGS (大窗口)
var okhttpHTTP2Settings = map[http2.SettingID]uint32{
	http2.SettingHeaderTableSize:   65536,
	http2.SettingEnablePush:        0,
	http2.SettingInitialWindowSize: 16777216,
	http2.SettingMaxFrameSize:      16384,
}

var okhttpHTTP2SettingsOrder = []http2.SettingID{
	http2.SettingHeaderTableSize,
	http2.SettingEnablePush,
	http2.SettingInitialWindowSize,
	http2.SettingMaxFrameSize,
}

var okhttpPseudoOrder = []string{
	":method", ":path", ":authority", ":scheme",
}

var okhttpConnFlow = uint32(16777216)

// ==================== Chrome 共享 cipher suites ====================
//
// 标准 Chrome 15 套密码套件 (TLS 1.3 + TLS 1.2 ECDHE + RSA + CBC)

const chromeCipherSuites = "4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53"
const chromeCipherSuitesModern = "4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53" // 同上

// firefoxCipherSuites17 Firefox 17 套密码套件
const firefoxCipherSuites17 = "4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53"
const firefoxCipherSuites15 = "4865-4867-4866-49195-49199-49196-49200-49171-49172-156-157-47-53"

// safariCipherSuites Safari 的密码套件 (更多 CBC 套件)
const safariCipherSuites = "4865-4866-4867-49196-49195-49200-49199-52393-52392-49188-49187-49192-49191-49162-49161-49172-49171-157-156-61-60-53-47-255"

// ==================== 核心构造函数 ====================

// buildChromeProfile 构造一个 Chrome 系列的 ClientProfile
func buildChromeProfile(ja3String string, clientName string, version string,
	versions []string, keyShareCurves []string) profiles.ClientProfile {

	specFunc, err := tlsclient.GetSpecFactoryFromJa3String(
		ja3String,
		chromeSigAlgs,
		chromeSigAlgs, // delegated credentials 与 sigAlgs 相同
		versions,
		keyShareCurves,
		alpnH2,
		alpsH2,
		echSuites,
		echPayloads,
		[]string{"brotli"},
		0, // recordSizeLimit: 0 = 不指定
	)
	if err != nil {
		// 失败时回退到 Chrome 124
		specFunc = profiles.Chrome_124.GetClientHelloSpec
	}

	seed, _ := bfutls.NewPRNGSeed()

	return profiles.NewClientProfile(bfutls.ClientHelloID{
		Client:               clientName,
		Version:              version,
		RandomExtensionOrder: false,
		Seed:                 seed,
		Weights:              &bfutls.DefaultWeights,
		SpecFactory:          specFunc,
	}, chromeHTTP2Settings, chromeHTTP2SettingsOrder, chromePseudoOrder, chromeConnFlow, nil, nil, 0, false, nil, nil, 0, nil, false)
}

// buildFirefoxProfile 构造一个 Firefox 系列的 ClientProfile
func buildFirefoxProfile(ja3String string, version string,
	versions []string, keyShareCurves []string) profiles.ClientProfile {

	specFunc, err := tlsclient.GetSpecFactoryFromJa3String(
		ja3String,
		firefoxSigAlgs,
		firefoxDelegatedCred,
		versions,
		keyShareCurves,
		alpnH2,
		nil, // Firefox 不启用 ALPS
		echSuites,
		echPayloads,
		[]string{"brotli"},
		0, // recordSizeLimit: 0 = 不指定
	)
	if err != nil {
		specFunc = profiles.Firefox_123.GetClientHelloSpec
	}

	seed, _ := bfutls.NewPRNGSeed()

	return profiles.NewClientProfile(bfutls.ClientHelloID{
		Client:               "Firefox",
		Version:              version,
		RandomExtensionOrder: false,
		Seed:                 seed,
		Weights:              &bfutls.DefaultWeights,
		SpecFactory:          specFunc,
	}, firefoxHTTP2Settings, firefoxHTTP2SettingsOrder, firefoxPseudoOrder, firefoxConnFlow, nil, nil, 0, false, nil, nil, 0, nil, false)
}
