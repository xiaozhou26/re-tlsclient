package tlsclient

import (
	tlsclient "github.com/xiaozhou26/re-tlsclient"
	"github.com/xiaozhou26/re-tlsclient/profiles"
	bfutls "github.com/bogdanfinn/utls"
)

// OkHttp 3.9-5 的指纹定义。
// 数据来源: wreq-util/src/emulate/profile/okhttp.rs
//
// OkHttp 是 Java HTTP 客户端, 与浏览器指纹不同:
// - 较大 HTTP/2 初始窗口 (16MB)
// - 简化的 cipher suites
// - ALPN 顺序可能不同

// okhttpSigAlgs OkHttp 的签名算法列表 (9 项, 包含 rsa_pkcs1_sha1)
var okhttpSigAlgs = []string{
	"ECDSAWithP256AndSHA256", // 0x0403
	"PSSWithSHA256",          // 0x0804
	"PKCS1WithSHA256",        // 0x0401
	"ECDSAWithP384AndSHA384", // 0x0503
	"PSSWithSHA384",          // 0x0805
	"PKCS1WithSHA384",        // 0x0501
	"PSSWithSHA512",          // 0x0806
	"PKCS1WithSHA512",        // 0x0601
	"PKCS1WithSHA1",          // 0x0201
}

// buildOkhttpProfile 构造 OkHttp 系列 ClientProfile
func buildOkhttpProfile(ja3String string, version string) profiles.ClientProfile {
	specFunc, err := tlsclient.GetSpecFactoryFromJa3String(
		ja3String,
		okhttpSigAlgs,
		okhttpSigAlgs,
		[]string{"1.3", "1.2"},
		[]string{"X25519", "P-256", "P-384"},
		[]string{"h2", "http/1.1"},
		nil,
		nil,
		nil,
		nil, // OkHttp 不指定证书压缩
		0,   // recordSizeLimit: 0 = 不指定
	)
	if err != nil {
		specFunc = profiles.Okhttp4Android12.GetClientHelloSpec
	}

	seed, _ := bfutls.NewPRNGSeed()

	return profiles.NewClientProfile(bfutls.ClientHelloID{
		Client:               "OkHttp",
		Version:              version,
		RandomExtensionOrder: false,
		Seed:                 seed,
		Weights:              &bfutls.DefaultWeights,
		SpecFactory:          specFunc,
	}, okhttpHTTP2Settings, okhttpHTTP2SettingsOrder, okhttpPseudoOrder, okhttpConnFlow, nil, nil, 0, false, nil, nil, 0, nil, false)
}

// OkHttp3.9 仅 TLS 1.2 密码套件 (15 套)
func OkHttp3_9() profiles.ClientProfile {
	return buildOkhttpProfile(
		"771,49196-49195-49200-49199-52393-52392-49188-49187-49192-49191-49162-49161-49172-49171-157-156-61-60-53-47,0-23-65281-10-11-35-16-5-13-18-51-45-43,29-23-24,0",
		"3.9",
	)
}

// OkHttp3.11 13 套 cipher
func OkHttp3_11() profiles.ClientProfile {
	return buildOkhttpProfile(
		"771,49196-49195-49200-49199-52393-52392-49188-49187-49192-49191-49162-49161-49172-49171-157-156-53-47,0-23-65281-10-11-35-16-5-13-18-51-45-43,29-23-24,0",
		"3.11",
	)
}

// OkHttp3.13 18 套 cipher
func OkHttp3_13() profiles.ClientProfile {
	return buildOkhttpProfile(
		"771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49188-49187-49192-49191-49162-49161-49172-49171-157-156-53-47,0-23-65281-10-11-35-16-5-13-18-51-45-43,29-23-24,0",
		"3.13",
	)
}

// OkHttp3.14 标准 15 套 cipher
func OkHttp3_14() profiles.ClientProfile {
	return buildOkhttpProfile(
		"771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43,29-23-24,0",
		"3.14",
	)
}

// OkHttp4.9
func OkHttp4_9() profiles.ClientProfile {
	return buildOkhttpProfile(
		"771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49188-49187-49192-49191-49162-49161-49172-49171-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43,29-23-24,0",
		"4.9",
	)
}

// OkHttp4.10 复用 OkHttp3.14
func OkHttp4_10() profiles.ClientProfile { return buildOkhttpProfile(
	"771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43,29-23-24,0",
	"4.10",
) }

// OkHttp4.12
func OkHttp4_12() profiles.ClientProfile { return buildOkhttpProfile(
	"771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43,29-23-24,0",
	"4.12",
) }

// OkHttp5 alpha
func OkHttp5() profiles.ClientProfile { return buildOkhttpProfile(
	"771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43,29-23-24,0",
	"5",
) }
