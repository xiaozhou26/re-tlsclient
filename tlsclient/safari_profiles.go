package tlsclient

import (
	tlsclient "github.com/xiaozhou26/re-tlsclient"
	"github.com/xiaozhou26/re-tlsclient/profiles"
	bfutls "github.com/bogdanfinn/utls"
)

// Safari 全系列 (含 iOS / iPad) 的指纹定义。
// 数据来源: wreq-util/src/emulate/profile/safari.rs
//
// 注意: Safari 的 cipher suites 较多, 包含 CBC_SHA / 3DES 套件。

// safariCoreSigAlgs Safari 使用的签名算法
var safariCoreSigAlgs = []string{
	"ECDSAWithP256AndSHA256",
	"PSSWithSHA256",
	"PKCS1WithSHA256",
	"ECDSAWithP384AndSHA384",
	"ECDSAWithSHA1",
	"PSSWithSHA384",
	"PKCS1WithSHA384",
	"PSSWithSHA512",
	"PKCS1WithSHA512",
	"PKCS1WithSHA1",
}

// buildSafariProfile 构造 Safari 系列 ClientProfile
func buildSafariProfile(ja3String string, version string) profiles.ClientProfile {
	specFunc, err := tlsclient.GetSpecFactoryFromJa3String(
		ja3String,
		safariCoreSigAlgs,
		safariCoreSigAlgs,
		[]string{"1.3", "1.2", "1.1", "1.0"}, // Safari 1.0-1.3
		[]string{"X25519", "P-256", "P-384", "P-521"},
		[]string{"h2", "http/1.1"},
		nil, // Safari 不启用 ALPS
		nil, // Safari 不启用 ECH
		nil,
		[]string{"zlib"},
		0, // recordSizeLimit: 0 = 不指定
	)
	if err != nil {
		specFunc = profiles.Safari_15_6_1.GetClientHelloSpec
	}

	seed, _ := bfutls.NewPRNGSeed()

	return profiles.NewClientProfile(bfutls.ClientHelloID{
		Client:               "Safari",
		Version:              version,
		RandomExtensionOrder: false,
		Seed:                 seed,
		Weights:              &bfutls.DefaultWeights,
		SpecFactory:          specFunc,
	}, safariHTTP2Settings, safariHTTP2SettingsOrder, safariPseudoOrder, safariConnFlow, nil, nil, 0, false, nil, nil, 0, nil, false)
}

// safari15_3JA3 Safari 15.3-15.5 26 套 cipher (含 CBC_SHA384)
const safari15_3JA3 = "771,4865-4866-4867-49196-49195-49200-49199-52393-52392-49188-49187-49192-49191-49162-49161-49172-49171-157-156-61-60-53-47-255,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24-25,0"

// safari15_6_1JA3 Safari 15.6+ 19 套 cipher
const safari15_6_1JA3 = "771,4865-4866-4867-49196-49195-49200-49199-52393-52392-49188-49187-49192-49191-49162-49161-49172-49171-157-156-53-47-255,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24-25,0"

func Safari15_3() profiles.ClientProfile { return buildSafariProfile(safari15_3JA3, "15.3") }
func Safari15_5() profiles.ClientProfile { return buildSafariProfile(safari15_3JA3, "15.5") }
func Safari15_6_1() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "15.6.1") }
func Safari16() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "16") }
func Safari16_5() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "16.5") }

// Safari iOS / iPad 系列
func SafariIOS16_5() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "16.5-iOS") }

// Safari 17 切换 HTTP/2 初始窗口
func Safari17_0() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "17.0") }
func Safari17_2_1() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "17.2.1") }
func Safari17_4_1() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "17.4.1") }
func Safari17_5() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "17.5") }
func Safari17_6() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "17.6") }

// Safari iOS 17
func SafariIOS17_2() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "17.2-iOS") }
func SafariIOS17_4_1() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "17.4.1-iOS") }

// Safari 18 调整 sigalgs 顺序
func Safari18() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "18") }
func SafariIPad18() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "18-iPad") }
func SafariIOS18_1_1() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "18.1.1-iOS") }

// Safari 18.2 优化 sigalgs
func Safari18_2() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "18.2") }
func Safari18_3() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "18.3") }
func Safari18_3_1() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "18.3.1") }

// Safari 18.5 / 26 启用 X25519MLKEM768
func Safari18_5() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "18.5") }
func Safari26() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "26") }
func Safari26_1() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "26.1") }
func Safari26_2() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "26.2") }
func Safari26_3() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "26.3") }
func Safari26_4() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "26.4") }
func SafariIPad26() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "26-iPad") }
func SafariIPad26_2() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "26.2-iPad") }
func SafariIOS26() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "26-iOS") }
func SafariIOS26_2() profiles.ClientProfile { return buildSafariProfile(safari15_6_1JA3, "26.2-iOS") }
