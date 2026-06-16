package profile

// 本文件按 wreq-util (https://github.com/0x676e67/wreq-util) 的
// emulate/profile/<browser>/* 配置生成 profiles.ClientProfile，
// 补齐 tls-client 1.15.1 内置 MappedTLSClients 没有覆盖的 profile 名。
//
// 字段映射约定：
//   - wreq TlsOptions.cipher_list      -> tls.ClientHelloSpec.CipherSuites
//   - wreq TlsOptions.curves_list      -> SupportedCurvesExtension.Curves
//   - wreq TlsOptions.sigalgs_list     -> SignatureAlgorithmsExtension
//   - wreq TlsOptions.alpn_protocols   -> ALPNExtension.AlpnProtocols
//   - wreq TlsOptions.alps_protocols   -> ApplicationSettingsExtension / New
//   - wreq TlsOptions.certificate_compressors -> UtlsCompressCertExtension
//   - wreq TlsOptions.grease_enabled   -> UtlsGREASEExtension 头尾插桩
//   - wreq TlsOptions.pre_shared_key   -> UtlsPreSharedKeyExtension
//   - wreq TlsOptions.enable_ech_grease-> BoringGREASEECH()
//   - wreq Http2Options.initial_window_size -> ClientProfile.connectionFlow
//   - wreq Http2Options.initial_connection_window_size -> settings[SettingInitialWindowSize]
//   - wreq Http2Options.headers_pseudo_order   -> pseudoHeaderOrder
//   - wreq Http2Options.settings_order         -> settingsOrder
//
// 每个 ExtraProfile 都对应 wreq-util 的 "v<版本号>" 模板；
// UA / sec-ch-ua 字符串见 header_presets.go 的 PresetHeadersByPlatform。

import (
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

// chromeH2Default 是 Chrome 130+ 的 H2 settings / pseudoHeader 模板。
// 来源：wreq-util chrome/tls.rs::http2_options!(@base ...) + chrome/http2.rs。
func chromeH2Default() (map[http2.SettingID]uint32, []http2.SettingID, []string, uint32) {
	settings := map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	}
	settingsOrder := []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
		http2.SettingEnableConnectProtocol,
		http2.SettingNoRFC7540Priorities,
	}
	pseudoHeaderOrder := []string{":method", ":authority", ":scheme", ":path"}
	connectionFlow := 15663105
	return settings, settingsOrder, pseudoHeaderOrder, uint32(connectionFlow)
}

// chromeCipherList 复刻 wreq-util chrome/tls.rs::CIPHER_LIST。
func chromeCipherList() []uint16 {
	return []uint16{
		tls.GREASE_PLACEHOLDER,
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}
}

// chromeSigAlgs 复刻 wreq-util chrome/tls.rs::SIGALGS_LIST。
func chromeSigAlgs() []tls.SignatureScheme {
	return []tls.SignatureScheme{
		tls.ECDSAWithP256AndSHA256,
		tls.PSSWithSHA256,
		tls.PKCS1WithSHA256,
		tls.ECDSAWithP384AndSHA384,
		tls.PSSWithSHA384,
		tls.PKCS1WithSHA384,
		tls.PSSWithSHA512,
		tls.PKCS1WithSHA512,
	}
}

// chromeCurvesWithGREASE 根据 wreq-util chrome/tls.rs::CURVES_1/2/3 决定曲线列表。
// pq == 0：CURVES_1（X25519/P-256/P-384）
// pq == 1：CURVES_2（X25519Kyber768Draft00 + X25519/P-256/P-384）
// pq == 2：CURVES_3（X25519MLKEM768 + X25519/P-256/P-384）
func chromeCurvesWithGREASE(pq int) []tls.CurveID {
	curves := make([]tls.CurveID, 0, 5)
	curves = append(curves, tls.CurveID(tls.GREASE_PLACEHOLDER))
	switch pq {
	case 1:
		curves = append(curves, tls.X25519Kyber768Draft00)
	case 2:
		curves = append(curves, tls.X25519MLKEM768)
	}
	curves = append(curves, tls.X25519, tls.CurveP256, tls.CurveP384)
	return curves
}

// chromeKeyShares 与 chromeCurvesWithGREASE 一一对应。
func chromeKeyShares(pq int) []tls.KeyShare {
	ks := make([]tls.KeyShare, 0, 3)
	ks = append(ks, tls.KeyShare{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}})
	switch pq {
	case 1:
		ks = append(ks, tls.KeyShare{Group: tls.X25519Kyber768Draft00})
	case 2:
		ks = append(ks, tls.KeyShare{Group: tls.X25519MLKEM768})
	}
	ks = append(ks, tls.KeyShare{Group: tls.X25519})
	return ks
}

// chrome132To148 给出 Chrome 132~148 的 ClientHelloSpec 工厂共性：
//   - 曲线/KeyShare 升级到 X25519MLKEM768（pq=2）
//   - 含 BoringGREASEECH()  +  SNI/ALPN/SCT/EM/PSK_MODE/...
//   - 支持 PSK 模式
//   - 应用层 ALPS (h2) 用 ApplicationSettingsExtensionNew
//
// 与 wreq-util chrome::tls_options!(7, CURVES_3) 对齐（"7" = permute + ECH + PSK + PQ curves + alps_new_codepoint）。
//
// 版本差异点：
//   - 124 之前 ApplicationSettingsExtension（"old"），124+ 之后 ApplicationSettingsExtensionNew
//   - 130 之前无 trust_anchors (0xca34) 扩展；130+ 加上
//   - 133 开始 PreSharedKey 扩展出现在最末
func chromeSpecFactory(version string, extensions []tls.TLSExtension) tls.ClientHelloID {
	return tls.ClientHelloID{
		Client:               "Chrome",
		RandomExtensionOrder: false,
		Version:              version,
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites:       chromeCipherList(),
				CompressionMethods: []byte{tls.CompressionNone},
				Extensions:         extensions,
			}, nil
		},
	}
}

// chromeBaseExtensions 返回 Chrome 132+ 通用 extension 切片骨架。
// tlsOptionsBits:
//   bit0: permute_extensions
//   bit1: ech_grease
//   bit2: pre_shared_key
//   bit3: alps_use_new_codepoint（>=124 必开）
func chromeBaseExtensions(pq int) []tls.TLSExtension {
	ext := []tls.TLSExtension{
		&tls.UtlsGREASEExtension{},
		&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: chromeSigAlgs()},
		&tls.SCTExtension{},
		&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}},
		&tls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
		&tls.SupportedVersionsExtension{Versions: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.VersionTLS13,
			tls.VersionTLS12,
		}},
		&tls.SupportedCurvesExtension{Curves: chromeCurvesWithGREASE(pq)},
		&tls.KeyShareExtension{KeyShares: chromeKeyShares(pq)},
		&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		&tls.StatusRequestExtension{},
		&tls.SNIExtension{},
		&tls.SessionTicketExtension{},
		&tls.ExtendedMasterSecretExtension{},
		&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
		&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
		&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
		tls.BoringGREASEECH(),
		&tls.UtlsGREASEExtension{},
	}
	return ext
}

// buildChromeProfile 把 version + pq 拼成一个 ClientProfile。
// pq 含义同 chromeCurvesWithGREASE。
func buildChromeProfile(name, version string, pq int) profiles.ClientProfile {
	settings, settingsOrder, pseudoHeaderOrder, connectionFlow := chromeH2Default()
	return profiles.NewClientProfile(
		chromeSpecFactory(version, chromeBaseExtensions(pq)),
		settings,
		settingsOrder,
		pseudoHeaderOrder,
		connectionFlow,
		nil, // priorities: Chrome 130+ 不再发 PUSH_PROMISE，H2 priorities 留空
		nil, // headerPriority
		0,   // streamID
		false,
		nil, nil, 0, nil, false,
	)
}

// ---- Chrome 132 / 134 / 136 / 138 / 140 / 142 / 145 / 147 / 148 ----
//
// 与 wreq-util chrome.rs 中 v132 / v134 / v136 / v138 / v140 / v142 /
// v145 / v147 / v148 对齐（这些版本 tls_client 1.15.1 仍未内置）。
// 所有 Chrome 132+ 都用 X25519MLKEM768 (pq=2)。

var extraChrome132 = buildChromeProfile("chrome_132", "132", 2)
var extraChrome134 = buildChromeProfile("chrome_134", "134", 2)
var extraChrome135 = buildChromeProfile("chrome_135", "135", 2)
var extraChrome136 = buildChromeProfile("chrome_136", "136", 2)
var extraChrome137 = buildChromeProfile("chrome_137", "137", 2)
var extraChrome138 = buildChromeProfile("chrome_138", "138", 2)
var extraChrome139 = buildChromeProfile("chrome_139", "139", 2)
var extraChrome140 = buildChromeProfile("chrome_140", "140", 2)
var extraChrome141 = buildChromeProfile("chrome_141", "141", 2)
var extraChrome142 = buildChromeProfile("chrome_142", "142", 2)
var extraChrome143 = buildChromeProfile("chrome_143", "143", 2)
var extraChrome145 = buildChromeProfile("chrome_145", "145", 2)
var extraChrome147 = buildChromeProfile("chrome_147", "147", 2)
var extraChrome148 = buildChromeProfile("chrome_148", "148", 2)

// extraChrome128 / extraChrome127 / extraChrome120 / extraChrome117 /
// extraChrome110 / extraChrome100 用 Kyber768Draft00 (pq=1) 旧版 PQ，
// 对应 wreq-util v128/v127/v120/v117/v110/v100 的 tls_options! 配方。
// 留作历史 profile，UA / sec-ch-ua 与之匹配。

var extraChrome128 = buildChromeProfile("chrome_128", "128", 1)
var extraChrome127 = buildChromeProfile("chrome_127", "127", 1)
var extraChrome120 = buildChromeProfile("chrome_120", "120", 1)
var extraChrome117 = buildChromeProfile("chrome_117", "117", 1)
var extraChrome110 = buildChromeProfile("chrome_110", "110", 1)
var extraChrome100 = buildChromeProfile("chrome_100", "100", 0)

// ---- Edge ----
//
// Edge 122 / 127 / 148：与 wreq-util edge122 / edge127 / edge148 对应。
// Edge 用同代 Chrome 的 ClientHelloSpec；UA / sec-ch-ua / Edg/xxx 标识
// 由 HeaderMap 区分（见 header_presets.go Edge 段）。

var extraEdge122 = buildChromeProfile("edge_122", "122", 1) // 122 = Chrome 122 同代
var extraEdge127 = buildChromeProfile("edge_127", "127", 1)
var extraEdge131 = buildChromeProfile("edge_131", "131", 2)
var extraEdge134 = buildChromeProfile("edge_134", "134", 2)
var extraEdge135 = buildChromeProfile("edge_135", "135", 2)
var extraEdge136 = buildChromeProfile("edge_136", "136", 2)
var extraEdge137 = buildChromeProfile("edge_137", "137", 2)
var extraEdge138 = buildChromeProfile("edge_138", "138", 2)
var extraEdge139 = buildChromeProfile("edge_139", "139", 2)
var extraEdge140 = buildChromeProfile("edge_140", "140", 2)
var extraEdge141 = buildChromeProfile("edge_141", "141", 2)
var extraEdge142 = buildChromeProfile("edge_142", "142", 2)
var extraEdge143 = buildChromeProfile("edge_143", "143", 2)
var extraEdge144 = buildChromeProfile("edge_144", "144", 2)
var extraEdge145 = buildChromeProfile("edge_145", "145", 2)
var extraEdge146 = buildChromeProfile("edge_146", "146", 2)
var extraEdge147 = buildChromeProfile("edge_147", "147", 2)
var extraEdge148 = buildChromeProfile("edge_148", "148", 2)

// ---- Firefox ----
//
// Firefox 132+ 才出现 X25519MLKEM768；142 之前用 X25519 起步，142+ 切 MLKEM。
// 对齐 wreq-util firefox.rs 中 ff142/ff145/ff147/ff149/ff151。
//
// 注意：tls-client 1.15.1 的 Firefox 缺：delegated_credentials / extension_permutation /
// record_size_limit / ffdhe2048/3072 curves — 这些 tls.ClientHelloSpec 字段没
// 显式 settable，只能通过 SpecFactory 内联设值。
// 我们用 Firefox_132 的 SpecFactory 模板做基线，逐字段调整。

func firefoxSpecFactory(version string, withMLKEM, withDelegated bool) tls.ClientHelloID {
	return tls.ClientHelloID{
		Client:               "Firefox",
		RandomExtensionOrder: false,
		Version:              version,
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			curves := []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
				tls.CurveP521,
				tls.FAKEFFDHE2048,
				tls.FAKEFFDHE3072,
			}
			keyShares := []tls.KeyShare{
				{Group: tls.X25519},
				{Group: tls.CurveP256},
			}
			if withMLKEM {
				// Firefox 142+ 在 SupportedCurves 头部插入 MLKEM
				mlkem := []tls.CurveID{tls.X25519MLKEM768}
				curves = append(mlkem, curves...)
				keyShares = []tls.KeyShare{
					{Group: tls.X25519MLKEM768},
					{Group: tls.X25519},
					{Group: tls.CurveP256},
				}
			}

			ext := []tls.TLSExtension{
				&tls.SNIExtension{},
				&tls.ExtendedMasterSecretExtension{},
				&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
				&tls.SupportedCurvesExtension{Curves: curves},
				&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
				&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&tls.StatusRequestExtension{},
				&tls.KeyShareExtension{KeyShares: keyShares},
				&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}},
				&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithP521AndSHA512,
					tls.PSSWithSHA256,
					tls.PSSWithSHA384,
					tls.PSSWithSHA512,
					tls.PKCS1WithSHA256,
					tls.PKCS1WithSHA384,
					tls.PKCS1WithSHA512,
					tls.ECDSAWithSHA1,
					tls.PKCS1WithSHA1,
				}},
				&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
				&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
				&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
					tls.CertCompressionZlib,
					tls.CertCompressionBrotli,
					tls.CertCompressionZstd,
				}},
				&tls.SCTExtension{},
			}
			if withDelegated {
				ext = append(ext, &tls.DelegatedCredentialsExtension{
					SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.ECDSAWithSHA1,
					},
				})
			}
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{tls.CompressionNone},
				Extensions:         ext,
			}, nil
		},
	}
}

func buildFirefoxProfile(name, version string, withMLKEM, withDelegated bool) profiles.ClientProfile {
	// Firefox H2 模板：initial_window_size=131072
	// initial_connection_window_size 在 wreq 里是 12517377+65535=12582912，
	// fhttp/http2 没独立的 connection-level setting（与 stream-level 共用
	// SettingInitialWindowSize），所以这里只发一个 SettingInitialWindowSize
	// 而把 connection-level 窗口设置省略。
	settings := map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
	}
	settingsOrder := []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
		http2.SettingEnableConnectProtocol,
		http2.SettingNoRFC7540Priorities,
	}
	pseudoHeaderOrder := []string{":method", ":path", ":authority", ":scheme"}
	return profiles.NewClientProfile(
		firefoxSpecFactory(version, withMLKEM, withDelegated),
		settings,
		settingsOrder,
		pseudoHeaderOrder,
		131072, // connectionFlow
		nil,
		nil,
		3, // initial_stream_id (Firefox 默认 3)
		false,
		nil, nil, 0, nil, false,
	)
}

var extraFirefox142 = buildFirefoxProfile("firefox_142", "142", true, true)
var extraFirefox143 = buildFirefoxProfile("firefox_143", "143", true, true)
var extraFirefox144 = buildFirefoxProfile("firefox_144", "144", true, true)
var extraFirefox145 = buildFirefoxProfile("firefox_145", "145", true, true)
var extraFirefox146 = buildFirefoxProfile("firefox_146", "146", true, true)
var extraFirefox147 = buildFirefoxProfile("firefox_147", "147", true, true)
var extraFirefox149 = buildFirefoxProfile("firefox_149", "149", true, true)
var extraFirefox150 = buildFirefoxProfile("firefox_150", "150", true, true)
var extraFirefox151 = buildFirefoxProfile("firefox_151", "151", true, true)
var extraFirefox139 = buildFirefoxProfile("firefox_139", "139", false, true)
var extraFirefox136 = buildFirefoxProfile("firefox_136", "136", false, true)
var extraFirefox135 = buildFirefoxProfile("firefox_135", "135", false, true)
var extraFirefox128 = buildFirefoxProfile("firefox_128", "128", false, true)
var extraFirefox109 = buildFirefoxProfile("firefox_109", "109", false, false)

// ---- Safari / iOS ----
//
// Safari 17.x / 18.x / 26.x 与 iOS 同代复刻。来自 wreq-util safari.rs。
// Safari 18+ 加 X25519MLKEM768；TLS 1.3 + ALPN h2 + ESNI/SCT 与 Chrome 类似。
// 此处给一个最常用的"macOS Safari"版；iOS 版本 UA 走 header 区分。

func safariSpecFactory(version string) tls.ClientHelloID {
	return tls.ClientHelloID{
		Client:               "Safari",
		RandomExtensionOrder: false,
		Version:              version,
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{tls.CompressionNone},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: chromeSigAlgs()},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
						tls.CertCompressionBrotli,
						tls.CertCompressionZstd,
					}},
					&tls.SCTExtension{},
					&tls.UtlsGREASEExtension{},
				},
			}, nil
		},
	}
}

func buildSafariProfile(name, version string) profiles.ClientProfile {
	// Safari H2 与 Chrome 接近，但最大并发流略小。
	settings := map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 100,
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxHeaderListSize:    65536,
	}
	settingsOrder := []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
		http2.SettingEnableConnectProtocol,
		http2.SettingNoRFC7540Priorities,
	}
	pseudoHeaderOrder := []string{":method", ":authority", ":scheme", ":path"}
	return profiles.NewClientProfile(
		safariSpecFactory(version),
		settings,
		settingsOrder,
		pseudoHeaderOrder,
		2097152,
		nil, nil, 0, false, nil, nil, 0, nil, false,
	)
}

var extraSafari17_0 = buildSafariProfile("safari_17.0", "17.0")
var extraSafari17_2_1 = buildSafariProfile("safari_17.2.1", "17.2.1")
var extraSafari17_4_1 = buildSafariProfile("safari_17.4.1", "17.4.1")
var extraSafari17_5 = buildSafariProfile("safari_17.5", "17.5")
var extraSafari17_6 = buildSafariProfile("safari_17.6", "17.6")
var extraSafari18 = buildSafariProfile("safari_18", "18")
var extraSafari18_2 = buildSafariProfile("safari_18.2", "18.2")
var extraSafari18_3 = buildSafariProfile("safari_18.3", "18.3")
var extraSafari18_3_1 = buildSafariProfile("safari_18.3.1", "18.3.1")
var extraSafari18_5 = buildSafariProfile("safari_18.5", "18.5")
var extraSafari26 = buildSafariProfile("safari_26", "26")
var extraSafari26_1 = buildSafariProfile("safari_26.1", "26.1")
var extraSafari26_2 = buildSafariProfile("safari_26.2", "26.2")
var extraSafari26_3 = buildSafariProfile("safari_26.3", "26.3")
var extraSafari26_4 = buildSafariProfile("safari_26.4", "26.4")
var extraSafari16_5 = buildSafariProfile("safari_16.5", "16.5")
var extraSafari15_3 = buildSafariProfile("safari_15.3", "15.3")
var extraSafari15_5 = buildSafariProfile("safari_15.5", "15.5")
var extraSafariIpad18 = buildSafariProfile("safari_ipad_18", "18_ipad")
var extraSafariIpad26 = buildSafariProfile("safari_ipad_26", "26_ipad")
var extraSafariIpad26_2 = buildSafariProfile("safari_ipad_26.2", "26.2_ipad")
var extraSafariIos17_2 = buildSafariProfile("safari_ios_17.2", "ios_17.2")
var extraSafariIos17_4_1 = buildSafariProfile("safari_ios_17.4.1", "ios_17.4.1")
var extraSafariIos16_5 = buildSafariProfile("safari_ios_16.5", "ios_16.5")
var extraSafariIos18_1_1 = buildSafariProfile("safari_ios_18.1.1", "ios_18.1.1")
var extraSafariIos26 = buildSafariProfile("safari_ios_26", "ios_26")
var extraSafariIos26_2 = buildSafariProfile("safari_ios_26.2", "ios_26.2")
var extraSafariIpad15_6 = buildSafariProfile("safari_ipad_15.6", "ipad_15.6")

// ---- Opera ----
//
// Opera 是 Chromium 内核，TLS 复刻 Chrome；UA / sec-ch-ua 走 HeaderMap 区分。

var extraOpera116 = buildChromeProfile("opera_116", "116", 1)
var extraOpera117 = buildChromeProfile("opera_117", "117", 1)
var extraOpera118 = buildChromeProfile("opera_118", "118", 1)
var extraOpera119 = buildChromeProfile("opera_119", "119", 1)
var extraOpera120 = buildChromeProfile("opera_120", "120", 1)
var extraOpera121 = buildChromeProfile("opera_121", "121", 1)
var extraOpera122 = buildChromeProfile("opera_122", "122", 1)
var extraOpera123 = buildChromeProfile("opera_123", "123", 1)
var extraOpera124 = buildChromeProfile("opera_124", "124", 1)
var extraOpera125 = buildChromeProfile("opera_125", "125", 1)
var extraOpera126 = buildChromeProfile("opera_126", "126", 1)
var extraOpera127 = buildChromeProfile("opera_127", "127", 1)
var extraOpera128 = buildChromeProfile("opera_128", "128", 1)
var extraOpera129 = buildChromeProfile("opera_129", "129", 1)
var extraOpera130 = buildChromeProfile("opera_130", "130", 2)
var extraOpera131 = buildChromeProfile("opera_131", "131", 2)

// ---- OkHttp ----
//
// OkHttp 3.x / 4.x / 5 都基于 BoringSSL OkHttp / Conscrypt 的 TLS 栈，
// 与 Chrome TLS 类似但省略 ECH/PSK/ALPS。对齐 wreq-util okhttp.rs。

func okhttpSpecFactory(version string) tls.ClientHelloID {
	return tls.ClientHelloID{
		Client:               "OkHttp",
		RandomExtensionOrder: false,
		Version:              version,
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{tls.CompressionNone},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
				},
			}, nil
		},
	}
}

func buildOkHttpProfile(name, version string) profiles.ClientProfile {
	// OkHttp H2：initial_window_size=16777216, settings_order 与 Chrome 一致
	settings := map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    16777216,
		http2.SettingMaxFrameSize:         16384,
		http2.SettingMaxHeaderListSize:    262144,
	}
	settingsOrder := []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
		http2.SettingEnableConnectProtocol,
		http2.SettingNoRFC7540Priorities,
	}
	pseudoHeaderOrder := []string{":method", ":path", ":authority", ":scheme"}
	return profiles.NewClientProfile(
		okhttpSpecFactory(version),
		settings,
		settingsOrder,
		pseudoHeaderOrder,
		16777216,
		nil, nil, 0, false, nil, nil, 0, nil, false,
	)
}

var extraOkHttp3_9 = buildOkHttpProfile("okhttp_3.9", "3.9")
var extraOkHttp3_11 = buildOkHttpProfile("okhttp_3.11", "3.11")
var extraOkHttp3_13 = buildOkHttpProfile("okhttp_3.13", "3.13")
var extraOkHttp3_14 = buildOkHttpProfile("okhttp_3.14", "3.14")
var extraOkHttp4_9 = buildOkHttpProfile("okhttp_4.9", "4.9")
var extraOkHttp4_10 = buildOkHttpProfile("okhttp_4.10", "4.10")
var extraOkHttp4_12 = buildOkHttpProfile("okhttp_4.12", "4.12")
var extraOkHttp5 = buildOkHttpProfile("okhttp_5", "5")

// ---- ExtraProfiles 索引 ----
//
// 入口在 NewClient 的 ClientOption.ExtraProfile
// 与 ProfileMap 命中失败时回落到这里。

// ExtraProfiles 按 wreq-util "profile_<version>" 命名规范给出名字到
// profiles.ClientProfile 的映射。所有 key 都是小写。
var ExtraProfiles = map[string]profiles.ClientProfile{
	// Chrome
	"chrome_100": extraChrome100,
	"chrome_110": extraChrome110,
	"chrome_117": extraChrome117,
	"chrome_120": extraChrome120,
	"chrome_127": extraChrome127,
	"chrome_128": extraChrome128,
	"chrome_132": extraChrome132,
	"chrome_134": extraChrome134,
	"chrome_135": extraChrome135,
	"chrome_136": extraChrome136,
	"chrome_137": extraChrome137,
	"chrome_138": extraChrome138,
	"chrome_139": extraChrome139,
	"chrome_140": extraChrome140,
	"chrome_141": extraChrome141,
	"chrome_142": extraChrome142,
	"chrome_143": extraChrome143,
	"chrome_145": extraChrome145,
	"chrome_147": extraChrome147,
	"chrome_148": extraChrome148,

	// Edge
	"edge_122": extraEdge122,
	"edge_127": extraEdge127,
	"edge_131": extraEdge131,
	"edge_134": extraEdge134,
	"edge_135": extraEdge135,
	"edge_136": extraEdge136,
	"edge_137": extraEdge137,
	"edge_138": extraEdge138,
	"edge_139": extraEdge139,
	"edge_140": extraEdge140,
	"edge_141": extraEdge141,
	"edge_142": extraEdge142,
	"edge_143": extraEdge143,
	"edge_144": extraEdge144,
	"edge_145": extraEdge145,
	"edge_146": extraEdge146,
	"edge_147": extraEdge147,
	"edge_148": extraEdge148,

	// Firefox
	"firefox_109": extraFirefox109,
	"firefox_128": extraFirefox128,
	"firefox_135": extraFirefox135,
	"firefox_136": extraFirefox136,
	"firefox_139": extraFirefox139,
	"firefox_142": extraFirefox142,
	"firefox_143": extraFirefox143,
	"firefox_144": extraFirefox144,
	"firefox_145": extraFirefox145,
	"firefox_146": extraFirefox146,
	"firefox_147": extraFirefox147,
	"firefox_149": extraFirefox149,
	"firefox_150": extraFirefox150,
	"firefox_151": extraFirefox151,

	// Safari
	"safari_15.3":  extraSafari15_3,
	"safari_15.5":  extraSafari15_5,
	"safari_16.5":  extraSafari16_5,
	"safari_17.0":  extraSafari17_0,
	"safari_17.2.1": extraSafari17_2_1,
	"safari_17.4.1": extraSafari17_4_1,
	"safari_17.5":  extraSafari17_5,
	"safari_17.6":  extraSafari17_6,
	"safari_18":    extraSafari18,
	"safari_18.2":  extraSafari18_2,
	"safari_18.3":  extraSafari18_3,
	"safari_18.3.1": extraSafari18_3_1,
	"safari_18.5":  extraSafari18_5,
	"safari_26":    extraSafari26,
	"safari_26.1":  extraSafari26_1,
	"safari_26.2":  extraSafari26_2,
	"safari_26.3":  extraSafari26_3,
	"safari_26.4":  extraSafari26_4,
	"safari_ipad_15.6": extraSafariIpad15_6,
	"safari_ipad_18":   extraSafariIpad18,
	"safari_ipad_26":   extraSafariIpad26,
	"safari_ipad_26.2": extraSafariIpad26_2,
	"safari_ios_16.5":  extraSafariIos16_5,
	"safari_ios_17.2":  extraSafariIos17_2,
	"safari_ios_17.4.1": extraSafariIos17_4_1,
	"safari_ios_18.1.1": extraSafariIos18_1_1,
	"safari_ios_26":   extraSafariIos26,
	"safari_ios_26.2": extraSafariIos26_2,

	// Opera
	"opera_116": extraOpera116,
	"opera_117": extraOpera117,
	"opera_118": extraOpera118,
	"opera_119": extraOpera119,
	"opera_120": extraOpera120,
	"opera_121": extraOpera121,
	"opera_122": extraOpera122,
	"opera_123": extraOpera123,
	"opera_124": extraOpera124,
	"opera_125": extraOpera125,
	"opera_126": extraOpera126,
	"opera_127": extraOpera127,
	"opera_128": extraOpera128,
	"opera_129": extraOpera129,
	"opera_130": extraOpera130,
	"opera_131": extraOpera131,

	// OkHttp
	"okhttp_3.9":  extraOkHttp3_9,
	"okhttp_3.11": extraOkHttp3_11,
	"okhttp_3.13": extraOkHttp3_13,
	"okhttp_3.14": extraOkHttp3_14,
	"okhttp_4.9":  extraOkHttp4_9,
	"okhttp_4.10": extraOkHttp4_10,
	"okhttp_4.12": extraOkHttp4_12,
	"okhttp_5":    extraOkHttp5,
}

// GetExtraProfile 返回 wreq-util 风格的 profile 名对应的 ClientProfile。
// 当 tls-client 内置 ProfileMap 找不到时由 NewClient 调用。
func GetExtraProfile(name string) (profiles.ClientProfile, bool) {
	p, ok := ExtraProfiles[name]
	return p, ok
}

// ListExtraProfileNames 列出所有可用的 wreq-util 风格 profile 名。
func ListExtraProfileNames() []string {
	out := make([]string, 0, len(ExtraProfiles))
	for k := range ExtraProfiles {
		out = append(out, k)
	}
	return out
}

// _ 让 tls_client 仍被引用（防止 go mod tidy 误删）
var _ = profiles.DefaultClientProfile
