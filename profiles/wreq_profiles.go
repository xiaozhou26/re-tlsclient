package profiles

import (
	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
)

// ============================================================================
// Wreq-based Browser Profiles
// Fingerprints ported from https://github.com/0x676e67/wreq-util
// ============================================================================

// --- Shared HTTP/2 Settings (matching wreq Chrome http2_options! macros) ---

// http2Type1: v100-v105, v110 (max_concurrent_streams=1000, push=true)
var h2SettingsType1 = map[http2.SettingID]uint32{
	http2.SettingHeaderTableSize:      65536,
	http2.SettingEnablePush:           1,
	http2.SettingMaxConcurrentStreams: 1000,
	http2.SettingInitialWindowSize:    6291456,
	http2.SettingMaxHeaderListSize:    262144,
}

var h2SettingsOrderType1 = []http2.SettingID{
	http2.SettingHeaderTableSize,
	http2.SettingEnablePush,
	http2.SettingMaxConcurrentStreams,
	http2.SettingInitialWindowSize,
	http2.SettingMaxHeaderListSize,
}

// http2Type2: v106-v116 (max_concurrent_streams=1000, push=false)
var h2SettingsType2 = map[http2.SettingID]uint32{
	http2.SettingHeaderTableSize:      65536,
	http2.SettingEnablePush:           0,
	http2.SettingMaxConcurrentStreams: 1000,
	http2.SettingInitialWindowSize:    6291456,
	http2.SettingMaxHeaderListSize:    262144,
}

var h2SettingsOrderType2 = []http2.SettingID{
	http2.SettingHeaderTableSize,
	http2.SettingEnablePush,
	http2.SettingMaxConcurrentStreams,
	http2.SettingInitialWindowSize,
	http2.SettingMaxHeaderListSize,
}

// http2Type3: v117+ (push=false, no max_concurrent_streams, no max_frame_size)
var h2SettingsType3 = map[http2.SettingID]uint32{
	http2.SettingHeaderTableSize:   65536,
	http2.SettingEnablePush:        0,
	http2.SettingInitialWindowSize: 6291456,
	http2.SettingMaxHeaderListSize: 262144,
}

var h2SettingsOrderType3 = []http2.SettingID{
	http2.SettingHeaderTableSize,
	http2.SettingEnablePush,
	http2.SettingInitialWindowSize,
	http2.SettingMaxHeaderListSize,
}

// pseudoHeaderOrder matching wreq: :method, :authority, :scheme, :path
var chromePseudoOrder = []string{":method", ":authority", ":scheme", ":path"}

// connectionFlow matching real Chrome: 15663105
const chromeConnFlow uint32 = 15663105

// --- Shared TLS Configurations ---

// Chrome cipher suites from wreq CIPHER_LIST
var chromeCipherSuites = []uint16{
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

// Chrome signature algorithms from wreq SIGALGS_LIST
var chromeSigAlgs = []tls.SignatureScheme{
	tls.ECDSAWithP256AndSHA256,
	tls.PSSWithSHA256,
	tls.PKCS1WithSHA256,
	tls.ECDSAWithP384AndSHA384,
	tls.PSSWithSHA384,
	tls.PKCS1WithSHA384,
	tls.PSSWithSHA512,
	tls.PKCS1WithSHA512,
}

// CURVES_1: X25519, P-256, P-384 (v100-v105, v110)
var chromeCurvesV1 = []tls.CurveID{
	tls.GREASE_PLACEHOLDER,
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
}

// CURVES_2: X25519Kyber768Draft00, X25519, P-256, P-384 (v124)
var chromeCurvesV2 = []tls.CurveID{
	tls.GREASE_PLACEHOLDER,
	tls.X25519Kyber768Draft00,
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
}

// CURVES_3: X25519MLKEM768, X25519, P-256, P-384 (v131+)
var chromeCurvesV3 = []tls.CurveID{
	tls.GREASE_PLACEHOLDER,
	tls.X25519MLKEM768,
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
}

// Key shares matching curves
var chromeKeySharesV1 = []tls.KeyShare{
	{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
	{Group: tls.X25519},
}

var chromeKeySharesV2 = []tls.KeyShare{
	{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
	{Group: tls.X25519Kyber768Draft00},
	{Group: tls.X25519},
}

var chromeKeySharesV3 = []tls.KeyShare{
	{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
	{Group: tls.X25519MLKEM768},
	{Group: tls.X25519},
}

// --- Profile Builders (matching wreq tls_options! variants) ---

// copyKeyShares deep-copies a KeyShare slice to prevent uTLS from mutating
// the shared global variables during TLS handshakes. Each handshake generates
// ephemeral key material and writes it into KeyShare.Data; without copying,
// the second handshake sees stale/corrupted key data and fails with
// "local error: tls: internal error".
func copyKeyShares(src []tls.KeyShare) []tls.KeyShare {
	dst := make([]tls.KeyShare, len(src))
	for i, ks := range src {
		var data []byte
		if len(ks.Data) > 0 {
			data = make([]byte, len(ks.Data))
			copy(data, ks.Data)
		}
		dst[i] = tls.KeyShare{Group: ks.Group, Data: data}
	}
	return dst
}

// tlsType1: base Chrome TLS (v100-v104, v110)
func makeChromeTLSType1() []tls.TLSExtension {
	return []tls.TLSExtension{
		&tls.UtlsGREASEExtension{},
		&tls.SNIExtension{},
		&tls.ExtendedMasterSecretExtension{},
		&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
		&tls.SupportedCurvesExtension{Curves: chromeCurvesV1},
		&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
		&tls.SessionTicketExtension{},
		&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		&tls.StatusRequestExtension{},
		&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: chromeSigAlgs},
		&tls.SCTExtension{},
		&tls.KeyShareExtension{KeyShares: copyKeyShares(chromeKeySharesV1)},
		&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
		&tls.SupportedVersionsExtension{Versions: []uint16{
			tls.GREASE_PLACEHOLDER, tls.VersionTLS13, tls.VersionTLS12,
		}},
		&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}},
		&tls.UtlsGREASEExtension{},
		&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
	}
}

// tlsType2: +ECH GREASE (v105)
func makeChromeTLSType2() []tls.TLSExtension {
	return []tls.TLSExtension{
		&tls.UtlsGREASEExtension{},
		&tls.SNIExtension{},
		&tls.ExtendedMasterSecretExtension{},
		&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
		&tls.SupportedCurvesExtension{Curves: chromeCurvesV1},
		&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
		&tls.SessionTicketExtension{},
		&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		&tls.StatusRequestExtension{},
		&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: chromeSigAlgs},
		&tls.SCTExtension{},
		&tls.KeyShareExtension{KeyShares: copyKeyShares(chromeKeySharesV1)},
		&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
		&tls.SupportedVersionsExtension{Versions: []uint16{
			tls.GREASE_PLACEHOLDER, tls.VersionTLS13, tls.VersionTLS12,
		}},
		&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}},
		tls.BoringGREASEECH(),
		&tls.UtlsGREASEExtension{},
		&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
	}
}

// tlsType3: +permute (v106-v109, v114)
func makeChromeTLSType3() []tls.TLSExtension {
	return []tls.TLSExtension{
		&tls.UtlsGREASEExtension{},
		&tls.SNIExtension{},
		&tls.ExtendedMasterSecretExtension{},
		&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
		&tls.SupportedCurvesExtension{Curves: chromeCurvesV1},
		&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
		&tls.SessionTicketExtension{},
		&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		&tls.StatusRequestExtension{},
		&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: chromeSigAlgs},
		&tls.SCTExtension{},
		&tls.KeyShareExtension{KeyShares: copyKeyShares(chromeKeySharesV1)},
		&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
		&tls.SupportedVersionsExtension{Versions: []uint16{
			tls.GREASE_PLACEHOLDER, tls.VersionTLS13, tls.VersionTLS12,
		}},
		&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}},
		&tls.UtlsGREASEExtension{},
		&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
	}
}

// tlsType4: +permute +ECH (v116, v118-v119)
func makeChromeTLSType4() []tls.TLSExtension {
	return []tls.TLSExtension{
		&tls.UtlsGREASEExtension{},
		&tls.SNIExtension{},
		&tls.ExtendedMasterSecretExtension{},
		&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
		&tls.SupportedCurvesExtension{Curves: chromeCurvesV1},
		&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
		&tls.SessionTicketExtension{},
		&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		&tls.StatusRequestExtension{},
		&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: chromeSigAlgs},
		&tls.SCTExtension{},
		&tls.KeyShareExtension{KeyShares: copyKeyShares(chromeKeySharesV1)},
		&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
		&tls.SupportedVersionsExtension{Versions: []uint16{
			tls.GREASE_PLACEHOLDER, tls.VersionTLS13, tls.VersionTLS12,
		}},
		&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}},
		tls.BoringGREASEECH(),
		&tls.UtlsGREASEExtension{},
		&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
	}
}

// tlsType5: +permute +ECH +PSK (v117, v120-v123)
// Extension order matches real Chrome (verified against bogdanfinn/tls-client).
func makeChromeTLSType5() []tls.TLSExtension {
	return []tls.TLSExtension{
		&tls.UtlsGREASEExtension{},
		&tls.KeyShareExtension{KeyShares: copyKeyShares(chromeKeySharesV1)},
		&tls.SNIExtension{},
		&tls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
		&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
		&tls.SupportedCurvesExtension{Curves: chromeCurvesV1},
		&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}},
		&tls.SessionTicketExtension{},
		&tls.StatusRequestExtension{},
		&tls.ExtendedMasterSecretExtension{},
		&tls.SupportedVersionsExtension{Versions: []uint16{
			tls.GREASE_PLACEHOLDER, tls.VersionTLS13, tls.VersionTLS12,
		}},
		&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: chromeSigAlgs},
		&tls.SCTExtension{},
		&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
		tls.BoringGREASEECH(),
		&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
		&tls.UtlsGREASEExtension{},
		&tls.UtlsPreSharedKeyExtension{},
	}
}

// tlsType6: +permute +ECH +CURVES_3 +ALPS_new +PSK (v124-v131)
// Extension order matches real Chrome (verified against wreq-util).
// trust_anchors extension (0xca34) only for Chrome 146+.
func makeChromeTLSType6(curves []tls.CurveID, keyShares []tls.KeyShare, alpsNew bool, psk bool, trustAnchors bool) []tls.TLSExtension {
	var alps tls.TLSExtension
	if alpsNew {
		alps = &tls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}
	} else {
		alps = &tls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}}
	}

	exts := []tls.TLSExtension{
		&tls.UtlsGREASEExtension{},
		&tls.KeyShareExtension{KeyShares: copyKeyShares(keyShares)},
		&tls.SNIExtension{},
		alps,
		&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
		&tls.SupportedCurvesExtension{Curves: curves},
		&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli}},
		&tls.SessionTicketExtension{},
		&tls.StatusRequestExtension{},
		&tls.ExtendedMasterSecretExtension{},
		&tls.SupportedVersionsExtension{Versions: []uint16{
			tls.GREASE_PLACEHOLDER, tls.VersionTLS13, tls.VersionTLS12,
		}},
		&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: chromeSigAlgs},
		&tls.SCTExtension{},
		&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
		tls.BoringGREASEECH(),
		&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
	}

	if trustAnchors {
		exts = append(exts, &tls.GenericExtension{Id: 0xca34, Data: []byte{0x00, 0x00}}) // trust_anchors (Chrome 146+)
	}

	exts = append(exts, &tls.UtlsGREASEExtension{})

	if psk {
		exts = append(exts, &tls.UtlsPreSharedKeyExtension{})
	}

	return exts
}

// tlsType7: +permute +ECH +CURVES_3 +ALPS_new_codepoint +PSK (v132+)
// Extension order matches real Chrome (verified against wreq-util).
// trust_anchors extension (0xca34) only for Chrome 146+.
func makeChromeTLSType7(curves []tls.CurveID, keyShares []tls.KeyShare, psk bool, trustAnchors bool) []tls.TLSExtension {
	return makeChromeTLSType6(curves, keyShares, true, psk, trustAnchors)
}

// --- Helper to create a ClientProfile ---

func makeChromeProfile(version string, settings map[http2.SettingID]uint32, settingsOrder []http2.SettingID, extsFn func() []tls.TLSExtension) ClientProfile {
	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Chrome",
			RandomExtensionOrder: false,
			Version:              version,
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites:       chromeCipherSuites,
					CompressionMethods: []byte{tls.CompressionNone},
					Extensions:         extsFn(),
					GetSessionID:       nil,
				}, nil
			},
		},
		settings:          settings,
		settingsOrder:     settingsOrder,
		pseudoHeaderOrder: chromePseudoOrder,
		connectionFlow:    chromeConnFlow,
		priorities: []http2.Priority{
			{StreamID: 0, PriorityParam: http2.PriorityParam{StreamDep: 0, Exclusive: true, Weight: 219}},
		},
		headerPriority: &http2.PriorityParam{
			StreamDep: 0,
			Exclusive: true,
			Weight:    219,
		},
		streamID:  1,
		allowHTTP: false,
	}
}

// ============================================================================
// Chrome Profiles (matching wreq Chrome versions)
// ============================================================================

// Chrome 100: tlsType1, http2Type1
var Chrome_100 = makeChromeProfile("100", h2SettingsType1, h2SettingsOrderType1, makeChromeTLSType1)

// Chrome 101: same as 100 (tlsType1, http2Type1)
var Chrome_101 = makeChromeProfile("101", h2SettingsType1, h2SettingsOrderType1, makeChromeTLSType1)

// Chrome 104: same as 100 (tlsType1, http2Type1)
var Chrome_104 = makeChromeProfile("104", h2SettingsType1, h2SettingsOrderType1, makeChromeTLSType1)

// Chrome 105: tlsType2 (+ECH GREASE), http2Type1
var Chrome_105 = makeChromeProfile("105", h2SettingsType1, h2SettingsOrderType1, makeChromeTLSType2)

// Chrome 106: tlsType3 (+permute), http2Type2 (push=false)
var Chrome_106 = makeChromeProfile("106", h2SettingsType2, h2SettingsOrderType2, makeChromeTLSType3)

// Chrome 107: same as 106
var Chrome_107 = makeChromeProfile("107", h2SettingsType2, h2SettingsOrderType2, makeChromeTLSType3)

// Chrome 108: same as 106
var Chrome_108 = makeChromeProfile("108", h2SettingsType2, h2SettingsOrderType2, makeChromeTLSType3)

// Chrome 109: same as 106
var Chrome_109 = makeChromeProfile("109", h2SettingsType2, h2SettingsOrderType2, makeChromeTLSType3)

// Chrome 110: same as 100 (tlsType1, http2Type1)
var Chrome_110 = makeChromeProfile("110", h2SettingsType1, h2SettingsOrderType1, makeChromeTLSType1)

// Chrome 114: same as 106
var Chrome_114 = makeChromeProfile("114", h2SettingsType2, h2SettingsOrderType2, makeChromeTLSType3)

// Chrome 116: tlsType4 + http2Type2
var Chrome_116 = makeChromeProfile("116", h2SettingsType2, h2SettingsOrderType2, makeChromeTLSType4)

// Chrome 117: tlsType5 + http2Type3
var Chrome_117 = makeChromeProfile("117", h2SettingsType3, h2SettingsOrderType3, makeChromeTLSType5)

// Chrome 118: tlsType4 + http2Type3
var Chrome_118 = makeChromeProfile("118", h2SettingsType3, h2SettingsOrderType3, makeChromeTLSType4)

// Chrome 119: same as 118
var Chrome_119 = makeChromeProfile("119", h2SettingsType3, h2SettingsOrderType3, makeChromeTLSType4)

// Chrome 120: tlsType5 + http2Type3
var Chrome_120 = makeChromeProfile("120", h2SettingsType3, h2SettingsOrderType3, makeChromeTLSType5)

// Chrome 123: same as 117 (tlsType5)
var Chrome_123 = makeChromeProfile("123", h2SettingsType3, h2SettingsOrderType3, makeChromeTLSType5)

// Chrome 124: tlsType6 + CURVES_2 + http2Type3 + PSK
var Chrome_124 = makeChromeProfile("124", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType6(chromeCurvesV2, chromeKeySharesV2, false, true, false) })

// Chrome 126: same as 124
var Chrome_126 = makeChromeProfile("126", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType6(chromeCurvesV2, chromeKeySharesV2, false, true, false) })

// Chrome 127: same as 124
var Chrome_127 = makeChromeProfile("127", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType6(chromeCurvesV2, chromeKeySharesV2, false, true, false) })

// Chrome 128: same as 124
var Chrome_128 = makeChromeProfile("128", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType6(chromeCurvesV2, chromeKeySharesV2, false, true, false) })

// Chrome 129: same as 124
var Chrome_129 = makeChromeProfile("129", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType6(chromeCurvesV2, chromeKeySharesV2, false, true, false) })

// Chrome 130: same as 124
var Chrome_130 = makeChromeProfile("130", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType6(chromeCurvesV2, chromeKeySharesV2, false, true, false) })

// Chrome 131: tlsType6 + CURVES_3 + http2Type3 + PSK
var Chrome_131 = makeChromeProfile("131", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType6(chromeCurvesV3, chromeKeySharesV3, false, true, false) })

// Chrome 132: tlsType7 + CURVES_3 + http2Type3 + PSK (new ALPS codepoint)
var Chrome_132 = makeChromeProfile("132", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, false) })

// Chrome 133-145: same as 132
var Chrome_133 = makeChromeProfile("133", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, false) })

var Chrome_134 = makeChromeProfile("134", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, false) })

var Chrome_135 = makeChromeProfile("135", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, false) })

var Chrome_136 = makeChromeProfile("136", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, false) })

var Chrome_137 = makeChromeProfile("137", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, false) })

var Chrome_138 = makeChromeProfile("138", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, false) })

var Chrome_139 = makeChromeProfile("139", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, false) })

var Chrome_140 = makeChromeProfile("140", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, false) })

var Chrome_141 = makeChromeProfile("141", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, false) })

var Chrome_142 = makeChromeProfile("142", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, false) })

var Chrome_143 = makeChromeProfile("143", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, false) })

var Chrome_144 = makeChromeProfile("144", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, false) })

var Chrome_145 = makeChromeProfile("145", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, false) })

// Chrome 146-148: trust_anchors (0xca34) included for Chrome 146+ with PSK
var Chrome_146 = makeChromeProfile("146", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, true) })

var Chrome_147 = makeChromeProfile("147", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, true) })

var Chrome_148 = makeChromeProfile("148", h2SettingsType3, h2SettingsOrderType3,
	func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, true) })

// ============================================================================
// Edge Profiles (use Chrome TLS but Edge-style HTTP/2)
// ============================================================================

func makeEdgeProfile(version string, trustAnchors bool) ClientProfile {
	return makeChromeProfile("Edge_"+version, h2SettingsType3, h2SettingsOrderType3,
		func() []tls.TLSExtension { return makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, trustAnchors) })
}

var Edge_131 = makeEdgeProfile("131", false)
var Edge_134 = makeEdgeProfile("134", false)
var Edge_135 = makeEdgeProfile("135", false)
var Edge_136 = makeEdgeProfile("136", false)
var Edge_137 = makeEdgeProfile("137", false)
var Edge_138 = makeEdgeProfile("138", false)
var Edge_139 = makeEdgeProfile("139", false)
var Edge_140 = makeEdgeProfile("140", false)
var Edge_141 = makeEdgeProfile("141", false)
var Edge_142 = makeEdgeProfile("142", false)
var Edge_143 = makeEdgeProfile("143", false)
var Edge_144 = makeEdgeProfile("144", false)
var Edge_145 = makeEdgeProfile("145", false)
var Edge_146 = makeEdgeProfile("146", true)
var Edge_147 = makeEdgeProfile("147", true)
var Edge_148 = makeEdgeProfile("148", true)

// ============================================================================
// Safari Profiles (based on wreq safari/tls.rs and safari/http2.rs)
// ============================================================================

// Safari cipher suites from wreq CIPHER_LIST_2 (Safari 15.6.1+)
// TLS 1.3 ciphers: AES_128_GCM, AES_256_GCM, CHACHA20
// TLS 1.2 ciphers: ECDHE_ECDSA/RSA with AES_256_GCM, AES_128_GCM, CHACHA20, AES_256_CBC_SHA, AES_128_CBC_SHA
// RSA with AES_256_GCM, AES_128_GCM, AES_256_CBC_SHA, AES_128_CBC_SHA
// 3DES
var safariCipherSuites = []uint16{
	tls.GREASE_PLACEHOLDER,
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

// Safari cipher suites for Safari 26.x: TLS 1.3 ciphers reordered (AES_256 first)
var safariCipherSuites26 = []uint16{
	tls.GREASE_PLACEHOLDER,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

// Safari signature algorithms SIGALGS_LIST_1 (Safari 15.x through 18.1.1)
// Includes ecdsa_sha1 and rsa_pkcs1_sha1
var safariSigAlgs = []tls.SignatureScheme{
	tls.ECDSAWithP256AndSHA256,
	tls.PSSWithSHA256,
	tls.PKCS1WithSHA256,
	tls.ECDSAWithP384AndSHA384,
	tls.ECDSAWithSHA1,
	tls.PSSWithSHA384,
	tls.PSSWithSHA384,
	tls.PKCS1WithSHA384,
	tls.PSSWithSHA512,
	tls.PKCS1WithSHA512,
	tls.PKCS1WithSHA1,
}

// Safari signature algorithms SIGALGS_LIST_2 (Safari 18.2+)
// ecdsa_sha1 removed, rsa_pkcs1_sha1 still present
var safariSigAlgs2 = []tls.SignatureScheme{
	tls.ECDSAWithP256AndSHA256,
	tls.PSSWithSHA256,
	tls.PKCS1WithSHA256,
	tls.ECDSAWithP384AndSHA384,
	tls.PSSWithSHA384,
	tls.PSSWithSHA384,
	tls.PKCS1WithSHA384,
	tls.PSSWithSHA512,
	tls.PKCS1WithSHA512,
	tls.PKCS1WithSHA1,
}

// CURVES_1: X25519, P-256, P-384, P-521 (default Safari)
var safariCurves = []tls.CurveID{
	tls.GREASE_PLACEHOLDER,
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
}

// CURVES_2: X25519MLKEM768, X25519, P-256, P-384, P-521 (Safari 26+)
var safariCurves26 = []tls.CurveID{
	tls.GREASE_PLACEHOLDER,
	tls.X25519MLKEM768,
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
}

// Safari key shares for CURVES_1
var safariKeyShares = []tls.KeyShare{
	{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
	{Group: tls.X25519},
	{Group: tls.CurveP256},
}

// Safari key shares for CURVES_2 (Safari 26+)
var safariKeyShares26 = []tls.KeyShare{
	{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
	{Group: tls.X25519MLKEM768},
	{Group: tls.X25519},
	{Group: tls.CurveP256},
}

// Safari HTTP/2 settings for Safari 18.x+ (desktop)
// initial_window_size=2097152, connection_window=10485760, push=false
var safariH2Settings18 = map[http2.SettingID]uint32{
	http2.SettingHeaderTableSize:      65536,
	http2.SettingEnablePush:           0,
	http2.SettingMaxConcurrentStreams: 100,
	http2.SettingInitialWindowSize:    2097152,
	http2.SettingMaxFrameSize:         16384,
	http2.SettingMaxHeaderListSize:    262144,
}

// Safari HTTP/2 settings for Safari 26.x (desktop)
var safariH2Settings26 = map[http2.SettingID]uint32{
	http2.SettingHeaderTableSize:      65536,
	http2.SettingEnablePush:           0,
	http2.SettingMaxConcurrentStreams: 100,
	http2.SettingInitialWindowSize:    2097152,
	http2.SettingMaxFrameSize:         16384,
	http2.SettingMaxHeaderListSize:    262144,
}

// Safari 18.x+ settings order (MaxConcurrentStreams before InitialWindowSize)
var safariSettingsOrder18 = []http2.SettingID{
	http2.SettingHeaderTableSize,
	http2.SettingEnablePush,
	http2.SettingMaxConcurrentStreams,
	http2.SettingInitialWindowSize,
	http2.SettingMaxFrameSize,
	http2.SettingMaxHeaderListSize,
}

// Safari pseudo-header order for 18.x+: :method, :scheme, :authority, :path
var safariPseudoOrder18 = []string{":method", ":scheme", ":authority", ":path"}

// Safari pseudo-header order for older: :method, :scheme, :path, :authority
var safariPseudoOrder = []string{":method", ":scheme", ":path", ":authority"}

// makeSafariProfile creates a Safari profile with the given TLS config
func makeSafariProfile(version string, ciphers []uint16, sigAlgs []tls.SignatureScheme, curves []tls.CurveID, keyShares []tls.KeyShare, h2Settings map[http2.SettingID]uint32, h2Order []http2.SettingID, pseudoOrder []string, connFlow uint32) ClientProfile {
	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Safari",
			RandomExtensionOrder: false,
			Version:              version,
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites: ciphers,
					CompressionMethods: []byte{tls.CompressionNone},
					Extensions: []tls.TLSExtension{
						&tls.UtlsGREASEExtension{},
						&tls.SNIExtension{},
						&tls.ExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
						&tls.SupportedCurvesExtension{Curves: curves},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: sigAlgs},
						&tls.SCTExtension{},
						&tls.KeyShareExtension{KeyShares: copyKeyShares(keyShares)},
						&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
						&tls.SupportedVersionsExtension{Versions: []uint16{
							tls.GREASE_PLACEHOLDER, tls.VersionTLS13, tls.VersionTLS12,
						}},
						&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionZlib}},
						&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
					},
				}, nil
			},
		},
		settings:          h2Settings,
		settingsOrder:     h2Order,
		pseudoHeaderOrder: pseudoOrder,
		connectionFlow:    connFlow,
		allowHTTP:         false,
	}
}

// Safari 18.x: cipherList2, sigAlgs1, curves1, h2Type18
var Safari_18 = makeSafariProfile("18", safariCipherSuites, safariSigAlgs, safariCurves, safariKeyShares, safariH2Settings18, safariSettingsOrder18, safariPseudoOrder18, 10485760)
var Safari_18_2 = makeSafariProfile("18.2", safariCipherSuites, safariSigAlgs2, safariCurves, safariKeyShares, safariH2Settings18, safariSettingsOrder18, safariPseudoOrder18, 10485760)
var Safari_18_3 = makeSafariProfile("18.3", safariCipherSuites, safariSigAlgs2, safariCurves, safariKeyShares, safariH2Settings18, safariSettingsOrder18, safariPseudoOrder18, 10485760)

// Safari 26.x: cipherList3, sigAlgs2, curves2 (MLKEM768), h2Type26
var Safari_26 = makeSafariProfile("26", safariCipherSuites26, safariSigAlgs2, safariCurves26, safariKeyShares26, safariH2Settings26, safariSettingsOrder18, safariPseudoOrder18, 10485760)
var Safari_26_1 = makeSafariProfile("26.1", safariCipherSuites26, safariSigAlgs2, safariCurves26, safariKeyShares26, safariH2Settings26, safariSettingsOrder18, safariPseudoOrder18, 10485760)
var Safari_26_2 = makeSafariProfile("26.2", safariCipherSuites26, safariSigAlgs2, safariCurves26, safariKeyShares26, safariH2Settings26, safariSettingsOrder18, safariPseudoOrder18, 10485760)

// iOS Safari variants
var Safari_IOS_18 = makeSafariProfile("iOS_18", safariCipherSuites, safariSigAlgs, safariCurves, safariKeyShares, safariH2Settings18, safariSettingsOrder18, safariPseudoOrder18, 10485760)
var Safari_IOS_26 = makeSafariProfile("iOS_26", safariCipherSuites26, safariSigAlgs2, safariCurves26, safariKeyShares26, safariH2Settings26, safariSettingsOrder18, safariPseudoOrder18, 10485760)

// ============================================================================
// Firefox Profiles (based on wreq firefox/tls.rs)
// ============================================================================

// Firefox cipher suites CIPHER_LIST_1 (wreq ordering)
var firefoxCipherSuites = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
}

// Firefox CURVES_1: X25519, P-256, P-384, P-521, ffdhe2048, ffdhe3072 (ff109, ff128)
var firefoxCurves1 = []tls.CurveID{
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
	tls.FakeCurveFFDHE2048,
	tls.FakeCurveFFDHE3072,
}

// Firefox CURVES_2: X25519MLKEM768, X25519, P-256, P-384, P-521, ffdhe2048, ffdhe3072 (ff133+)
var firefoxCurves2 = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
	tls.FakeCurveFFDHE2048,
	tls.FakeCurveFFDHE3072,
}

// Firefox signature algorithms
var firefoxSigAlgs = []tls.SignatureScheme{
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
}

// Firefox delegated credentials algorithms
var firefoxDelegatedCredentialsAlgs = []tls.SignatureScheme{
	tls.ECDSAWithP256AndSHA256,
	tls.ECDSAWithP384AndSHA384,
	tls.ECDSAWithP521AndSHA512,
	tls.ECDSAWithSHA1,
}

// Firefox KEY_SHARES_1: X25519, P256 (ff109, ff128, ff_android_135)
var firefoxKeyShares1 = []tls.KeyShare{
	{Group: tls.X25519},
	{Group: tls.CurveP256},
}

// Firefox KEY_SHARES_2: X25519MLKEM768, X25519, P256 (ff133+)
var firefoxKeyShares2 = []tls.KeyShare{
	{Group: tls.X25519MLKEM768},
	{Group: tls.X25519},
	{Group: tls.CurveP256},
}

// Firefox HTTP/2 settings (matching bogdanfinn/tls-client)
var firefoxSettings = map[http2.SettingID]uint32{
	http2.SettingHeaderTableSize:   65536,
	http2.SettingInitialWindowSize: 131072,
	http2.SettingMaxFrameSize:      16384,
}

var firefoxSettingsOrder = []http2.SettingID{
	http2.SettingHeaderTableSize,
	http2.SettingInitialWindowSize,
	http2.SettingMaxFrameSize,
}

// Firefox pseudo-header order: :method, :path, :authority, :scheme
// (wreq doesn't send :protocol in HTTP/2 SETTINGS, only in the header order)
var firefoxPseudoOrder = []string{":method", ":path", ":authority", ":scheme"}

// makeFirefoxProfile creates a Firefox profile with the given TLS parameters
func makeFirefoxProfile(version string, curves []tls.CurveID, keyShares []tls.KeyShare, echGrease, psk, sessionTicket, signedCertTimestamps bool, certCompressors []tls.CertCompressionAlgo) ClientProfile {
	// Build Firefox TLS extensions in the correct order (matching wreq EXTENSION_PERMUTATION_INDICES)
	// 1. SERVER_NAME (SNI)
	// 2. EXTENDED_MASTER_SECRET
	// 3. RENEGOTIATE
	// 4. SUPPORTED_GROUPS (curves)
	// 5. EC_POINT_FORMATS
	// 6. SESSION_TICKET
	// 7. APPLICATION_LAYER_PROTOCOL_NEGOTIATION (ALPN)
	// 8. STATUS_REQUEST
	// 9. DELEGATED_CREDENTIAL
	// 10. CERTIFICATE_TIMESTAMP (SCT)
	// 11. KEY_SHARE
	// 12. SUPPORTED_VERSIONS
	// 13. SIGNATURE_ALGORITHMS
	// 14. PSK_KEY_EXCHANGE_MODES
	// 15. RECORD_SIZE_LIMIT
	// 16. CERT_COMPRESSION
	// 17. ENCRYPTED_CLIENT_HELLO (ECH GREASE)

	exts := []tls.TLSExtension{
		&tls.SNIExtension{},
		&tls.ExtendedMasterSecretExtension{},
		&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
		&tls.SupportedCurvesExtension{Curves: curves},
		&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
	}

	if sessionTicket {
		exts = append(exts, &tls.SessionTicketExtension{})
	}

	exts = append(exts,
		&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		&tls.StatusRequestExtension{},
		&tls.FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: firefoxDelegatedCredentialsAlgs},
		&tls.SCTExtension{},
		&tls.KeyShareExtension{KeyShares: copyKeyShares(keyShares)},
		&tls.SupportedVersionsExtension{Versions: []uint16{
			tls.VersionTLS13, tls.VersionTLS12,
		}},
		&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: firefoxSigAlgs},
		&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
		&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
		&tls.UtlsCompressCertExtension{Algorithms: certCompressors},
	)

	if echGrease {
		exts = append(exts, tls.BoringGREASEECH())
	}

	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Firefox",
			RandomExtensionOrder: false,
			Version:              version,
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites:       firefoxCipherSuites,
					CompressionMethods: []byte{tls.CompressionNone},
					Extensions:         exts,
				}, nil
			},
		},
		settings:          firefoxSettings,
		settingsOrder:     firefoxSettingsOrder,
		pseudoHeaderOrder: firefoxPseudoOrder,
		connectionFlow:    12517377,
		streamID:          3,
		allowHTTP:         false,
	}
}

// Firefox 109: tls_options!(2) — no ECH, no PSK, no cert compressors
var Firefox_109 = makeFirefoxProfile("109", firefoxCurves1, firefoxKeyShares1, false, false, true, false, nil)

// Firefox 117: same as 109
var Firefox_117 = makeFirefoxProfile("117", firefoxCurves1, firefoxKeyShares1, false, false, true, false, nil)

// Firefox 128: tls_options!(3) — ECH GREASE, no PSK, no session ticket, no cert compressors
var Firefox_128 = makeFirefoxProfile("128", firefoxCurves1, firefoxKeyShares1, true, false, false, false, nil)

// Firefox 133: tls_options!(1) — ECH GREASE + PSK + cert compressors
var Firefox_133 = makeFirefoxProfile("133", firefoxCurves2, firefoxKeyShares2, true, true, true, false,
	[]tls.CertCompressionAlgo{tls.CertCompressionZlib, tls.CertCompressionBrotli, tls.CertCompressionZstd})

// Firefox 135: tls_options!(4) — ECH GREASE + PSK + signed cert timestamps + cert compressors
var Firefox_135 = makeFirefoxProfile("135", firefoxCurves2, firefoxKeyShares2, true, true, true, true,
	[]tls.CertCompressionAlgo{tls.CertCompressionZlib, tls.CertCompressionBrotli, tls.CertCompressionZstd})

// Firefox 136: same as 135
var Firefox_136 = makeFirefoxProfile("136", firefoxCurves2, firefoxKeyShares2, true, true, true, true,
	[]tls.CertCompressionAlgo{tls.CertCompressionZlib, tls.CertCompressionBrotli, tls.CertCompressionZstd})

// Firefox 139-151: all use ff135 config
var Firefox_139 = makeFirefoxProfile("139", firefoxCurves2, firefoxKeyShares2, true, true, true, true,
	[]tls.CertCompressionAlgo{tls.CertCompressionZlib, tls.CertCompressionBrotli, tls.CertCompressionZstd})
var Firefox_142 = makeFirefoxProfile("142", firefoxCurves2, firefoxKeyShares2, true, true, true, true,
	[]tls.CertCompressionAlgo{tls.CertCompressionZlib, tls.CertCompressionBrotli, tls.CertCompressionZstd})
var Firefox_143 = makeFirefoxProfile("143", firefoxCurves2, firefoxKeyShares2, true, true, true, true,
	[]tls.CertCompressionAlgo{tls.CertCompressionZlib, tls.CertCompressionBrotli, tls.CertCompressionZstd})
var Firefox_144 = makeFirefoxProfile("144", firefoxCurves2, firefoxKeyShares2, true, true, true, true,
	[]tls.CertCompressionAlgo{tls.CertCompressionZlib, tls.CertCompressionBrotli, tls.CertCompressionZstd})
var Firefox_145 = makeFirefoxProfile("145", firefoxCurves2, firefoxKeyShares2, true, true, true, true,
	[]tls.CertCompressionAlgo{tls.CertCompressionZlib, tls.CertCompressionBrotli, tls.CertCompressionZstd})
var Firefox_146 = makeFirefoxProfile("146", firefoxCurves2, firefoxKeyShares2, true, true, true, true,
	[]tls.CertCompressionAlgo{tls.CertCompressionZlib, tls.CertCompressionBrotli, tls.CertCompressionZstd})
var Firefox_147 = makeFirefoxProfile("147", firefoxCurves2, firefoxKeyShares2, true, true, true, true,
	[]tls.CertCompressionAlgo{tls.CertCompressionZlib, tls.CertCompressionBrotli, tls.CertCompressionZstd})
var Firefox_148 = makeFirefoxProfile("148", firefoxCurves2, firefoxKeyShares2, true, true, true, true,
	[]tls.CertCompressionAlgo{tls.CertCompressionZlib, tls.CertCompressionBrotli, tls.CertCompressionZstd})
var Firefox_149 = makeFirefoxProfile("149", firefoxCurves2, firefoxKeyShares2, true, true, true, true,
	[]tls.CertCompressionAlgo{tls.CertCompressionZlib, tls.CertCompressionBrotli, tls.CertCompressionZstd})
var Firefox_150 = makeFirefoxProfile("150", firefoxCurves2, firefoxKeyShares2, true, true, true, true,
	[]tls.CertCompressionAlgo{tls.CertCompressionZlib, tls.CertCompressionBrotli, tls.CertCompressionZstd})
var Firefox_151 = makeFirefoxProfile("151", firefoxCurves2, firefoxKeyShares2, true, true, true, true,
	[]tls.CertCompressionAlgo{tls.CertCompressionZlib, tls.CertCompressionBrotli, tls.CertCompressionZstd})

// ============================================================================
// OkHttp Profiles (Android HTTP client)
// ============================================================================

var okhttpCipherSuites = []uint16{
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

func makeOkHttpProfile(version string) ClientProfile {
	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "OkHttp",
			RandomExtensionOrder: false,
			Version:              version,
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites: okhttpCipherSuites,
					CompressionMethods: []byte{tls.CompressionNone},
					Extensions: []tls.TLSExtension{
						&tls.SNIExtension{},
						&tls.ExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
						&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
							tls.X25519, tls.CurveP256, tls.CurveP384,
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{tls.PointFormatUncompressed}},
						&tls.SessionTicketExtension{},
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
						&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
						&tls.SupportedVersionsExtension{Versions: []uint16{
							tls.VersionTLS13, tls.VersionTLS12,
						}},
						&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
					},
				}, nil
			},
		},
		settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingEnablePush:           0,
			http2.SettingMaxConcurrentStreams: 256,
			http2.SettingInitialWindowSize:    16777216,
			http2.SettingMaxFrameSize:         16384,
			http2.SettingMaxHeaderListSize:    262144,
		},
		settingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
			http2.SettingMaxHeaderListSize,
		},
		pseudoHeaderOrder: []string{":method", ":path", ":authority", ":scheme"},
		connectionFlow:    16777216,
		allowHTTP:         false,
	}
}

var OkHttp4 = makeOkHttpProfile("4")
var OkHttp5 = makeOkHttpProfile("5")

// ============================================================================
// Opera Profiles (Chromium-based, same TLS as Chrome Type7)
// ============================================================================

func makeOperaProfile(version string) ClientProfile {
	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Opera",
			RandomExtensionOrder: false,
			Version:              version,
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites:       chromeCipherSuites,
					CompressionMethods: []byte{tls.CompressionNone},
					Extensions:         makeChromeTLSType7(chromeCurvesV3, chromeKeySharesV3, true, false),
				}, nil
			},
		},
		settings:          h2SettingsType3,
		settingsOrder:     h2SettingsOrderType3,
		pseudoHeaderOrder: chromePseudoOrder,
		connectionFlow:    chromeConnFlow,
		priorities: []http2.Priority{
			{StreamID: 0, PriorityParam: http2.PriorityParam{StreamDep: 0, Exclusive: true, Weight: 219}},
		},
		headerPriority: &http2.PriorityParam{
			StreamDep: 0,
			Exclusive: true,
			Weight:    219,
		},
		streamID:  1,
		allowHTTP: false,
	}
}

var Opera_116 = makeOperaProfile("116")
var Opera_117 = makeOperaProfile("117")
var Opera_118 = makeOperaProfile("118")
var Opera_119 = makeOperaProfile("119")
var Opera_120 = makeOperaProfile("120")
var Opera_121 = makeOperaProfile("121")
var Opera_122 = makeOperaProfile("122")
var Opera_123 = makeOperaProfile("123")
var Opera_124 = makeOperaProfile("124")
var Opera_125 = makeOperaProfile("125")
var Opera_126 = makeOperaProfile("126")
var Opera_127 = makeOperaProfile("127")
var Opera_128 = makeOperaProfile("128")
var Opera_129 = makeOperaProfile("129")
var Opera_130 = makeOperaProfile("130")
var Opera_131 = makeOperaProfile("131")
