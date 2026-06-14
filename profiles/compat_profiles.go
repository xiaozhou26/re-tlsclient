package profiles

import (
	"math"

	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
	"github.com/bogdanfinn/utls/dicttls"
)

// ============================================================================
// Compatibility Profiles — ported from bogdanfinn/tls-client
//
// These profiles exist in the upstream tls-client library but were not
// included in the initial wreq-based profile set. They are provided here
// to ensure seamless migration: users can switch from
//   github.com/bogdanfinn/tls-client
// to
//   github.com/xiaozhou26/re-tlsclient
// by only changing import paths, without adjusting any profile references.
//
// All fingerprints are preserved exactly as in the upstream library.
// ============================================================================
var Chrome_146_PSK = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Chrome",
		RandomExtensionOrder: false,
		Version:              "146_PSK",
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
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.ApplicationSettingsExtensionNew{
						SupportedProtocols: []string{"h2"},
					},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SCTExtension{},
					tls.BoringGREASEECH(),
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ExtendedMasterSecretExtension{},
					&tls.SessionTicketExtension{},
					&tls.SNIExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.StatusRequestExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&tls.GenericExtension{Id: 0xca34, Data: []byte{0x00, 0x00}}, // https://source.chromium.org/search?q=TLSEXT_TYPE_trust_anchors https://issues.chromium.org/issues/398275713
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPreSharedKeyExtension{},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 6291456,
		http2.SettingMaxHeaderListSize: 262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var Chrome_144_PSK = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Chrome",
		RandomExtensionOrder: false,
		Version:              "144",
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
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.ApplicationSettingsExtensionNew{
						SupportedProtocols: []string{"h2"},
					},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.SCTExtension{},
					tls.BoringGREASEECH(),
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ExtendedMasterSecretExtension{},
					&tls.SessionTicketExtension{},
					&tls.SNIExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.StatusRequestExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPreSharedKeyExtension{OmitEmptyPsk: true},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 6291456,
		http2.SettingMaxHeaderListSize: 262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
	http3Settings: map[uint64]uint64{
		1: 65536, // SETTINGS_QPACK_MAX_TABLE_CAPACITY
		7: 100,   // SETTINGS_QPACK_BLOCKED_STREAMS
	},
	http3SettingsOrder: []uint64{
		1,    // SETTINGS_QPACK_MAX_TABLE_CAPACITY
		0x6,  // SETTINGS_MAX_FIELD_SECTION_SIZE
		7,    // SETTINGS_QPACK_BLOCKED_STREAMS
		0x33, // SETTINGS_H3_DATAGRAM
	},
	http3PriorityParam: 984832,
	http3PseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	http3SendGreaseFrames: true,
}
var Chrome_133_PSK = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Chrome",
		RandomExtensionOrder: false,
		Version:              "133",
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
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SCTExtension{},
					&tls.SNIExtension{},
					tls.BoringGREASEECH(),
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.ExtendedMasterSecretExtension{},
					&tls.StatusRequestExtension{},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.ApplicationSettingsExtensionNew{
						SupportedProtocols: []string{"h3", "h2"},
					},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
					}},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h3",
						"h2",
						"http/1.1",
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPreSharedKeyExtension{},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 6291456,
		http2.SettingMaxHeaderListSize: 262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var Chrome_112 = ClientProfile{
	clientHelloId: tls.HelloChrome_112,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var Chrome_116_PSK = ClientProfile{
	clientHelloId: tls.HelloChrome_112_PSK,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var Chrome_116_PSK_PQ = ClientProfile{
	clientHelloId: tls.HelloChrome_115_PQ_PSK,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var Chrome_111 = ClientProfile{
	clientHelloId: tls.HelloChrome_111,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var Chrome_103 = ClientProfile{
	clientHelloId: tls.HelloChrome_103,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var Safari_15_6_1 = ClientProfile{
	clientHelloId: tls.HelloSafari_15_6_1,
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize:    4194304,
		http2.SettingMaxConcurrentStreams: 100,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
		http2.SettingMaxConcurrentStreams,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 10485760,
}
var Safari_16_0 = ClientProfile{
	clientHelloId: tls.HelloSafari_16_0,
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize:    4194304,
		http2.SettingMaxConcurrentStreams: 100,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
		http2.SettingMaxConcurrentStreams,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 10485760,
}
var Safari_Ipad_15_6 = ClientProfile{
	clientHelloId: tls.HelloIPad_15_6,
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxConcurrentStreams: 100,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
		http2.SettingMaxConcurrentStreams,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 10485760,
}
var Safari_IOS_17_0 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "iOS",
		RandomExtensionOrder: false,
		Version:              "17.0",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
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
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{[]tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
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
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{[]tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{[]uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{[]uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10,
					}},
					&tls.UtlsCompressCertExtension{[]tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingEnablePush:           0,
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxConcurrentStreams: 100,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxConcurrentStreams,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 10485760,
}
var Safari_IOS_26_0 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "iOS",
		RandomExtensionOrder: false,
		Version:              "26.0",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
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
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{[]tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
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
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{[]tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{[]uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{[]uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{[]tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 100,
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingNoRFC7540Priorities:  1,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingNoRFC7540Priorities,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":authority",
		":path",
	},
	connectionFlow: 10420225,
}
var Safari_IOS_18_5 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "iOS",
		RandomExtensionOrder: false,
		Version:              "18.5",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
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
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{[]tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
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
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{[]tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{[]uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{[]uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10,
					}},
					&tls.UtlsCompressCertExtension{[]tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 100,
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingNoRFC7540Priorities:  1,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingNoRFC7540Priorities,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":authority",
		":path",
	},
	connectionFlow: 10420225,
	headerPriority: &http2.PriorityParam{
		StreamDep: 0,
		Exclusive: false,
		Weight:    255,
	},
}
var Safari_IOS_18_0 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "iOS",
		RandomExtensionOrder: false,
		Version:              "18.0",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
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
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{[]tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
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
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{[]tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{[]uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{[]uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
						tls.VersionTLS11,
						tls.VersionTLS10,
					}},
					&tls.UtlsCompressCertExtension{[]tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 100,
		http2.SettingInitialWindowSize:    2097152,
		0x8:                               1,
		0x9:                               1,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		0x8,
		0x9,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":authority",
		":path",
	},
	connectionFlow: 10420225,
}
var Safari_IOS_16_0 = ClientProfile{
	clientHelloId: tls.HelloIOS_16_0,
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxConcurrentStreams: 100,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
		http2.SettingMaxConcurrentStreams,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 10485760,
}
var Safari_IOS_15_5 = ClientProfile{
	clientHelloId: tls.HelloIOS_15_5,
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxConcurrentStreams: 100,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
		http2.SettingMaxConcurrentStreams,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 10485760,
}
var Safari_IOS_15_6 = ClientProfile{
	clientHelloId: tls.HelloIOS_15_6,
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxConcurrentStreams: 100,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
		http2.SettingMaxConcurrentStreams,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 10485760,
}
var Firefox_110 = ClientProfile{
	clientHelloId: tls.HelloFirefox_110,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	headerPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}
var Firefox_108 = ClientProfile{
	clientHelloId: tls.HelloFirefox_108,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	headerPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}
var Firefox_106 = ClientProfile{
	clientHelloId: tls.HelloFirefox_106,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	headerPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}
var Firefox_105 = ClientProfile{
	clientHelloId: tls.HelloFirefox_105,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	headerPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}
var Firefox_104 = ClientProfile{
	clientHelloId: tls.HelloFirefox_104,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	headerPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}
var Firefox_102 = ClientProfile{
	clientHelloId: tls.HelloFirefox_102,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	headerPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}
var Opera_90 = ClientProfile{
	clientHelloId: tls.HelloOpera_90,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var Opera_91 = ClientProfile{
	clientHelloId: tls.HelloOpera_91,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var Opera_89 = ClientProfile{
	clientHelloId: tls.HelloOpera_89,
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var Brave_146 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Brave",
		RandomExtensionOrder: true,
		Version:              "146",
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
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					// Brave randomizes extension order each connection (RandomExtensionOrder=true).
					// GREASE bookends (first+last) stay fixed; inner extensions are shuffled.
					&tls.UtlsGREASEExtension{},
					&tls.SessionTicketExtension{},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.ExtendedMasterSecretExtension{},
					tls.BoringGREASEECH(),
					&tls.SNIExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ApplicationSettingsExtensionNew{
						SupportedProtocols: []string{"h2"},
					},
					&tls.SCTExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.StatusRequestExtension{},
					&tls.UtlsGREASEExtension{},
				},
			}, nil
		},
	},
	headerPriority: &http2.PriorityParam{
		StreamDep: 0,
		Exclusive: true,
		Weight:    255,
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 6291456,
		http2.SettingMaxHeaderListSize: 262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var Brave_146_PSK = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Brave",
		RandomExtensionOrder: true,
		Version:              "146_PSK",
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
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					// Brave randomizes extension order each connection (RandomExtensionOrder=true).
					// GREASE bookends (first+last) stay fixed; inner extensions are shuffled.
					&tls.UtlsGREASEExtension{},
					&tls.SessionTicketExtension{},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.ExtendedMasterSecretExtension{},
					tls.BoringGREASEECH(),
					&tls.SNIExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ApplicationSettingsExtensionNew{
						SupportedProtocols: []string{"h2"},
					},
					&tls.SCTExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.StatusRequestExtension{},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPreSharedKeyExtension{},
				},
			}, nil
		},
	},
	headerPriority: &http2.PriorityParam{
		StreamDep: 0,
		Exclusive: true,
		Weight:    255,
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 6291456,
		http2.SettingMaxHeaderListSize: 262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var Firefox_147_PSK = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Firefox",
		RandomExtensionOrder: false,
		Version:              "147",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
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
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.FAKEFFDHE2048,
						tls.FAKEFFDHE3072,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
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
						tls.PKCS1WithSHA1,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
						tls.CertCompressionBrotli,
						tls.CertCompressionZstd,
					}},
					&tls.GREASEEncryptedClientHelloExtension{
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_256_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_CHACHA20_POLY1305,
							},
						},
						CandidatePayloadLens: []uint16{128, 223},
					},
					&tls.UtlsPreSharedKeyExtension{OmitEmptyPsk: true},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	headerPriority: &http2.PriorityParam{
		StreamDep: 0,
		Exclusive: false,
		Weight:    41,
	},
	http3Settings: map[uint64]uint64{
		1:         65536, // QPACK_MAX_TABLE_CAPACITY
		7:         20,    // QPACK_BLOCKED_STREAMS
		727725890: 0,     // Reserved/GREASE setting
		16765559:  1,     // Reserved/GREASE setting
		0x33:      1,     // H3_DATAGRAM (51)
		8:         1,     // Unknown setting (possibly ENABLE_CONNECT_PROTOCOL)
	},
	http3SettingsOrder: []uint64{
		1,         // QPACK_MAX_TABLE_CAPACITY
		7,         // QPACK_BLOCKED_STREAMS
		727725890, // Reserved/GREASE setting
		16765559,  // Reserved/GREASE setting
		0x33,      // H3_DATAGRAM
		8,         // Unknown setting
	},
	http3PseudoHeaderOrder: []string{
		":method",
		":scheme",
		":authority",
		":path",
	},
	http3PriorityParam:    0,
	http3SendGreaseFrames: true,
}
var Firefox_146_PSK = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Firefox",
		RandomExtensionOrder: false,
		Version:              "146",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
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
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.FAKEFFDHE2048,
						tls.FAKEFFDHE3072,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.ECDSAWithSHA1,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
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
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
						tls.CertCompressionBrotli,
						tls.CertCompressionZstd,
					}},
					&tls.GREASEEncryptedClientHelloExtension{
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_256_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_CHACHA20_POLY1305,
							},
						},
						CandidatePayloadLens: []uint16{128, 223},
					},
					&tls.UtlsPreSharedKeyExtension{OmitEmptyPsk: true},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	headerPriority: &http2.PriorityParam{
		StreamDep: 0,
		Exclusive: false,
		Weight:    41,
	},
}
var Chrome_130_PSK = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Chrome",
		RandomExtensionOrder: false,
		Version:              "130",
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
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					tls.BoringGREASEECH(),
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SCTExtension{},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&tls.StatusRequestExtension{},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.ApplicationSettingsExtension{
						SupportedProtocols: []string{"h2"},
					},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.SessionTicketExtension{},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPreSharedKeyExtension{},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 6291456,
		http2.SettingMaxHeaderListSize: 262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var Chrome_131_PSK = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Chrome",
		RandomExtensionOrder: false,
		Version:              "131",
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
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
					}},
					tls.BoringGREASEECH(),
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SCTExtension{},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&tls.StatusRequestExtension{},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.ApplicationSettingsExtension{
						SupportedProtocols: []string{"h2"},
					},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
					}},
					&tls.SessionTicketExtension{},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPreSharedKeyExtension{},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingEnablePush:        0,
		http2.SettingInitialWindowSize: 6291456,
		http2.SettingMaxHeaderListSize: 262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var Firefox_132 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Firefox",
		RandomExtensionOrder: false,
		Version:              "132",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
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
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.FAKEFFDHE2048,
						tls.FAKEFFDHE3072,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{
						"h2",
						"http/1.1",
					}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.ECDSAWithSHA1,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
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
					&tls.FakeRecordSizeLimitExtension{Limit: 0x4001},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
						tls.CertCompressionBrotli,
						tls.CertCompressionZstd,
					}},
					&tls.GREASEEncryptedClientHelloExtension{
						CandidateCipherSuites: []tls.HPKESymmetricCipherSuite{
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_128_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_AES_256_GCM,
							},
							{
								KdfId:  dicttls.HKDF_SHA256,
								AeadId: dicttls.AEAD_CHACHA20_POLY1305,
							},
						},
						CandidatePayloadLens: []uint16{128, 223}, // +16: 144, 239
					},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:     65536,
		http2.SettingEnablePush:          0,
		http2.SettingInitialWindowSize:   131072,
		http2.SettingMaxFrameSize:        16384,
		http2.SettingNoRFC7540Priorities: 1,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingNoRFC7540Priorities,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
}
var Firefox_123 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Firefox",
		RandomExtensionOrder: false,
		Version:              "123",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
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
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{[]tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.FAKEFFDHE2048,
						tls.FAKEFFDHE3072,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},

					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
						},
					},
					&tls.KeyShareExtension{[]tls.KeyShare{
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{[]uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
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
					&tls.PSKKeyExchangeModesExtension{[]uint8{
						tls.PskModeDHE,
					}},
					&tls.FakeRecordSizeLimitExtension{0x4001},
					tls.BoringGREASEECH(),
				}}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
	headerPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
}
var Firefox_120 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Firefox",
		RandomExtensionOrder: false,
		Version:              "120",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
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
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{[]tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
						tls.FAKEFFDHE2048,
						tls.FAKEFFDHE3072,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},

					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.DelegatedCredentialsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
						},
					},
					&tls.KeyShareExtension{[]tls.KeyShare{
						{Group: tls.X25519},
						{Group: tls.CurveP256},
					}},
					&tls.SupportedVersionsExtension{[]uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
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
					&tls.FakeRecordSizeLimitExtension{0x4001},
					tls.BoringGREASEECH(),
				}}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   65536,
		http2.SettingInitialWindowSize: 131072,
		http2.SettingMaxFrameSize:      16384,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 12517377,
	headerPriority: &http2.PriorityParam{
		StreamDep: 13,
		Exclusive: false,
		Weight:    41,
	},
	priorities: []http2.Priority{
		{StreamID: 3, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    200,
		}},
		{StreamID: 5, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    100,
		}},
		{StreamID: 7, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 9, PriorityParam: http2.PriorityParam{
			StreamDep: 7,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 11, PriorityParam: http2.PriorityParam{
			StreamDep: 3,
			Exclusive: false,
			Weight:    0,
		}},
		{StreamID: 13, PriorityParam: http2.PriorityParam{
			StreamDep: 0,
			Exclusive: false,
			Weight:    240,
		}},
	},
}
var ZalandoAndroidMobile = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "ZalandoAndroidCustom",
		Version: "1",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
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
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      4096,
		http2.SettingMaxConcurrentStreams: math.MaxUint32,
		http2.SettingInitialWindowSize:    16777216,
		http2.SettingMaxFrameSize:         16384,
		http2.SettingMaxHeaderListSize:    math.MaxUint32,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 15663105,
}
var ZalandoIosMobile = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "ZalandoIosCustom",
		Version: "1",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
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
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
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
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      4096,
		http2.SettingMaxConcurrentStreams: 100,
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxFrameSize:         16384,
		http2.SettingMaxHeaderListSize:    math.MaxUint32,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 15663105,
}
var NikeIosMobile = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "NikeIosCustom",
		Version: "1",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
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
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
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
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      4096,
		http2.SettingMaxConcurrentStreams: 100,
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxFrameSize:         16384,
		http2.SettingMaxHeaderListSize:    math.MaxUint32,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 15663105,
}
var NikeAndroidMobile = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "NikeAndroidCustom",
		Version: "1",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
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
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      4096,
		http2.SettingMaxConcurrentStreams: math.MaxUint32,
		http2.SettingInitialWindowSize:    16777216,
		http2.SettingMaxFrameSize:         16384,
		http2.SettingMaxHeaderListSize:    math.MaxUint32,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 15663105,
}
var CloudflareCustom = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "CloudflareCustom",
		Version: "1",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.SupportedPointsExtension{SupportedPoints: []uint8{
						tls.PointFormatUncompressed,
						1, // ansiX962_compressed_prime
						2, // ansiX962_compressed_char2
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(0x0017),
					}},
					&tls.SessionTicketExtension{},
					// due to that we do not care about http2 frame settings
					&tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
					&tls.GenericExtension{Id: 22}, // encrypt_then_mac
					&tls.ExtendedMasterSecretExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.ECDSAWithP521AndSHA512,
						0x0807,
						0x0808,
						0x0809,
						0x080a,
						0x080b,
						tls.PSSWithSHA256,
						tls.PSSWithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA256,
						tls.PKCS1WithSHA384,
						tls.PKCS1WithSHA512,
						0x0303,
						0x0203,
						0x0301,
						0x0201,
						0x0302,
						0x0202,
						0x0402,
						0x0502,
						0x0602,
					}},
				},
			}, nil
		},
	},

	//actually the h2 settings are not relevant, because this client does only support http1
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      4096,
		http2.SettingMaxConcurrentStreams: math.MaxUint32,
		http2.SettingInitialWindowSize:    16777216,
		http2.SettingMaxFrameSize:         16384,
		http2.SettingMaxHeaderListSize:    math.MaxUint32,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 15663105,
}
var MMSIos = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "MMSIos",
		Version: "1",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					0x1303,
					0x1301,
					0x1302,
					0xcca9,
					0xcca8,
					0xc02b,
					0xc02f,
					0xc02c,
					0xc030,
					0xc009,
					0xc013,
					0xc00a,
					0xc014,
					0x009c,
					0x009d,
					0x002f,
					0x0035,
					0x000a,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(0x001d),
						tls.CurveID(0x0017),
						tls.CurveID(0x0018),
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []uint8{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						0x0403,
						0x0804,
						0x0401,
						0x0503,
						0x0805,
						0x0501,
						0x0806,
						0x0601,
						0x0201,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      4096,
		http2.SettingEnablePush:           1,
		http2.SettingMaxConcurrentStreams: 100,
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxFrameSize:         16384,
		http2.SettingMaxHeaderListSize:    math.MaxUint32,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 15663105,
}
var MeshIos = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "MeshIos",
		Version: "1",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.GREASE_PLACEHOLDER,
					0x1301,
					0x1302,
					0x1303,
					0xc02c,
					0xc02b,
					0xcca9,
					0xc030,
					0xc02f,
					0xcca8,
					0xc00a,
					0xc009,
					0xc014,
					0xc013,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.CurveID(0x001d),
						tls.CurveID(0x0017),
						tls.CurveID(0x0018),
						tls.CurveID(0x0019),
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []uint8{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						0x0403,
						0x0804,
						0x0401,
						0x0503,
						0x0203,
						0x0805,
						0x0805,
						0x0501,
						0x0806,
						0x0601,
						0x0201,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      4096,
		http2.SettingEnablePush:           1,
		http2.SettingMaxConcurrentStreams: 100,
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxFrameSize:         16384,
		http2.SettingMaxHeaderListSize:    math.MaxUint32,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 15663105,
}
var MeshAndroid = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "MeshAndroid",
		Version: "1",
		Seed:    nil,
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
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []uint8{
						tls.PointFormatUncompressed,
					}},
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
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionBrotli,
					}},
					&tls.ApplicationSettingsExtension{
						SupportedProtocols: []string{},
					},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var MeshIos2 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "MeshIos2",
		Version: "1",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
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
					tls.DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []uint8{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
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
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      4096,
		http2.SettingMaxConcurrentStreams: 100,
		http2.SettingInitialWindowSize:    2097152,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var MeshAndroid2 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "MeshAndroid2",
		Version: "1",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.SessionTicketExtension{},
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
					&tls.StatusRequestExtension{},
					// due to that we do not care about http2 frame settings
					&tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
					&tls.SupportedPointsExtension{SupportedPoints: []uint8{
						tls.PointFormatUncompressed,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      65536,
		http2.SettingMaxConcurrentStreams: 1000,
		http2.SettingInitialWindowSize:    6291456,
		http2.SettingMaxHeaderListSize:    262144,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":authority",
		":scheme",
		":path",
	},
	connectionFlow: 15663105,
}
var ConfirmedIos = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "ConfirmedIos",
		Version: "1",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
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
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(tls.GREASE_PLACEHOLDER),
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []uint8{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
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
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      4096,
		http2.SettingEnablePush:           1,
		http2.SettingMaxConcurrentStreams: 100,
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxFrameSize:         16384,
		http2.SettingMaxHeaderListSize:    math.MaxUint32,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 15663105,
}
var ConfirmedAndroid = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "ConfirmedAndroid",
		Version: "1",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateNever},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						0x0804,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						0x0805,
						tls.PKCS1WithSHA384,
						0x0806,
						0x0601,
						tls.PKCS1WithSHA1,
					}},
					&tls.StatusRequestExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	headerPriority: &http2.PriorityParam{},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 16711681,
}
var ConfirmedAndroid2 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "ConfirmedAndroid2",
		Version: "1",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateNever},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						0x0804,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						0x0805,
						tls.PKCS1WithSHA384,
						0x0806,
						0x0601,
						tls.PKCS1WithSHA1,
					}},
					&tls.StatusRequestExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.UtlsPaddingExtension{WillPad: true, GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 16711681,
}
var Okhttp4Android13 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "OkHttp4Android13",
		Version: "4.10.0",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return Okhttp4Android10.GetClientHelloSpec()
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	headerPriority: &http2.PriorityParam{},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 16711681,
}
var Okhttp4Android12 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "OkHttp4Android12",
		Version: "4.10.0",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return Okhttp4Android10.GetClientHelloSpec()
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	headerPriority: &http2.PriorityParam{},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 16711681,
}
var Okhttp4Android11 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "OkHttp4Android11",
		Version: "4.10.0",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return Okhttp4Android10.GetClientHelloSpec()
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	headerPriority: &http2.PriorityParam{},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 16711681,
}
var Okhttp4Android10 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "OkHttp4Android10",
		Version: "4.10.0",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateNever},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
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
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	headerPriority: &http2.PriorityParam{},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 16711681,
}
var Okhttp4Android9 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "OkHttp4Android9",
		Version: "4.10.0",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateNever},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.SessionTicketExtension{},
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
					&tls.StatusRequestExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	headerPriority: &http2.PriorityParam{},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 16711681,
}
var Okhttp4Android8 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "OkHttp4Android8",
		Version: "4.10.0",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateNever},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PKCS1WithSHA384,
						tls.ECDSAWithP521AndSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.StatusRequestExtension{},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	headerPriority: &http2.PriorityParam{},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 16711681,
}
var Okhttp4Android7 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "OkHttp4Android7",
		Version: "4.10.0",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
				CompressionMethods: []byte{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateNever},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.PKCS1WithSHA512,
						tls.ECDSAWithP521AndSHA512,
						tls.PKCS1WithSHA384,
						tls.ECDSAWithP384AndSHA384,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP256AndSHA256,
						0x0301,
						0x0303,
						tls.PKCS1WithSHA1,
						tls.ECDSAWithSHA1,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize: 16777216,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingInitialWindowSize,
	},
	headerPriority: &http2.PriorityParam{},
	pseudoHeaderOrder: []string{
		":method",
		":path",
		":authority",
		":scheme",
	},
	connectionFlow: 16711681,
}
var MMSIos2 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "MMSIos",
		Version: "2",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					0x1301,
					0x1302,
					0x1303,
					0xc02b,
					0xc02f,
					0xc02c,
					0xc030,
					0xcca9,
					0xcca8,
					0xc009,
					0xc013,
					0xc00a,
					0xc014,
					0x009c,
					0x009d,
					0x002f,
					0x0035,
					0x000a,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(0x001d),
						tls.CurveID(0x0017),
						tls.CurveID(0x0018),
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []uint8{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						0x0403,
						0x0804,
						0x0401,
						0x0503,
						0x0805,
						0x0501,
						0x0806,
						0x0601,
						0x0201,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      4096,
		http2.SettingEnablePush:           1,
		http2.SettingMaxConcurrentStreams: 100,
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxFrameSize:         16384,
		http2.SettingMaxHeaderListSize:    math.MaxUint32,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 15663105,
}

var MMSIos3 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:  "MMSIos",
		Version: "3",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.GREASE_PLACEHOLDER,
					0x1301,
					0x1302,
					0x1303,
					0xc02c,
					0xc02b,
					0xcca9,
					0xc030,
					0xc02f,
					0xcca8,
					0xc00a,
					0xc009,
					0xc014,
					0xc013,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						0x001d,
						0x0017,
						0x0018,
						0x0019,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []uint8{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						0x0403,
						0x0804,
						0x0401,
						0x0503,
						0x0203,
						0x0805,
						0x0501,
						0x0806,
						0x0601,
						0x0201,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{[]tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{[]tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      4096,
		http2.SettingEnablePush:           1,
		http2.SettingMaxConcurrentStreams: 100,
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxFrameSize:         16384,
		http2.SettingMaxHeaderListSize:    math.MaxUint32,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":path",
		":authority",
	},
	connectionFlow: 15663105,
}
