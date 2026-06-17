// Package safari26 provides a tls-client ClientProfile that emulates
// Safari 26 (macOS) as defined in
// wreq-util/src/emulate/profile/safari.rs (safari26).
//
// wreq Safari 26 TLS config (safari/tls.rs SafariTlsConfig → TlsOptions):
//   - session_ticket = false
//   - grease_enabled = true
//   - enable_ocsp_stapling = true
//   - enable_signed_cert_timestamps = true
//   - preserve_tls13_cipher_list = true
//   - certificate_compressors = [Zlib]
//   - min/max tls = TLS_1_2 / TLS_1_3
//   - curves = CURVES_2 = "X25519MLKEM768:X25519:P-256:P-384:P-521"
//   - sigalgs = SIGALGS_LIST_2
//   - cipher = CIPHER_LIST_3
//   - permute_extensions = false (Safari builder does not enable it)
//
// Extension layout is mirrored on tls-client's Safari_IOS_26_0
// (internal_browser_profiles.go:1471) — wreq's underlying utls fork
// emits the same shape: GREASE in SupportedCurves, ALPN before
// StatusRequest, PSKKeyExchangeModes alongside, Zlib certificate
// compression.
package safari26

import (
	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

// MacOSHeaders is the default header set emitted by Safari 26 on macOS.
var MacOSHeaders = fhttp.Header{
	"sec-fetch-dest":  {"document"},
	"user-agent":      {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15"},
	"accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
	"sec-fetch-site":  {"none"},
	"sec-fetch-mode":  {"navigate"},
	"accept-language": {"en-US,en;q=0.9"},
	"priority":        {"u=0, i"},
	"accept-encoding": {"gzip, deflate, br"},
}

// Profile returns a tls_client.ClientProfile that mirrors Safari 26.
func Profile() profiles.ClientProfile {
	return profiles.NewClientProfile(
		utls.ClientHelloID{
			Client:               "Safari_26_Custom",
			RandomExtensionOrder: false,
			Version:              "26",
			Seed:                 nil,
			SpecFactory:          specFactory,
		},
		// settings mirror Safari_IOS_26_0 (internal_browser_profiles.go:1557).
		map[http2.SettingID]uint32{
			http2.SettingEnablePush:           0,
			http2.SettingMaxConcurrentStreams: 100,
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingNoRFC7540Priorities:  1,
		},
		[]http2.SettingID{
			http2.SettingEnablePush,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingNoRFC7540Priorities,
		},
		[]string{":method", ":scheme", ":authority", ":path"},
		// connectionFlow = 10420225 (Safari_IOS_26_0)
		10420225,
		nil, nil,
		0, false,
		nil, nil, 0, nil, false,
	)
}

// specFactory reproduces Safari 26's TLS ClientHello spec.
// Mirrors wreq-util's tls_options!(3, CIPHER_LIST_3, SIGALGS_LIST_2, CURVES_2)
// and tls-client's Safari_IOS_26_0 extension layout.
func specFactory() (utls.ClientHelloSpec, error) {
	return utls.ClientHelloSpec{
		// CIPHER_LIST_3 from safari/tls.rs:86-108.
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		CompressionMethods: []byte{utls.CompressionNone},
		// Extension order follows tls-client's Safari_IOS_26_0.
		// Wreq Safari 26's tls_options! does not enable pre_shared_key,
		// but the underlying utls fork (and tls-client's reference
		// profile) emits PSKKeyExchangeModes alongside for Safari.
		// We follow the reference layout for byte-for-byte parity.
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			// CURVES_2 = "X25519MLKEM768:X25519:P-256:P-384:P-521".
			// GREASE placeholder at index 0, then MLKEM (matches
			// tls-client Safari_IOS_26_0 / Safari_IOS_18_5 layout).
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{utls.PointFormatUncompressed}},
			// ALPN before StatusRequest (matches Safari_IOS_26_0).
			// wreq: session_ticket=false → omit SessionTicketExtension.
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			// wreq: enable_ocsp_stapling=true → StatusRequest.
			&utls.StatusRequestExtension{},
			// SIGALGS_LIST_2 from safari/tls.rs:125-137.
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
				utls.PSSWithSHA512, utls.PKCS1WithSHA512, utls.PKCS1WithSHA1,
			}},
			// wreq: enable_signed_cert_timestamps=true → SCT.
			&utls.SCTExtension{},
			// KeyShare. utls fills empty Data fields with fresh keys
			// (u_parrots.go:3458). GREASE placeholder gets Data:[0] so
			// the fill loop skips it; MLKEM and X25519 are filled in.
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			}},
			// PSKKeyExchangeModes. tls-client's Safari_IOS_26_0 emits
			// this; wreq's TlsOptions default omits it, but mirroring
			// the reference byte layout has proven necessary for the
			// downstream site to accept the handshake.
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER, utls.VersionTLS13, utls.VersionTLS12,
			}},
			// wreq: certificate_compressors = [Zlib].
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionZlib}},
			&utls.UtlsGREASEExtension{},
		},
	}, nil
}

// NewClient returns a tls_client.HttpClient pre-configured with Safari 26.
// permute_extensions is intentionally OFF (wreq Safari 26's
// tls_options!(3, ...) does not enable it). Extra tls_client options can
// be passed in (e.g. tls_client.WithProxyUrl(...)) and are applied after
// the defaults.
func NewClient(extra ...tls_client.HttpClientOption) (tls_client.HttpClient, error) {
	opts := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(Profile()),
		tls_client.WithDefaultHeaders(fhttp.Header{
			"user-agent":      MacOSHeaders["user-agent"],
			"accept":          MacOSHeaders["accept"],
			"accept-language": MacOSHeaders["accept-language"],
			"accept-encoding": MacOSHeaders["accept-encoding"],
		}),
	}
	opts = append(opts, extra...)
	return tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
}

// ApplyHeaders pins Safari 26's header set onto an outgoing request.
func ApplyHeaders(req *fhttp.Request) {
	for k, vs := range MacOSHeaders {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
}
