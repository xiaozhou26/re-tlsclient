// Package safari26 provides a tls-client ClientProfile that emulates
// Safari 26 (macOS) as defined in
// wreq-util/src/emulate/profile/safari.rs (safari26).
//
//   TLS:    tls_options!(3, CIPHER_LIST_3, SIGALGS_LIST_2, CURVES_2)
//           →  preserve_tls13_cipher_list, TLS 1.2-1.3, MLKEM curves
//   HTTP/2: http2_options!(6)
//           →  init 2097152, conn 10485760, push=off, no_rfc7540_priorities,
//              max_concurrent 100, pseudo (method,scheme,authority,path)
//   Header: header_initializer_for_18  →  sec-fetch-* + priority + accept br
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
		map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   4096, // not set in safari26's http2_options!(6); default-ish
			http2.SettingEnablePush:        0,
			http2.SettingInitialWindowSize: 2097152,
			http2.SettingMaxConcurrentStreams: 100,
			http2.SettingMaxHeaderListSize: 0,
		},
		// settingsOrder from safari/http2.rs settings_order!(2)
		[]http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxFrameSize,
			http2.SettingMaxHeaderListSize,
			http2.SettingEnableConnectProtocol,
			http2.SettingNoRFC7540Priorities,
		},
		// pseudoOrder from safari/http2.rs headers_pseudo_order!(2)
		[]string{":method", ":scheme", ":authority", ":path"},
		// initial_connection_window_size = 10485760
		10485760,
		nil, nil,
		0, false,
		nil, nil, 0, nil, false,
	)
}

func specFactory() (utls.ClientHelloSpec, error) {
	return utls.ClientHelloSpec{
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
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519MLKEM768, utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521,
				utls.CurveID(utls.GREASE_PLACEHOLDER), // GREASE at the end so first non-GREASE is a real curve
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{utls.PointFormatUncompressed}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
				utls.PSSWithSHA512, utls.PKCS1WithSHA512, utls.PKCS1WithSHA1,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER, utls.VersionTLS13, utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionZlib}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.UtlsGREASEExtension{},
		},
	}, nil
}

// NewClient returns a tls_client.HttpClient pre-configured with Safari 26.
func NewClient() (tls_client.HttpClient, error) {
	return tls_client.NewHttpClient(
		tls_client.NewNoopLogger(),
		tls_client.WithClientProfile(Profile()),
		tls_client.WithDefaultHeaders(fhttp.Header{
			"user-agent":      MacOSHeaders["user-agent"],
			"accept":          MacOSHeaders["accept"],
			"accept-language": MacOSHeaders["accept-language"],
			"accept-encoding": MacOSHeaders["accept-encoding"],
		}),
	)
}

// ApplyHeaders pins Safari 26's header set onto an outgoing request.
func ApplyHeaders(req *fhttp.Request) {
	for k, vs := range MacOSHeaders {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
}
