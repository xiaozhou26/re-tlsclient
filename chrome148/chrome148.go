// Package chrome148 provides a tls-client ClientProfile that emulates
// Chrome 148 (Windows x64) as defined in wreq-util/src/emulate/profile/chrome.rs
// (v148 / v132::build_emulation).
//
//   TLS:    tls_options!(7, CURVES_3)  →  permute_extensions + ECH GREASE + PSK + alps_new_codepoint + X25519MLKEM768
//   HTTP/2: http2_options!(3)          →  push off, init_window=6291456, header_table=65536
//   Header: header_initializer_with_zstd_priority  →  zstd accept-encoding + "priority: u=0, i"
package chrome148

import (
	"crypto/tls"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

// Headers is the default header set used by Chrome 148 (Windows) when
// wreq-util's header_initializer_with_zstd_priority is selected.
var Headers = fhttp.Header{
	"sec-ch-ua":          {`"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"`},
	"sec-ch-ua-mobile":   {"?0"},
	"sec-ch-ua-platform": {`"Windows"`},
	"user-agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"},
	"sec-fetch-dest":     {"document"},
	"sec-fetch-mode":     {"navigate"},
	"sec-fetch-site":     {"none"},
	"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
	"accept-encoding":    {"gzip, deflate, br, zstd"},
	"accept-language":    {"en-US,en;q=0.9"},
	"priority":           {"u=0, i"},
}

// Profile returns a tls_client.ClientProfile that mirrors the Chrome 148
// emulation defined in wreq-util (v148 / v132::build_emulation).
func Profile() profiles.ClientProfile {
	return profiles.NewClientProfile(
		utls.ClientHelloID{
			Client:               "Chrome_148_Custom",
			RandomExtensionOrder: false, // enabled globally via WithRandomTLSExtensionOrder
			Version:              "148",
			Seed:                 nil,
			SpecFactory:          specFactory,
		},
		// settings
		map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingEnablePush:        0,
			http2.SettingInitialWindowSize: 6291456,
			http2.SettingMaxHeaderListSize: 262144,
		},
		// settingsOrder
		[]http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		// pseudoHeaderOrder
		[]string{":method", ":authority", ":scheme", ":path"},
		// connectionFlow
		15663105,
		// priorities, headerPriority
		nil, nil,
		// streamID, allowHTTP
		0, false,
		// http3*
		nil, nil, 0, nil, false,
	)
}

// specFactory reproduces Chrome 148's TLS ClientHello spec.
// Mirrors wreq-util's tls_options!(7, CURVES_3).
func specFactory() (utls.ClientHelloSpec, error) {
	return utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CompressionMethods: []byte{utls.CompressionNone},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{utls.PointFormatUncompressed}},
			&utls.SessionTicketExtension{},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			}},
			&utls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			utls.BoringGREASEECH(),
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.UtlsGREASEExtension{},
		},
	}, nil
}

// NewClient returns a tls_client.HttpClient pre-configured with the Chrome
// 148 profile and the standard Windows header set. It also enables
// random TLS extension order, matching wreq-util's permute_extensions=true.
func NewClient() (tls_client.HttpClient, error) {
	return tls_client.NewHttpClient(
		tls_client.NewNoopLogger(),
		tls_client.WithClientProfile(Profile()),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithDefaultHeaders(fhttp.Header{
			"sec-ch-ua":          Headers["sec-ch-ua"],
			"sec-ch-ua-mobile":   Headers["sec-ch-ua-mobile"],
			"sec-ch-ua-platform": Headers["sec-ch-ua-platform"],
			"user-agent":         Headers["user-agent"],
			"accept":             Headers["accept"],
			"accept-encoding":    Headers["accept-encoding"],
			"accept-language":    Headers["accept-language"],
		}),
	)
}

// ApplyHeaders copies the Chrome 148 default header set onto an existing
// request, overriding any values already set. This is needed because
// WithDefaultHeaders only fills in missing headers — it does not overwrite
// the request's own header set.
func ApplyHeaders(req *fhttp.Request) {
	for k, vs := range Headers {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
}

// Ensure unused import is referenced when building a minimal example.
var _ = tls.Config{}
