// Package opera131 provides a tls-client ClientProfile that emulates
// Opera 131 (Windows x64) as defined in
// wreq-util/src/emulate/profile/opera.rs (opera131 / opera116::build_emulation).
//
// wreq opera131 TLS data (opera/tls.rs):
//   - cipher = CIPHER_LIST (16 ciphers incl. CBC + RSA suites)
//   - sigalgs = SIGALGS_LIST (8 schemes, no PKCS1WithSHA1)
//   - curves = "X25519MLKEM768:X25519:P-256:P-384"
//   - certificate_compressors = [Brotli]
//   - alps_protos = HTTP2, alps_use_new_codepoint = false
//   - permute_extensions = true
//   - pre_shared_key = true
//   - enable_ech_grease = true
//
// Extension layout mirrors tls-client's Chrome_146 (the closest
// available reference; Opera 131 is Chromium-147 based). Differences
// from a literal Chrome copy: keep wreq's data exactly (cipher / sigalgs
// / curves), use ApplicationSettingsExtension (not New) because
// alps_use_new_codepoint=false.
package opera131

import (
	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

// WindowsHeaders is the default header set emitted by Opera 131 on Windows.
var WindowsHeaders = fhttp.Header{
	"sec-ch-ua":          {`"Opera";v="131", "Not.A/Brand";v="8", "Chromium";v="147"`},
	"sec-ch-ua-mobile":   {"?0"},
	"sec-ch-ua-platform": {`"Windows"`},
	"user-agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 OPR/131.0.0.0"},
	"sec-fetch-dest":     {"document"},
	"sec-fetch-mode":     {"navigate"},
	"sec-fetch-site":     {"none"},
	"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
	"accept-encoding":    {"gzip, deflate, br, zstd"},
	"accept-language":    {"en-US,en;q=0.9"},
	"priority":           {"u=0, i"},
}

// Profile returns a tls_client.ClientProfile that mirrors Opera 131.
func Profile() profiles.ClientProfile {
	return profiles.NewClientProfile(
		utls.ClientHelloID{
			Client:               "Opera_131_Custom",
			RandomExtensionOrder: false, // enabled globally via WithRandomTLSExtensionOrder
			Version:              "131",
			Seed:                 nil,
			SpecFactory:          specFactory,
		},
		// settings from wreq opera131 (opera/http2.rs http2_options!()).
		map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingEnablePush:        0,
			http2.SettingInitialWindowSize: 6291456,
			http2.SettingMaxHeaderListSize: 262144,
		},
		[]http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		[]string{":method", ":authority", ":scheme", ":path"},
		15663105,
		nil, nil,
		0, false,
		nil, nil, 0, nil, false,
	)
}

// specFactory reproduces Opera 131's TLS ClientHello spec.
// Mirrors wreq-util's tls_options!(CURVES) — single-arg form, all other
// fields at OperaTlsConfig defaults. Layout follows tls-client
// Chrome_146.
func specFactory() (utls.ClientHelloSpec, error) {
	return utls.ClientHelloSpec{
		// CIPHER_LIST from opera/tls.rs:17-34.
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
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{utls.CompressionNone},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			}},
			&utls.SNIExtension{},
			// alps_use_new_codepoint=false → use old ALPS codepoint 17513,
			// not ApplicationSettingsExtensionNew.
			&utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			// CURVES = "X25519MLKEM768:X25519:P-256:P-384" (4 entries, no P-521).
			// GREASE placeholder at index 0 (Chrome-146 layout).
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli}},
			&utls.SessionTicketExtension{},
			&utls.StatusRequestExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER, utls.VersionTLS13, utls.VersionTLS12,
			}},
			// SIGALGS_LIST from opera/tls.rs:36-46.
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
				utls.PSSWithSHA512, utls.PKCS1WithSHA512,
			}},
			&utls.SCTExtension{},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{utls.PointFormatUncompressed}},
			// enable_ech_grease=true → BoringGREASEECH().
			utls.BoringGREASEECH(),
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			// pre_shared_key=true → PskModeDHE.
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.UtlsGREASEExtension{},
		},
	}, nil
}

// NewClient returns a tls_client.HttpClient pre-configured with Opera 131.
// permute_extensions is ON (wreq opera131 tls_options! sets it true).
func NewClient() (tls_client.HttpClient, error) {
	return tls_client.NewHttpClient(
		tls_client.NewNoopLogger(),
		tls_client.WithClientProfile(Profile()),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithDefaultHeaders(fhttp.Header{
			"sec-ch-ua":          WindowsHeaders["sec-ch-ua"],
			"sec-ch-ua-mobile":   WindowsHeaders["sec-ch-ua-mobile"],
			"sec-ch-ua-platform": WindowsHeaders["sec-ch-ua-platform"],
			"user-agent":         WindowsHeaders["user-agent"],
			"accept":             WindowsHeaders["accept"],
			"accept-encoding":    WindowsHeaders["accept-encoding"],
			"accept-language":    WindowsHeaders["accept-language"],
		}),
	)
}

// ApplyHeaders pins Opera 131's header set onto an outgoing request.
func ApplyHeaders(req *fhttp.Request) {
	for k, vs := range WindowsHeaders {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
}
