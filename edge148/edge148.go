// Package edge148 provides a tls-client ClientProfile that emulates
// Microsoft Edge 148 (Windows x64) as defined in
// wreq-util/src/emulate/profile/chrome.rs (edge148 / v132::build_emulation).
//
// Edge reuses Chrome's TLS and HTTP/2 configuration; only UA and sec-ch-ua
// differ (Edge labels instead of Chrome labels).
package edge148

import (
	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

// WindowsHeaders is the default header set emitted by Edge 148 on Windows.
var WindowsHeaders = fhttp.Header{
	"sec-ch-ua":          {`"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"`},
	"sec-ch-ua-mobile":   {"?0"},
	"sec-ch-ua-platform": {`"Windows"`},
	"user-agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0"},
	"sec-fetch-dest":     {"document"},
	"sec-fetch-mode":     {"navigate"},
	"sec-fetch-site":     {"none"},
	"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
	"accept-encoding":    {"gzip, deflate, br, zstd"},
	"accept-language":    {"en-US,en;q=0.9"},
	"priority":           {"u=0, i"},
}

// Profile returns a tls_client.ClientProfile that mirrors Edge 148.
func Profile() profiles.ClientProfile {
	return profiles.NewClientProfile(
		utls.ClientHelloID{
			Client:               "Edge_148_Custom",
			RandomExtensionOrder: false,
			Version:              "148",
			Seed:                 nil,
			SpecFactory:          specFactory,
		},
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
				utls.X25519MLKEM768, utls.X25519, utls.CurveP256, utls.CurveP384,
				utls.CurveID(utls.GREASE_PLACEHOLDER), // GREASE at the end
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{utls.PointFormatUncompressed}},
			&utls.SessionTicketExtension{},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
				utls.PSSWithSHA512, utls.PKCS1WithSHA512,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519MLKEM768}, {Group: utls.X25519},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER, utls.VersionTLS13, utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli}},
			&utls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			utls.BoringGREASEECH(),
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.UtlsGREASEExtension{},
		},
	}, nil
}

// NewClient returns a tls_client.HttpClient pre-configured with Edge 148.
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

// ApplyHeaders pins Edge 148's header set onto an outgoing request.
func ApplyHeaders(req *fhttp.Request) {
	for k, vs := range WindowsHeaders {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
}
