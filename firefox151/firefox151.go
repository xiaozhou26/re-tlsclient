// Package firefox151 provides a tls-client ClientProfile that emulates
// Firefox 151 (Windows x64) as defined in
// wreq-util/src/emulate/profile/firefox.rs (ff151 / ff135::build_emulation).
//
//   TLS:    tls_options!(4, CIPHER_LIST_1, CURVES_2, KEY_SHARES_2)
//           →  ECH + SCT + session_ticket + pre_shared_key + psk_skip_session_tickets
//              + brotli/zlib/zstd cert compression + MLKEM curves
//   HTTP/2: http2_options!(1)
//           →  initial_stream_id=3, header_table=65536, push=off,
//              header_dep=(stream0, weight=21, exclusive=false)
//   Header: header_initializer_with_zstd  →  zstd + "priority: u=0, i"
package firefox151

import (
	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/bogdanfinn/utls/dicttls"
	utls "github.com/bogdanfinn/utls"
)

// WindowsHeaders is the default header set emitted by Firefox 151 on Windows.
var WindowsHeaders = fhttp.Header{
	"te":              {"trailers"}, // Firefox-specific TE header
	"user-agent":      {"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0"},
	"accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
	"accept-language": {"en-US,en;q=0.5"},
	"accept-encoding": {"gzip, deflate, br, zstd"},
	"sec-fetch-dest":  {"document"},
	"sec-fetch-mode":  {"navigate"},
	"sec-fetch-site":  {"none"},
	"priority":        {"u=0, i"},
}

// Profile returns a tls_client.ClientProfile that mirrors Firefox 151.
func Profile() profiles.ClientProfile {
	return profiles.NewClientProfile(
		utls.ClientHelloID{
			Client:               "Firefox_151_Custom",
			RandomExtensionOrder: false,
			Version:              "151",
			Seed:                 nil,
			SpecFactory:          specFactory,
		},
		map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingEnablePush:        0,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
			http2.SettingMaxHeaderListSize: 0, // not exposed in wreq-util ff-http2
		},
		// settingsOrder from wreq-util's firefox/http2.rs settings_order!():
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
		// pseudoOrder from firefox/http2.rs pseudo_order!():
		[]string{":method", ":path", ":authority", ":scheme"},
		// initial_connection_window_size = 12517377 + 65535 = 13182912
		13182912,
		nil, nil,
		// initial_stream_id = 3 (from http2_options!(1))
		3, false,
		nil, nil, 0, nil, false,
	)
}

func specFactory() (utls.ClientHelloSpec, error) {
	return utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{utls.CompressionNone},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519MLKEM768, utls.X25519, utls.CurveP256, utls.CurveP384,
				utls.CurveP521, utls.CurveID(dicttls.SupportedGroups_ffdhe2048), utls.CurveID(dicttls.SupportedGroups_ffdhe3072),
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{utls.PointFormatUncompressed}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.DelegatedCredentialsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{utls.ECDSAWithP256AndSHA256, utls.ECDSAWithP384AndSHA384, utls.ECDSAWithP521AndSHA512, utls.ECDSAWithSHA1},
			},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
				{Group: utls.CurveP256},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.ECDSAWithP384AndSHA384, utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256, utls.PSSWithSHA384, utls.PSSWithSHA512,
				utls.PKCS1WithSHA256, utls.PKCS1WithSHA384, utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1, utls.PKCS1WithSHA1,
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionZlib, utls.CertCompressionBrotli, utls.CertCompressionZstd,
			}},
			&utls.UtlsGREASEExtension{},
			&utls.UtlsGREASEExtension{},
		},
	}, nil
}

// NewClient returns a tls_client.HttpClient pre-configured with Firefox 151.
func NewClient() (tls_client.HttpClient, error) {
	return tls_client.NewHttpClient(
		tls_client.NewNoopLogger(),
		tls_client.WithClientProfile(Profile()),
		tls_client.WithDefaultHeaders(fhttp.Header{
			"te":              WindowsHeaders["te"],
			"user-agent":      WindowsHeaders["user-agent"],
			"accept":          WindowsHeaders["accept"],
			"accept-language": WindowsHeaders["accept-language"],
			"accept-encoding": WindowsHeaders["accept-encoding"],
		}),
	)
}

// ApplyHeaders pins Firefox 151's header set onto an outgoing request.
func ApplyHeaders(req *fhttp.Request) {
	for k, vs := range WindowsHeaders {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
}
