// Package okhttp5 provides a tls-client ClientProfile that emulates
// OkHttp 5 (Android) as defined in
// wreq-util/src/emulate/profile/okhttp.rs (okhttp5).
//
//   TLS:    CIPHER_LIST (full cipher suite), curves = X25519 : P-256 : P-384
//   HTTP/2: init 16777216, conn 16777216,
//           pseudo (method, path, authority, scheme)
//   Header: accept */* + accept-encoding gzip + accept-language en-US
package okhttp5

import (
	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

// Headers is the default header set emitted by OkHttp 5.
var Headers = fhttp.Header{
	"accept":          {"*/*"},
	"accept-language": {"en-US,en;q=0.9"},
	"user-agent":      {"NRC Audio/2.0.6 (nl.nrc.audio; build:36; Android 14; Sdk:34; Manufacturer:OnePlus; Model: CPH2609) OkHttp/5.0.0-alpha2"},
	"accept-encoding": {"gzip"},
}

// Profile returns a tls_client.ClientProfile that mirrors OkHttp 5.
func Profile() profiles.ClientProfile {
	return profiles.NewClientProfile(
		utls.ClientHelloID{
			Client:               "OkHttp_5_Custom",
			RandomExtensionOrder: false,
			Version:              "5",
			Seed:                 nil,
			SpecFactory:          specFactory,
		},
		map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   4096,
			http2.SettingEnablePush:        0,
			http2.SettingInitialWindowSize: 16777216,
			http2.SettingMaxHeaderListSize: 0,
		},
		// settingsOrder from okhttp.rs build_emulation
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
		// pseudoOrder from okhttp.rs (method, path, authority, scheme)
		[]string{":method", ":path", ":authority", ":scheme"},
		// initial_connection_window_size = 16777216
		16777216,
		nil, nil,
		0, false,
		nil, nil, 0, nil, false,
	)
}

func specFactory() (utls.ClientHelloSpec, error) {
	return utls.ClientHelloSpec{
		CipherSuites: []uint16{
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
			utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		CompressionMethods: []byte{utls.CompressionNone},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519, utls.CurveP256, utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{utls.PointFormatUncompressed}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
				utls.PSSWithSHA512, utls.PKCS1WithSHA512, utls.PKCS1WithSHA1,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
		},
	}, nil
}

// NewClient returns a tls_client.HttpClient pre-configured with OkHttp 5.
func NewClient() (tls_client.HttpClient, error) {
	return tls_client.NewHttpClient(
		tls_client.NewNoopLogger(),
		tls_client.WithClientProfile(Profile()),
		tls_client.WithDefaultHeaders(fhttp.Header{
			"accept":          Headers["accept"],
			"accept-language": Headers["accept-language"],
			"user-agent":      Headers["user-agent"],
			"accept-encoding": Headers["accept-encoding"],
		}),
	)
}

// ApplyHeaders pins OkHttp 5's header set onto an outgoing request.
func ApplyHeaders(req *fhttp.Request) {
	for k, vs := range Headers {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
}
