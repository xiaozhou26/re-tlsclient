// Package okhttp provides tls-client ClientProfiles that emulate
// OkHttp 3.9..5 (Android) as defined in
// wreq-util/src/emulate/profile/okhttp.rs.
//
// All supported OkHttp versions share the same HTTP/2 stack and
// most of the TLS stack; only the cipher list and User-Agent vary
// per version:
//
//   TLS:    OkHttpTlsConfig { cipher_list = <per-version CIPHER_LIST> }
//           →  enable_ocsp_stapling=true
//              + curves = "X25519:P-256:P-384"
//              + sigalgs = SIGALGS_LIST (9 incl. PKCS1WithSHA1)
//              + aes_hw_override=true
//   HTTP/2: initial_window=16777216, initial_connection_window=16777216,
//           pseudo (method, path, authority, scheme),
//           full settings_order (8 keys, but only the one key in the
//           map actually appears in the SETTINGS frame — same as
//           Okhttp4Android10 in tls-client).
//   Header: accept */* + accept-encoding gzip + accept-language en-US
//
// Each OkHttp version has its own (different) cipher list sourced
// directly from okhttp.rs mod_generator! blocks:
//   - okhttp3_9  : 15 ciphers (no TLS 1.3, no CHACHA20, no GCM TLS 1.3)
//   - okhttp3_11 : 14 ciphers (no TLS 1.3, no CHACHA20)
//   - okhttp3_13 : 18 ciphers (incl. TLS_AES_128_CCM_SHA256)
//   - okhttp3_14 : CIPHER_LIST (15 ciphers incl. 3DES, no CCM)
//   - okhttp4_9  : 14 ciphers (no 3DES)
//   - okhttp4_10 : CIPHER_LIST (15 ciphers incl. 3DES)
//   - okhttp4_12 : CIPHER_LIST (15 ciphers incl. 3DES)
//   - okhttp5    : CIPHER_LIST (15 ciphers incl. 3DES)
//
// Extension layout mirrors tls-client's Okhttp4Android10
// (contributed_custom_profiles.go:1275). Notable: no GREASE, no
// MLKEM, no ECH, no ALPS, no cert_compressors, ends with
// UtlsPaddingExtension for client_hello length alignment.
package okhttp

import (
	"fmt"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/bogdanfinn/utls/dicttls"
	utls "github.com/bogdanfinn/utls"
)

// Version selects which OkHttp version to emulate.
type Version string

const (
	V3_9  Version = "3.9"
	V3_11 Version = "3.11"
	V3_13 Version = "3.13"
	V3_14 Version = "3.14"
	V4_9  Version = "4.9"
	V4_10 Version = "4.10"
	V4_12 Version = "4.12"
	V5    Version = "5"
)

// headersFor returns the default header set for a given OkHttp
// version. UA varies; accept / accept-encoding / accept-language
// are constant.
func headersFor(v Version) (fhttp.Header, error) {
	entry, ok := allVersions[v]
	if !ok {
		return nil, fmt.Errorf("okhttp: unsupported version %s", v)
	}
	return fhttp.Header{
		"accept":          {"*/*"},
		"accept-language": {"en-US,en;q=0.9"},
		"user-agent":      {entry.ua},
		"accept-encoding": {"gzip"},
	}, nil
}

// allVersions maps each Version → (User-Agent, cipher list). The
// cipher list is a Go []uint16 sourced verbatim from the wreq
// okhttp.rs mod_generator! blocks for that version.
var allVersions = map[Version]struct {
	ua      string
	ciphers []uint16
}{
	V3_9: {
		ua: "MaiMemo/4.4.50_639 okhttp/3.9 Android/5.0 Channel/WanDouJia Device/alps+M8+Emulator (armeabi-v7a) Screen/4.44 Resolution/480x800 DId/aa6cde19def3806806d5374c4e5fd617 RAM/0.94 ROM/4.91 Theme/Day",
		ciphers: []uint16{
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	},
	V3_11: {
		ua: "NRC Audio/2.0.6 (nl.nrc.audio; build:36; Android 12; Sdk:31; Manufacturer:motorola; Model: moto g72) OkHttp/3.11.0",
		ciphers: []uint16{
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
	},
	V3_13: {
		ua: "GM-Android/6.112.2 (240590300; M:Google Pixel 7a; O:34; D:2b045e03986fa6dc) ObsoleteUrlFactory/1.0 OkHttp/3.13.0",
		ciphers: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			dicttls.TLS_AES_128_CCM_SHA256,
			dicttls.TLS_AES_128_CCM_8_SHA256,
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
	},
	V3_14: {
		ua: "DS podcast/2.0.1 (be.standaard.audio; build:9; Android 11; Sdk:30; Manufacturer:samsung; Model: SM-A405FN) OkHttp/3.14.0",
		ciphers: cipherListCIPHER_LIST(),
	},
	V4_9: {
		ua: "GM-Android/6.111.1 (240460200; M:motorola moto g power (2021); O:30; D:76ba9f6628d198c8) ObsoleteUrlFactory/1.0 OkHttp/4.9",
		ciphers: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	},
	V4_10: {
		ua: "GM-Android/6.112.2 (240590300; M:samsung SM-G781U1; O:33; D:edb34792871638d8) ObsoleteUrlFactory/1.0 OkHttp/4.10.0",
		ciphers: cipherListCIPHER_LIST(),
	},
	V4_12: {
		ua: "okhttp/4.12.0",
		ciphers: cipherListCIPHER_LIST(),
	},
	V5: {
		ua: "NRC Audio/2.0.6 (nl.nrc.audio; build:36; Android 14; Sdk:34; Manufacturer:OnePlus; Model: CPH2609) OkHttp/5.0.0-alpha2",
		ciphers: cipherListCIPHER_LIST(),
	},
}

// cipherListCIPHER_LIST returns the wreq okhttp.rs CIPHER_LIST (15
// ciphers incl. 3DES), shared by okhttp3_14, okhttp4_10, okhttp4_12,
// and okhttp5.
func cipherListCIPHER_LIST() []uint16 {
	return []uint16{
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
	}
}

// Profile returns a tls_client.ClientProfile that mirrors
// okhttp's HTTP/2 stack. The cipher list (and therefore the
// ClientHelloSpec) is per-version, supplied by the v parameter.
func Profile(v Version) profiles.ClientProfile {
	entry, ok := allVersions[v]
	if !ok {
		// Fall back to V5's cipher list — this branch is never
		// hit because callers should pass a valid Version, but
		// keeps Profile resilient to typos in v.
		entry = allVersions[V5]
	}
	return profiles.NewClientProfile(
		utls.ClientHelloID{
			Client:               "OkHttp_" + string(v) + "_Custom",
			RandomExtensionOrder: false,
			Version:              string(v),
			Seed:                 nil,
			SpecFactory:          makeSpecFactory(entry.ciphers),
		},
		// settings mirror Okhttp4Android10 (contributed_custom_profiles.go:1343).
		// Only InitialWindowSize appears in the SETTINGS frame;
		// settingsOrder lists it as the only key.
		map[http2.SettingID]uint32{
			http2.SettingInitialWindowSize: 16777216,
		},
		[]http2.SettingID{
			http2.SettingInitialWindowSize,
		},
		// pseudoOrder from okhttp.rs (method, path, authority, scheme).
		[]string{":method", ":path", ":authority", ":scheme"},
		// connectionFlow = 16711681.
		16711681,
		nil, nil,
		0, false,
		nil, nil, 0, nil, false,
	)
}

// makeSpecFactory returns a tls-client SpecFactory bound to a
// per-version cipher list. The rest of the ClientHello (curves /
// sigalgs / extensions / padding) is shared across all OkHttp
// versions.
func makeSpecFactory(ciphers []uint16) func() (utls.ClientHelloSpec, error) {
	return func() (utls.ClientHelloSpec, error) {
		return utls.ClientHelloSpec{
			CipherSuites: ciphers,
			CompressionMethods: []byte{utls.CompressionNone},
			Extensions: []utls.TLSExtension{
				// RenegotiationInfo first (Okhttp4Android10 layout).
				&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateNever},
				&utls.SNIExtension{},
				&utls.ExtendedMasterSecretExtension{},
				// CURVES = "X25519:P-256:P-384" (no MLKEM, no GREASE).
				&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
					utls.X25519, utls.CurveP256, utls.CurveP384,
				}},
				&utls.SupportedPointsExtension{SupportedPoints: []byte{utls.PointFormatUncompressed}},
				&utls.SessionTicketExtension{},
				// ALPN before StatusRequest (Okhttp4Android10 layout).
				&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				// enable_ocsp_stapling=true → StatusRequest.
				&utls.StatusRequestExtension{},
				// SIGALGS_LIST from okhttp.rs (9 sigalgs incl. PKCS1WithSHA1).
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
					utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
					utls.PSSWithSHA512, utls.PKCS1WithSHA512, utls.PKCS1WithSHA1,
				}},
				// Single X25519 key share (no MLKEM, no GREASE).
				&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
					{Group: utls.X25519},
				}},
				&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
				&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
				// UtlsPadding for client_hello length alignment.
				&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
			},
		}, nil
	}
}

// HeadersFor returns the header set for the given OkHttp version,
// or an error if unsupported.
func HeadersFor(v Version) (fhttp.Header, error) {
	return headersFor(v)
}

// NewClient returns a tls_client.HttpClient configured for the given
// OkHttp version.
func NewClient(v Version) (tls_client.HttpClient, error) {
	h, err := headersFor(v)
	if err != nil {
		return nil, err
	}
	return tls_client.NewHttpClient(
		tls_client.NewNoopLogger(),
		tls_client.WithClientProfile(Profile(v)),
		tls_client.WithDefaultHeaders(fhttp.Header{
			"accept":          h["accept"],
			"accept-language": h["accept-language"],
			"user-agent":      h["user-agent"],
			"accept-encoding": h["accept-encoding"],
		}),
	)
}

// ApplyHeaders pins the chosen OkHttp version's header set onto an
// outgoing request.
func ApplyHeaders(req *fhttp.Request, v Version) error {
	h, err := headersFor(v)
	if err != nil {
		return err
	}
	for k, vs := range h {
		for _, val := range vs {
			req.Header.Set(k, val)
		}
	}
	return nil
}
