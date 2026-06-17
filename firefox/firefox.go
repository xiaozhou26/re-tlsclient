// Package firefox provides tls-client ClientProfiles that emulate
// Firefox 135..151 (Windows / macOS / Linux / Android / iOS) as
// defined in wreq-util/src/emulate/profile/firefox.rs.
//
// All supported versions (ff135..ff151) inherit from
// ff135::build_emulation and therefore share the same TLS / HTTP/2
// stack:
//
//   TLS:    tls_options!(4, CIPHER_LIST_1, CURVES_2, KEY_SHARES_2)
//           →  ECH + SCT + session_ticket + pre_shared_key
//              + psk_skip_session_tickets
//              + brotli/zlib/zstd cert compression
//              + MLKEM curves
//   HTTP/2: http2_options!(1)  →  init_window=131072, conn=12517377,
//                                 header_table=65536, push=off
//   Header: header_initializer_with_zstd
//           →  zstd accept-encoding + "te: trailers" (Firefox)
//
// Older wreq versions (ff109, ff117, ff128, ff133) use a different
// TLS stack and are not exposed here.
//
// The only thing that varies between (v, p) is the User-Agent string
// (and, for cross-OS families, the "te"/"priority" header set),
// sourced verbatim from firefox.rs's mod_generator! blocks.
//
// Extension layout mirrors tls-client's Firefox_117
// (internal_browser_profiles.go:1859) — Firefox's ECH is emitted as
// BoringGREASEECH (placeholder) to match the wire-level pattern
// wreq's BoringSSL backend produces.
package firefox

import (
	"fmt"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/bogdanfinn/utls/dicttls"
	utls "github.com/bogdanfinn/utls"
)

// Version selects which Firefox major version's User-Agent string the
// profile should emit. All Version values share the same TLS / HTTP/2
// fingerprint (ff135::build_emulation stack from wreq-util).
type Version int

const (
	V135 Version = 135
	V136 Version = 136
	V139 Version = 139
	V142 Version = 142
	V143 Version = 143
	V144 Version = 144
	V145 Version = 145
	V146 Version = 146
	V147 Version = 147
	V148 Version = 148
	V149 Version = 149
	V150 Version = 150
	V151 Version = 151
)

// Platform selects the OS platform for the UA string. wreq-util only
// defines the (v, p) combinations listed in the `allVersions` table
// below; other combinations return an error from NewClient / ApplyHeaders.
type Platform int

const (
	Windows Platform = iota
	MacOS
	Linux
	Android
	IOS
)

// allVersions is the closed set of (v, p) → UA-string combinations
// defined in wreq-util/src/emulate/profile/firefox.rs. Strings are
// copied verbatim. Versions not in this table are not supported.
var allVersions = map[Version]map[Platform]string{
	V135: {
		MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
		Windows: "Mozilla/5.0 (Windows NT 10.0; rv:135.0) Gecko/20100101 Firefox/135.0",
		Linux:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
	},
	V136: {
		MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0",
		Windows: "Mozilla/5.0 (Windows NT 10.0; rv:136.0) Gecko/20100101 Firefox/136.0",
		Linux:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0",
	},
	V139: {
		MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:139.0) Gecko/20100101 Firefox/139.0",
		Windows: "Mozilla/5.0 (Windows NT 10.0; rv:136.0) Gecko/20100101 Firefox/139.0",
		Linux:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/139.0",
	},
	V142: {
		Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0",
		MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0",
		Linux:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0",
		Android: "Mozilla/5.0 (Android 13; Mobile; rv:142.0) Gecko/142.0 Firefox/142.0",
		IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/142.0 Mobile/15E148 Safari/605.1.15",
	},
	V143: {
		Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
		MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0",
		Linux:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0",
		Android: "Mozilla/5.0 (Android 13; Mobile; rv:143.0) Gecko/143.0 Firefox/143.0",
		IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/143.0 Mobile/15E148 Safari/605.1.15",
	},
	V144: {
		Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0",
		MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:144.0) Gecko/20100101 Firefox/144.0",
		Linux:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
		Android: "Mozilla/5.0 (Android 13; Mobile; rv:144.0) Gecko/144.0 Firefox/144.0",
		IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/144.0 Mobile/15E148 Safari/605.1.15",
	},
	V145: {
		Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
		MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:145.0) Gecko/20100101 Firefox/145.0",
		Linux:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0",
		Android: "Mozilla/5.0 (Android 13; Mobile; rv:145.0) Gecko/145.0 Firefox/145.0",
		IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/145.0 Mobile/15E148 Safari/605.1.15",
	},
	V146: {
		Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:146.0) Gecko/20100101 Firefox/146.0",
		MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0",
		Linux:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:146.0) Gecko/20100101 Firefox/146.0",
		Android: "Mozilla/5.0 (Android 13; Mobile; rv:146.0) Gecko/146.0 Firefox/146.0",
		IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/146.0 Mobile/15E148 Safari/605.1.15",
	},
	V147: {
		Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
		MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0",
		Linux:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0",
		Android: "Mozilla/5.0 (Android 13; Mobile; rv:147.0) Gecko/147.0 Firefox/147.0",
		IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/147.0 Mobile/15E148 Safari/605.1.15",
	},
	V148: {
		Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0",
		MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0",
		Linux:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0",
		Android: "Mozilla/5.0 (Android 13; Mobile; rv:148.0) Gecko/148.0 Firefox/148.0",
		IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/148.0 Mobile/15E148 Safari/605.1.15",
	},
	V149: {
		Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
		MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0",
		Linux:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0",
		Android: "Mozilla/5.0 (Android 13; Mobile; rv:149.0) Gecko/149.0 Firefox/149.0",
		IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/149.0 Mobile/15E148 Safari/605.1.15",
	},
	V150: {
		Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0",
		MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:150.0) Gecko/20100101 Firefox/150.0",
		Linux:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0",
		Android: "Mozilla/5.0 (Android 13; Mobile; rv:150.0) Gecko/150.0 Firefox/150.0",
		IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/150.0 Mobile/15E148 Safari/605.1.15",
	},
	V151: {
		Windows: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0",
		MacOS:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0",
		Linux:   "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0",
		Android: "Mozilla/5.0 (Android 13; Mobile; rv:151.0) Gecko/151.0 Firefox/151.0",
		IOS:     "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/151.0 Mobile/15E148 Safari/605.1.15",
	},
}

// Profile returns a tls_client.ClientProfile that mirrors
// ff135::build_emulation from wreq-util. The fingerprint is identical
// for all Version values; the (v, p) combination only affects the
// User-Agent header.
func Profile() profiles.ClientProfile {
	return profiles.NewClientProfile(
		utls.ClientHelloID{
			Client:               "Firefox_135_Custom",
			RandomExtensionOrder: false,
			Version:              "135",
			Seed:                 nil,
			SpecFactory:          specFactory,
		},
		// settings from wreq firefox http2_options!(1):
		// initial_window_size=131072, initial_connection_window_size=12517377,
		// header_table_size=65536, push=off. We expose 4 keys
		// matching the map; the rest of settingsOrder!() defaults
		// are encoded in the order slice for round-tripping
		// fidelity, but tls-client only emits the keys that are
		// present in the map.
		map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingEnablePush:        0,
			http2.SettingInitialWindowSize: 131072,
			http2.SettingMaxFrameSize:      16384,
		},
		// settingsOrder from wreq-util's firefox/http2.rs settings_order!().
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
		[]string{":method", ":path", ":authority", ":scheme"},
		// initial_connection_window_size = 12517377.
		12517377,
		nil, nil,
		3, false,
		nil, nil, 0, nil, false,
	)
}

// specFactory reproduces the ff135 ClientHello spec.
// Mirrors wreq-util's tls_options!(4, CIPHER_LIST_1, CURVES_2, KEY_SHARES_2)
// with extension layout from tls-client Firefox_117.
func specFactory() (utls.ClientHelloSpec, error) {
	return utls.ClientHelloSpec{
		// CIPHER_LIST_1 from firefox/tls.rs.
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
			// CURVES_2 = "X25519MLKEM768:X25519:P-256:P-384:P-521:ffdhe2048:ffdhe3072"
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519MLKEM768, utls.X25519, utls.CurveP256, utls.CurveP384,
				utls.CurveP521, utls.CurveID(dicttls.SupportedGroups_ffdhe2048), utls.CurveID(dicttls.SupportedGroups_ffdhe3072),
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{utls.PointFormatUncompressed}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			// DELEGATED_CREDENTIALS (firefox/tls.rs).
			&utls.DelegatedCredentialsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256, utls.ECDSAWithP384AndSHA384,
					utls.ECDSAWithP521AndSHA512, utls.ECDSAWithSHA1,
				},
			},
			&utls.SCTExtension{},
			// KEY_SHARES_2 = [X25519_MLKEM768, X25519, P256].
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
				{Group: utls.CurveP256},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			// SIGALGS_LIST from firefox/tls.rs.
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.ECDSAWithP384AndSHA384, utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256, utls.PSSWithSHA384, utls.PSSWithSHA512,
				utls.PKCS1WithSHA256, utls.PKCS1WithSHA384, utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1, utls.PKCS1WithSHA1,
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			// record_size_limit = 0x4001.
			&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
			// certificate_compressors = [Zlib, Brotli, Zstd].
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionZlib, utls.CertCompressionBrotli, utls.CertCompressionZstd,
			}},
			// enable_ech_grease=true → BoringGREASEECH (placeholder).
			utls.BoringGREASEECH(),
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}, nil
}

// HeadersFor returns the header set for the given (v, p) combination,
// or an error if wreq-util does not define that combination.
func HeadersFor(v Version, p Platform) (fhttp.Header, error) {
	platforms, ok := allVersions[v]
	if !ok {
		return nil, fmt.Errorf("firefox: unsupported version %d", v)
	}
	ua, ok := platforms[p]
	if !ok {
		return nil, fmt.Errorf("firefox: unsupported platform %d for version %d", p, v)
	}
	// All Firefox UAs share the same accept / accept-encoding /
	// accept-language / sec-fetch-* / priority set from
	// header_initializer_with_zstd. "te: trailers" is Firefox's
	// signature header — emitted by wreq's FirefoxEmulation.
	return fhttp.Header{
		"te":              {"trailers"},
		"user-agent":      {ua},
		"accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		"accept-language": {"en-US,en;q=0.5"},
		"accept-encoding": {"gzip, deflate, br, zstd"},
		"sec-fetch-dest":  {"document"},
		"sec-fetch-mode":  {"navigate"},
		"sec-fetch-site":  {"none"},
		"priority":        {"u=0, i"},
	}, nil
}

// NewClient returns a tls_client.HttpClient configured for the given
// Firefox version (135..151) and platform.
func NewClient(v Version, p Platform) (tls_client.HttpClient, error) {
	h, err := HeadersFor(v, p)
	if err != nil {
		return nil, err
	}
	return tls_client.NewHttpClient(
		tls_client.NewNoopLogger(),
		tls_client.WithClientProfile(Profile()),
		tls_client.WithDefaultHeaders(fhttp.Header{
			"te":              h["te"],
			"user-agent":      h["user-agent"],
			"accept":          h["accept"],
			"accept-language": h["accept-language"],
			"accept-encoding": h["accept-encoding"],
		}),
	)
}

// ApplyHeaders pins the chosen (v, p) header set onto an outgoing
// request.
func ApplyHeaders(req *fhttp.Request, v Version, p Platform) error {
	h, err := HeadersFor(v, p)
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
