// Package safari provides tls-client ClientProfiles that emulate
// Safari 26.0..26.4 (macOS / iOS / iPadOS) as defined in
// wreq-util/src/emulate/profile/safari.rs.
//
// All supported Safari versions inherit safari26::build_emulation
// (or safari18_5::build_emulation for 26.1/26.2/26.3/26.4) and
// therefore share the same TLS / HTTP/2 stack:
//
//   TLS:    tls_options!(3, CIPHER_LIST_3, SIGALGS_LIST_2, CURVES_2)
//           →  grease_enabled=true
//              + session_ticket=false
//              + enable_ocsp_stapling=true
//              + enable_signed_cert_timestamps=true
//              + preserve_tls13_cipher_list=true
//              + certificate_compressors=[Zlib]
//              + alps_protos=HTTP2 (alps_use_new_codepoint=false default)
//              + permute_extensions=false
//              + curves = "X25519MLKEM768:X25519:P-256:P-384:P-521"
//              + sigalgs = SIGALGS_LIST_2
//              + cipher = CIPHER_LIST_3 (21 ciphers incl. 3DES)
//   HTTP/2: http2_options!(6)  →  initial_window=2097152, conn=10420225,
//                                 push=off, max_concurrent_streams=100
//   Header: header_initializer_for_18  →  accept-encoding includes "br"
//
// The only difference between (v, p) combinations is the
// User-Agent string (and, for cross-device families, the
// accept/accept-language/priority header set).
//
// Extension layout is mirrored on tls-client's Safari_IOS_26_0
// (internal_browser_profiles.go:1471) — wreq's underlying utls fork
// emits the same shape: GREASE in SupportedCurves, ALPN before
// StatusRequest, PSKKeyExchangeModes alongside, Zlib certificate
// compression.
package safari

import (
	"fmt"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

// Version selects which Safari minor version's User-Agent string the
// profile should emit. All Version values share the same TLS / HTTP/2
// fingerprint (safari26::build_emulation stack).
type Version string

const (
	V26_0 Version = "26.0"
	V26_1 Version = "26.1"
	V26_2 Version = "26.2"
	V26_3 Version = "26.3"
	V26_4 Version = "26.4"
)

// Platform selects the device platform for the UA string.
type Platform int

const (
	MacOS Platform = iota
	IOS
	IPadOS
)

// allVersions is the closed set of (v, p) → UA combinations defined
// in wreq-util/src/emulate/profile/safari.rs. Strings are copied
// verbatim.
var allVersions = map[Version]map[Platform]string{
	V26_0: {
		MacOS:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
		IOS:    "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
		IPadOS: "Mozilla/5.0 (iPad; CPU OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
	},
	V26_1: {
		MacOS: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Safari/605.1.15",
	},
	V26_2: {
		MacOS:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15",
		IOS:    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Mobile/15E148 Safari/604.1",
		IPadOS: "Mozilla/5.0 (iPad; CPU OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Mobile/15E148 Safari/604.1",
	},
	V26_3: {
		MacOS: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.3 Safari/605.1.15",
	},
	V26_4: {
		MacOS: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Safari/605.1.15",
	},
}

// Profile returns a tls_client.ClientProfile that mirrors
// safari26::build_emulation. The fingerprint is identical for all
// Version values; the (v, p) combination only affects the
// User-Agent header.
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
		// connectionFlow = 10420225.
		10420225,
		nil, nil,
		0, false,
		nil, nil, 0, nil, false,
	)
}

// specFactory reproduces the Safari 26 ClientHello spec.
// Mirrors wreq-util's tls_options!(3, CIPHER_LIST_3, SIGALGS_LIST_2, CURVES_2)
// and tls-client's Safari_IOS_26_0 extension layout.
func specFactory() (utls.ClientHelloSpec, error) {
	return utls.ClientHelloSpec{
		// CIPHER_LIST_3 from safari/tls.rs (21 ciphers incl. 3DES).
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
			// CURVES_2 = "X25519MLKEM768:X25519:P-256:P-384:P-521".
			// GREASE placeholder at index 0 (Safari_IOS_26_0 layout).
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{utls.PointFormatUncompressed}},
			// ALPN before StatusRequest (Safari_IOS_26_0).
			// session_ticket=false → omit SessionTicketExtension.
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			// SIGALGS_LIST_2 from safari/tls.rs.
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
				utls.PSSWithSHA512, utls.PKCS1WithSHA512, utls.PKCS1WithSHA1,
			}},
			&utls.SCTExtension{},
			// KeyShare. utls fills empty Data fields with fresh
			// keys. GREASE placeholder gets Data:[0] so the fill
			// loop skips it; MLKEM and X25519 are filled in.
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER, utls.VersionTLS13, utls.VersionTLS12,
			}},
			// certificate_compressors = [Zlib].
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionZlib}},
			&utls.UtlsGREASEExtension{},
		},
	}, nil
}

// HeadersFor returns the header set for the given (v, p) combination,
// or an error if wreq-util does not define that combination.
func HeadersFor(v Version, p Platform) (fhttp.Header, error) {
	platforms, ok := allVersions[v]
	if !ok {
		return nil, fmt.Errorf("safari: unsupported version %s", v)
	}
	ua, ok := platforms[p]
	if !ok {
		return nil, fmt.Errorf("safari: unsupported platform %d for version %s", p, v)
	}
	return fhttp.Header{
		"sec-fetch-dest":  {"document"},
		"user-agent":      {ua},
		"accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		"sec-fetch-site":  {"none"},
		"sec-fetch-mode":  {"navigate"},
		"accept-language": {"en-US,en;q=0.9"},
		"priority":        {"u=0, i"},
		"accept-encoding": {"gzip, deflate, br"},
	}, nil
}

// NewClient returns a tls_client.HttpClient configured for the given
// Safari version (26.0..26.4) and platform (macOS / iOS / iPadOS).
// permute_extensions is OFF (matches wreq Safari 26 TLS config).
func NewClient(v Version, p Platform) (tls_client.HttpClient, error) {
	h, err := HeadersFor(v, p)
	if err != nil {
		return nil, err
	}
	return tls_client.NewHttpClient(
		tls_client.NewNoopLogger(),
		tls_client.WithClientProfile(Profile()),
		tls_client.WithDefaultHeaders(fhttp.Header{
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
