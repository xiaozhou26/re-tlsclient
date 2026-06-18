// Package chrome provides tls-client ClientProfiles that emulate
// Chrome 147 and Chrome 148 (Windows / macOS / Linux / Android / iOS)
// as defined in wreq-util/src/emulate/profile/chrome.rs.
//
// Both v147 and v148 share the same underlying TLS / HTTP/2 stack —
// they inherit from v132::build_emulation:
//
//	TLS:    tls_options!(7, CURVES_3)   →  permute_extensions=true
//	                                       + enable_ech_grease=true
//	                                       + pre_shared_key=true
//	                                       + alps_use_new_codepoint=true
//	                                       + curves = X25519MLKEM768:X25519:P-256:P-384
//	                                       + cipher = CIPHER_LIST (16, no SHA1, no 3DES)
//	                                       + sigalgs = SIGALGS_LIST (8, no PKCS1WithSHA1)
//	                                       + certificate_compressors = [Brotli]
//	HTTP/2: http2_options!(3)           →  initial_window=6291456
//	                                       + initial_connection_window=15728640
//	                                       + max_header_list=262144
//	                                       + header_table=65536
//	                                       + headers_stream_dep=(0, w=219, excl=true)
//	                                       + push=off
//	Header: header_initializer_with_zstd_priority
//	                                       →  zstd accept-encoding + "priority: u=0, i"
//
// The only difference between v147 and v148 is the UA / sec-ch-ua
// strings (see WindowsHeaders / MacOSHeaders / etc below, sourced
// directly from chrome.rs v147 / v148 mod_generator! blocks).
package chrome

import (
	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

// Version selects which Chrome major version's UA / sec-ch-ua strings
// the profile should emit. The TLS / HTTP/2 fingerprint is identical
// for both (v147 and v148 inherit v132::build_emulation in wreq-util).
type Version int

const (
	V147 Version = 147
	V148 Version = 148
)

// Platform selects the OS platform used in the UA / sec-ch-ua headers.
// All platforms share the same TLS / HTTP/2 fingerprint.
type Platform int

const (
	Windows Platform = iota
	MacOS
	Linux
	Android
	IOS
)

// Chrome147WindowsHeaders — sec-ch-ua + UA for Chrome 147 on Windows.
// Sourced from wreq-util/src/emulate/profile/chrome.rs v147 block.
var Chrome147WindowsHeaders = fhttp.Header{
	"sec-ch-ua":          {`"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`},
	"sec-ch-ua-mobile":   {"?0"},
	"sec-ch-ua-platform": {`"Windows"`},
	"user-agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"},
	"sec-fetch-dest":     {"document"},
	"sec-fetch-mode":     {"navigate"},
	"sec-fetch-site":     {"none"},
	"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
	"accept-encoding":    {"gzip, deflate, br, zstd"},
	"accept-language":    {"en-US,en;q=0.9"},
	"priority":           {"u=0, i"},
}

// Chrome148WindowsHeaders — sec-ch-ua + UA for Chrome 148 on Windows.
// Sourced from wreq-util/src/emulate/profile/chrome.rs v148 block.
var Chrome148WindowsHeaders = fhttp.Header{
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

// Profile returns a tls_client.ClientProfile that mirrors the
// v132::build_emulation stack used by both Chrome 147 and 148.
// Pick a Version via the UA / sec-ch-ua strings (see WindowsHeaders
// etc). The ClientHelloSpec and HTTP/2 SETTINGS frame are identical
// across versions and platforms.
func Profile() profiles.ClientProfile {
	return profiles.NewClientProfile(
		utls.ClientHelloID{
			Client:               "Chrome_v148_Custom",
			RandomExtensionOrder: false, // enabled globally via WithRandomTLSExtensionOrder
			Version:              "148",
			Seed:                 nil,
			SpecFactory:          specFactory,
		},
		// settings from wreq chrome v132 (http2_options!(3)).
		// initial_window_size=6291456, initial_connection_window_size=15728640,
		// header_table_size=65536, max_header_list_size=262144,
		// enable_push=false. Order matches settings_order!() in
		// chrome/http2.rs, but tls-client only emits the keys that
		// are present in the map.
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
		// pseudoOrder from chrome/http2.rs pseudo_order!()
		// (Method, Authority, Scheme, Path).
		[]string{":method", ":authority", ":scheme", ":path"},
		// initial_connection_window_size = 15728640 (http2_options!(3)).
		15728640,
		// priorities, headerPriority.
		nil, nil,
		// streamID, allowHTTP.
		0, false,
		// http3*.
		nil, nil, 0, nil, false,
	)
}

// specFactory reproduces the v132 Chrome ClientHello spec.
// Mirrors wreq-util's tls_options!(7, CURVES_3):
//   - permute_extensions=true → enabled via WithRandomTLSExtensionOrder
//   - enable_ech_grease=true → BoringGREASEECH
//   - pre_shared_key=true → PskModeDHE
//   - alps_use_new_codepoint=true → ApplicationSettingsExtensionNew
//   - curves = X25519MLKEM768:X25519:P-256:P-384
//   - cipher = CIPHER_LIST (16, no SHA1, no 3DES)
//   - sigalgs = SIGALGS_LIST (8, no PKCS1WithSHA1)
//   - certificate_compressors = [Brotli]
func specFactory() (utls.ClientHelloSpec, error) {
	return utls.ClientHelloSpec{
		// CIPHER_LIST from chrome/tls.rs:49-66 (16 ciphers).
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
			// permute_extensions=true (tls_options!(7) sets it
			// true) — enabled globally via WithRandomTLSExtensionOrder
			// on the client. The bare GreasedSNI placeholder at
			// position 0 is required so permute can shuffle from
			// a valid prefix.
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			// CURVES_3 = "X25519MLKEM768:X25519:P-256:P-384"
			// (4 entries, no P-521). GREASE placeholder at index 0.
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
			// SIGALGS_LIST from chrome/tls.rs:68-78 (8 sigalgs, no PKCS1WithSHA1).
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
			// KeyShare. utls fills empty Data fields with fresh
			// keys. GREASE placeholder gets Data:[0] so the fill
			// loop skips it; MLKEM and X25519 are filled in.
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
			// certificate_compressors = [Brotli].
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			}},
			// alps_use_new_codepoint=true → ApplicationSettingsExtensionNew.
			&utls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
			// pre_shared_key=true → PskModeDHE.
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			// enable_ech_grease=true → BoringGREASEECH()
			// (required — the master commit a5d2c766 includes
			// this and is the version that passes chatgpt.com).
			utls.BoringGREASEECH(),
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.UtlsGREASEExtension{},
		},
	}, nil
}

// NewClient returns a tls_client.HttpClient configured for the given
// Chrome version (147 or 148) and platform (Windows / macOS / Linux /
// Android / iOS). All version+platform combinations share the same
// TLS / HTTP/2 fingerprint — only the UA / sec-ch-ua header strings
// differ, sourced directly from wreq-util's chrome.rs mod_generator!
// blocks.
//
// permute_extensions is ON (matches wreq v132 TLS config).
func NewClient(v Version, p Platform) (tls_client.HttpClient, error) {
	h := headersFor(v, p)
	return tls_client.NewHttpClient(
		tls_client.NewNoopLogger(),
		tls_client.WithClientProfile(Profile()),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithDefaultHeaders(fhttp.Header{
			"sec-ch-ua":          h["sec-ch-ua"],
			"sec-ch-ua-mobile":   h["sec-ch-ua-mobile"],
			"sec-ch-ua-platform": h["sec-ch-ua-platform"],
			"user-agent":         h["user-agent"],
			"accept":             h["accept"],
			"accept-encoding":    h["accept-encoding"],
			"accept-language":    h["accept-language"],
		}),
	)
}

// ApplyHeaders pins the chosen Chrome version+platform header set onto
// an outgoing request, overriding any values already set. This is
// needed because WithDefaultHeaders only fills in missing headers —
// it does not overwrite the request's own header set.
func ApplyHeaders(req *fhttp.Request, v Version, p Platform) {
	h := headersFor(v, p)
	for k, vs := range h {
		for _, val := range vs {
			req.Header.Set(k, val)
		}
	}
}

// headersFor returns the header set for the given (v, p) combination.
// All UA / sec-ch-ua strings below are copied verbatim from
// wreq-util/src/emulate/profile/chrome.rs v147 and v148 blocks.
func headersFor(v Version, p Platform) fhttp.Header {
	switch v {
	case V147:
		switch p {
		case Windows:
			return fhttp.Header{
				"sec-ch-ua":          {`"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`},
				"sec-ch-ua-mobile":   {"?0"},
				"sec-ch-ua-platform": {`"Windows"`},
				"user-agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"},
				"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
				"accept-encoding":    {"gzip, deflate, br, zstd"},
				"accept-language":    {"en-US,en;q=0.9"},
			}
		case MacOS:
			return fhttp.Header{
				"sec-ch-ua":          {`"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`},
				"sec-ch-ua-mobile":   {"?0"},
				"sec-ch-ua-platform": {`"macOS"`},
				"user-agent":         {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"},
				"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
				"accept-encoding":    {"gzip, deflate, br, zstd"},
				"accept-language":    {"en-US,en;q=0.9"},
			}
		case Linux:
			return fhttp.Header{
				"sec-ch-ua":          {`"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`},
				"sec-ch-ua-mobile":   {"?0"},
				"sec-ch-ua-platform": {`"Linux"`},
				"user-agent":         {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"},
				"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
				"accept-encoding":    {"gzip, deflate, br, zstd"},
				"accept-language":    {"en-US,en;q=0.9"},
			}
		case Android:
			return fhttp.Header{
				"sec-ch-ua":          {`"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`},
				"sec-ch-ua-mobile":   {"?1"},
				"sec-ch-ua-platform": {`"Android"`},
				"user-agent":         {"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7712.122 Mobile Safari/537.36"},
				"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
				"accept-encoding":    {"gzip, deflate, br, zstd"},
				"accept-language":    {"en-US,en;q=0.9"},
			}
		case IOS:
			return fhttp.Header{
				"sec-ch-ua":          {`"Google Chrome";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`},
				"sec-ch-ua-mobile":   {"?1"},
				"sec-ch-ua-platform": {`"iOS"`},
				"user-agent":         {"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/147.0.7712.122 Mobile/15E148 Safari/604.1"},
				"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
				"accept-encoding":    {"gzip, deflate, br, zstd"},
				"accept-language":    {"en-US,en;q=0.9"},
			}
		}
	case V148:
		switch p {
		case Windows:
			return fhttp.Header{
				"sec-ch-ua":          {`"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"`},
				"sec-ch-ua-mobile":   {"?0"},
				"sec-ch-ua-platform": {`"Windows"`},
				"user-agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"},
				"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
				"accept-encoding":    {"gzip, deflate, br, zstd"},
				"accept-language":    {"en-US,en;q=0.9"},
			}
		case MacOS:
			return fhttp.Header{
				"sec-ch-ua":          {`"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"`},
				"sec-ch-ua-mobile":   {"?0"},
				"sec-ch-ua-platform": {`"macOS"`},
				"user-agent":         {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"},
				"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
				"accept-encoding":    {"gzip, deflate, br, zstd"},
				"accept-language":    {"en-US,en;q=0.9"},
			}
		case Linux:
			return fhttp.Header{
				"sec-ch-ua":          {`"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"`},
				"sec-ch-ua-mobile":   {"?0"},
				"sec-ch-ua-platform": {`"Linux"`},
				"user-agent":         {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"},
				"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
				"accept-encoding":    {"gzip, deflate, br, zstd"},
				"accept-language":    {"en-US,en;q=0.9"},
			}
		case Android:
			return fhttp.Header{
				"sec-ch-ua":          {`"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"`},
				"sec-ch-ua-mobile":   {"?1"},
				"sec-ch-ua-platform": {`"Android"`},
				"user-agent":         {"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36"},
				"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
				"accept-encoding":    {"gzip, deflate, br, zstd"},
				"accept-language":    {"en-US,en;q=0.9"},
			}
		case IOS:
			return fhttp.Header{
				"sec-ch-ua":          {`"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"`},
				"sec-ch-ua-mobile":   {"?1"},
				"sec-ch-ua-platform": {`"iOS"`},
				"user-agent":         {"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/148.0.0.0 Mobile/15E148 Safari/604.1"},
				"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
				"accept-encoding":    {"gzip, deflate, br, zstd"},
				"accept-language":    {"en-US,en;q=0.9"},
			}
		}
	}
	// Fallback: Windows v148 (matches old default).
	return Chrome148WindowsHeaders
}
