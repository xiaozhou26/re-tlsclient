// Package edge provides a tls-client ClientProfile that emulates
// Microsoft Edge 148 (5 platforms) as defined in
// wreq-util/src/emulate/profile/chrome.rs (edge148 mod_generator! block,
// v132::build_emulation). Edge reuses Chrome 148's TLS and HTTP/2
// configuration; only the UA / sec-ch-ua / sec-ch-ua-platform strings
// differ per platform (Microsoft Edge brand instead of Google Chrome).
package edge

import (
	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

// Version is kept for compatibility with callers. The profile is fixed
// to Edge 148 (wreq edge148 / v132::build_emulation).
type Version int

const (
	V134 Version = 134
	V135 Version = 135
	V136 Version = 136
	V137 Version = 137
	V138 Version = 138
	V139 Version = 139
	V140 Version = 140
	V141 Version = 141
	V142 Version = 142
	V143 Version = 143
	V144 Version = 144
	V145 Version = 145
	V146 Version = 146
	V147 Version = 147
	V148 Version = 148
)

// Platform selects the OS platform used in the UA / sec-ch-ua-platform
// headers. All platforms share the same TLS / HTTP/2 fingerprint
// (v132::build_emulation). UA and sec-ch-ua-mobile are per-platform.
type Platform int

const (
	Windows Platform = iota
	MacOS
	Linux
	Android
	IOS
)

// WindowsHeaders — UA + sec-ch-ua for Edge 148 on Windows.
// Sourced verbatim from wreq-util/src/emulate/profile/chrome.rs edge148.
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

// MacOSHeaders — Edge 148 on macOS.
var MacOSHeaders = fhttp.Header{
	"sec-ch-ua":          {`"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"`},
	"sec-ch-ua-mobile":   {"?0"},
	"sec-ch-ua-platform": {`"macOS"`},
	"user-agent":         {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0"},
	"sec-fetch-dest":     {"document"},
	"sec-fetch-mode":     {"navigate"},
	"sec-fetch-site":     {"none"},
	"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
	"accept-encoding":    {"gzip, deflate, br, zstd"},
	"accept-language":    {"en-US,en;q=0.9"},
	"priority":           {"u=0, i"},
}

// LinuxHeaders — Edge 148 on Linux. (Edge "shouldn't exist" on Linux
// per wreq comment, but real UAs exist in the wild and are listed.)
var LinuxHeaders = fhttp.Header{
	"sec-ch-ua":          {`"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"`},
	"sec-ch-ua-mobile":   {"?0"},
	"sec-ch-ua-platform": {`"Linux"`},
	"user-agent":         {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0"},
	"sec-fetch-dest":     {"document"},
	"sec-fetch-mode":     {"navigate"},
	"sec-fetch-site":     {"none"},
	"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
	"accept-encoding":    {"gzip, deflate, br, zstd"},
	"accept-language":    {"en-US,en;q=0.9"},
	"priority":           {"u=0, i"},
}

// AndroidHeaders — Edge 148 on Android. Note UA suffix is "EdgA/", not "Edg/".
var AndroidHeaders = fhttp.Header{
	"sec-ch-ua":          {`"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"`},
	"sec-ch-ua-mobile":   {"?1"},
	"sec-ch-ua-platform": {`"Android"`},
	"user-agent":         {"Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36 EdgA/148.0.0.0"},
	"sec-fetch-dest":     {"document"},
	"sec-fetch-mode":     {"navigate"},
	"sec-fetch-site":     {"none"},
	"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
	"accept-encoding":    {"gzip, deflate, br, zstd"},
	"accept-language":    {"en-US,en;q=0.9"},
	"priority":           {"u=0, i"},
}

// IOSHeaders — Edge 148 on iOS. Note UA uses "EdgiOS/" + Safari/605.1.15.
var IOSHeaders = fhttp.Header{
	"sec-ch-ua":          {`"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"`},
	"sec-ch-ua-mobile":   {"?1"},
	"sec-ch-ua-platform": {`"iOS"`},
	"user-agent":         {"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 EdgiOS/148.0.0.0 Mobile/15E148 Safari/605.1.15"},
	"sec-fetch-dest":     {"document"},
	"sec-fetch-mode":     {"navigate"},
	"sec-fetch-site":     {"none"},
	"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
	"accept-encoding":    {"gzip, deflate, br, zstd"},
	"accept-language":    {"en-US,en;q=0.9"},
	"priority":           {"u=0, i"},
}

// headersFor returns the per-platform header set for Edge 148. Falls
// back to Windows if (v, p) is unrecognized.
func headersFor(_ Version, p Platform) fhttp.Header {
	switch p {
	case Windows:
		return WindowsHeaders
	case MacOS:
		return MacOSHeaders
	case Linux:
		return LinuxHeaders
	case Android:
		return AndroidHeaders
	case IOS:
		return IOSHeaders
	}
	return WindowsHeaders
}

// Profile returns a tls_client.ClientProfile that mirrors Edge 148
// (v132::build_emulation). All (v, p) combinations share the same
// ClientHelloSpec and HTTP/2 SETTINGS frame; only the UA / sec-ch-ua
// strings differ per platform.
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

// specFactory reproduces the v132 Chrome/Edge ClientHello spec.
// Mirrors wreq-util's tls_options!(7, CURVES_3). The cipher list is
// the full Chrome 148 list (16 entries, incl. legacy RSA/AES-CBC);
// Edge 148 inherits this verbatim because Edge IS Chromium. Skipping
// the legacy 6 ciphers (as the prior edge148 revision did) drops
// JA4 from `t13d1516h2_...` to `t13d916h2_...` and is what trips
// Cloudflare's bot score above the chatgpt.com threshold.
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
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli}},
			&utls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			utls.BoringGREASEECH(),
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.UtlsGREASEExtension{},
		},
	}, nil
}

// HeadersFor returns the per-platform Edge 148 header set.
func HeadersFor(_ Version, p Platform) fhttp.Header {
	return headersFor(0, p)
}

// NewClient returns a tls_client.HttpClient pre-configured with Edge
// 148 and the per-platform header set. permute_extensions is ON
// (matches wreq v132 TLS config).
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

// ApplyHeaders pins the chosen Edge (v, p) header set onto an
// outgoing request, overriding any values already set. This is needed
// because WithDefaultHeaders only fills in missing headers — it does
// not overwrite the request's own header set.
func ApplyHeaders(req *fhttp.Request, v Version, p Platform) error {
	h := headersFor(v, p)
	for k, vs := range h {
		for _, val := range vs {
			req.Header.Set(k, val)
		}
	}
	return nil
}
