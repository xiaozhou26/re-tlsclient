// Package opera provides tls-client ClientProfiles that emulate
// Opera 116..131 (Windows / macOS) as defined in
// wreq-util/src/emulate/profile/opera.rs.
//
// All supported Opera versions inherit opera116::build_emulation and
// therefore share the same TLS / HTTP/2 stack:
//
//   TLS:    tls_options!(CURVES) — single-arg form
//           →  permute_extensions=true
//              + pre_shared_key=true
//              + enable_ech_grease=true
//              + alps_use_new_codepoint=false (default)
//              + curves = "X25519MLKEM768:X25519:P-256:P-384"
//              + cipher = CIPHER_LIST (16, no SHA1, no 3DES)
//              + sigalgs = SIGALGS_LIST (8, no PKCS1WithSHA1)
//              + certificate_compressors = [Brotli]
//   HTTP/2: http2_options!()      —  initial_window_size=6291456
//                                  + initial_connection_window_size=15728640
//                                  + max_header_list=262144
//                                  + header_table=65536
//                                  + push=off
//   Header: header_initializer_with_zstd_priority
//                                  —  zstd accept-encoding + "priority: u=0, i"
//
// The only difference between (v, p) combinations is the User-Agent
// / sec-ch-ua strings. Each Opera N corresponds to a Chromium
// M = N + 15 (i.e. opera116 → Chrome 131, opera131 → Chrome 147).
//
// Extension layout mirrors tls-client's Chrome_146. KeyShare sits
// at position 2 (after GREASE), ALPS uses the old codepoint
// (alps_use_new_codepoint=false), BoringGREASEECH is emitted
// (enable_ech_grease=true), and PSKKeyExchangeModes is present
// (pre_shared_key=true).
package opera

import (
	"fmt"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

// Version selects which Opera major version's UA / sec-ch-ua strings
// the profile should emit. All Version values share the same
// TLS / HTTP/2 fingerprint (opera116::build_emulation stack).
type Version int

const (
	V116 Version = 116
	V117 Version = 117
	V118 Version = 118
	V119 Version = 119
	V120 Version = 120
	V121 Version = 121
	V122 Version = 122
	V123 Version = 123
	V124 Version = 124
	V125 Version = 125
	V126 Version = 126
	V127 Version = 127
	V128 Version = 128
	V129 Version = 129
	V130 Version = 130
	V131 Version = 131
)

// Platform selects the OS platform for the UA string. wreq-util only
// defines MacOS and Windows for Opera.
type Platform int

const (
	Windows Platform = iota
	MacOS
)

// allVersions is the closed set of (v, p) → (sec-ch-ua, user-agent)
// combinations defined in wreq-util/src/emulate/profile/opera.rs.
// Strings are copied verbatim.
var allVersions = map[Version]map[Platform]ua{
	V116: {
		MacOS:   {`"Opera";v="116", "Chromium";v="131", "Not_A Brand";v="24"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0"},
		Windows: {`"Opera";v="116", "Chromium";v="131", "Not_A Brand";v="24"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0"},
	},
	V117: {
		MacOS:   {`"Not A(Brand";v="8", "Chromium";v="132", "Opera";v="117"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 OPR/117.0.0.0"},
		Windows: {`"Not A(Brand";v="8", "Chromium";v="132", "Opera";v="117"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 OPR/117.0.0.0"},
	},
	V118: {
		MacOS:   {`"Not(A:Brand";v="99", "Opera";v="118", "Chromium";v="133"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 OPR/118.0.0.0"},
		Windows: {`"Not(A:Brand";v="99", "Opera";v="118", "Chromium";v="133"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 OPR/118.0.0.0"},
	},
	V119: {
		MacOS:   {`"Chromium";v="134", "Not:A-Brand";v="24", "Opera";v="119"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 OPR/119.0.0.0"},
		Windows: {`"Chromium";v="134", "Not:A-Brand";v="24", "Opera";v="119"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 OPR/119.0.0.0"},
	},
	V120: {
		MacOS:   {`"Chromium";v="135", "Not:A-Brand";v="24", "Opera";v="120"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 OPR/120.0.0.0"},
		Windows: {`"Chromium";v="135", "Not:A-Brand";v="24", "Opera";v="120"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 OPR/120.0.0.0"},
	},
	V121: {
		MacOS:   {`"Opera";v="121", "Chromium";v="137", "Not/A)Brand";v="24"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 OPR/121.0.0.0"},
		Windows: {`"Opera";v="121", "Chromium";v="137", "Not/A)Brand";v="24"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 OPR/121.0.0.0"},
	},
	V122: {
		MacOS:   {`"Chromium";v="138", "Not=A?Brand";v="24", "Opera";v="122"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 OPR/122.0.0.0"},
		Windows: {`"Chromium";v="138", "Not=A?Brand";v="24", "Opera";v="122"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 OPR/122.0.0.0"},
	},
	V123: {
		MacOS:   {`"Chromium";v="139", "Not=A?Brand";v="24", "Opera";v="123"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 OPR/123.0.0.0"},
		Windows: {`"Chromium";v="139", "Not=A?Brand";v="24", "Opera";v="123"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 OPR/123.0.0.0"},
	},
	V124: {
		MacOS:   {`"Chromium";v="140", "Not=A?Brand";v="24", "Opera";v="124"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 OPR/124.0.0.0"},
		Windows: {`"Chromium";v="140", "Not=A?Brand";v="24", "Opera";v="124"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 OPR/124.0.0.0"},
	},
	V125: {
		MacOS:   {`"Opera";v="125", "Not?A_Brand";v="8", "Chromium";v="141"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 OPR/125.0.0.0"},
		Windows: {`"Opera";v="125", "Not?A_Brand";v="8", "Chromium";v="141"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 OPR/125.0.0.0"},
	},
	V126: {
		MacOS:   {`"Not:A-Brand";v="99", "Opera";v="126", "Chromium";v="142"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 OPR/126.0.0.0"},
		Windows: {`"Not:A-Brand";v="99", "Opera";v="126", "Chromium";v="142"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 OPR/126.0.0.0"},
	},
	V127: {
		MacOS:   {`"Not:A-Brand";v="99", "Opera";v="127", "Chromium";v="143"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 OPR/127.0.0.0"},
		Windows: {`"Not:A-Brand";v="99", "Opera";v="127", "Chromium";v="143"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 OPR/127.0.0.0"},
	},
	V128: {
		MacOS:   {`"Not:A-Brand";v="99", "Opera";v="128", "Chromium";v="144"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 OPR/128.0.0.0"},
		Windows: {`"Not:A-Brand";v="99", "Opera";v="128", "Chromium";v="144"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 OPR/128.0.0.0"},
	},
	V129: {
		MacOS:   {`"Not:A-Brand";v="99", "Opera";v="129", "Chromium";v="145"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 OPR/129.0.0.0"},
		Windows: {`"Not:A-Brand";v="99", "Opera";v="129", "Chromium";v="145"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 OPR/129.0.0.0"},
	},
	V130: {
		MacOS:   {`"Not:A-Brand";v="99", "Opera";v="130", "Chromium";v="146"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 OPR/130.0.0.0"},
		Windows: {`"Not:A-Brand";v="99", "Opera";v="130", "Chromium";v="146"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 OPR/130.0.0.0"},
	},
	V131: {
		MacOS:   {`"Opera";v="131", "Not.A/Brand";v="8", "Chromium";v="147"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 OPR/131.0.0.0"},
		Windows: {`"Opera";v="131", "Not.A/Brand";v="8", "Chromium";v="147"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 OPR/131.0.0.0"},
	},
}

// ua is a (sec-ch-ua, user-agent) pair for one (v, p) combination.
type ua struct {
	secChUa string
	userAg  string
}

// Profile returns a tls_client.ClientProfile that mirrors
// opera116::build_emulation from wreq-util. The fingerprint is
// identical for all Version values; the (v, p) combination only
// affects the User-Agent / sec-ch-ua headers.
func Profile() profiles.ClientProfile {
	return profiles.NewClientProfile(
		utls.ClientHelloID{
			Client:               "Opera_116_Custom",
			RandomExtensionOrder: false, // enabled globally via WithRandomTLSExtensionOrder
			Version:              "116",
			Seed:                 nil,
			SpecFactory:          specFactory,
		},
		// settings from wreq opera http2_options!().
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
		15728640,
		nil, nil,
		0, false,
		nil, nil, 0, nil, false,
	)
}

// specFactory reproduces the Opera 116+ ClientHello spec.
// Mirrors wreq-util's tls_options!(CURVES) — single-arg form.
// Layout follows tls-client Chrome_146.
func specFactory() (utls.ClientHelloSpec, error) {
	return utls.ClientHelloSpec{
		// CIPHER_LIST from opera/tls.rs (16 ciphers).
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
			// KeyShare at position 2 (Chrome-146 layout).
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			}},
			&utls.SNIExtension{},
			// alps_use_new_codepoint=false → use old ALPS codepoint
			// (ApplicationSettingsExtension, not the New variant).
			&utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			// CURVES = "X25519MLKEM768:X25519:P-256:P-384" with
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
			// SIGALGS_LIST from opera/tls.rs (8 sigalgs, no PKCS1WithSHA1).
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

// HeadersFor returns the header set for the given (v, p) combination,
// or an error if wreq-util does not define that combination.
func HeadersFor(v Version, p Platform) (fhttp.Header, error) {
	platforms, ok := allVersions[v]
	if !ok {
		return nil, fmt.Errorf("opera: unsupported version %d", v)
	}
	u, ok := platforms[p]
	if !ok {
		return nil, fmt.Errorf("opera: unsupported platform %d for version %d", p, v)
	}
	return fhttp.Header{
		"sec-ch-ua":          {u.secChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"sec-ch-ua-platform": platformSecChUaPlatform(p),
		"user-agent":         {u.userAg},
		"sec-fetch-dest":     {"document"},
		"sec-fetch-mode":     {"navigate"},
		"sec-fetch-site":     {"none"},
		"accept":             {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {"en-US,en;q=0.9"},
		"priority":           {"u=0, i"},
	}, nil
}

func platformSecChUaPlatform(p Platform) []string {
	switch p {
	case Windows:
		return []string{`"Windows"`}
	case MacOS:
		return []string{`"macOS"`}
	}
	return nil
}

// chromiumVersionFor returns the Chromium version (Chrome NN.0.0.0)
// corresponding to a given Opera version. Opera N → Chrome (N+15).
// (Unused for now — kept as a reference for anyone hand-rolling new
// entries. The allVersions table above is the source of truth.)
func chromiumVersionFor(v Version) int { return int(v) + 15 }

// NewClient returns a tls_client.HttpClient configured for the given
// Opera version (116..131) and platform. permute_extensions is ON
// (matches wreq opera116 TLS config).
func NewClient(v Version, p Platform) (tls_client.HttpClient, error) {
	h, err := HeadersFor(v, p)
	if err != nil {
		return nil, err
	}
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
