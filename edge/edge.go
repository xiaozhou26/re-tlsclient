// Package edge provides tls-client ClientProfiles that emulate
// Microsoft Edge 134..148 (Windows / macOS / Linux / Android / iOS)
// as defined in wreq-util/src/emulate/profile/chrome.rs.
//
// All supported Edge versions (edge134..edge148) inherit
// v132::build_emulation — the same TLS / HTTP/2 stack as Chrome
// 147/148. The only difference between (v, p) combinations is the
// User-Agent / sec-ch-ua / Edg version tag.
//
//   TLS:    tls_options!(7, CURVES_3)   →  permute_extensions + ECH GREASE
//                                          + PSK + alps_new_codepoint
//                                          + X25519MLKEM768 curves
//   HTTP/2: http2_options!(3)           →  push off, init_window=6291456,
//                                          initial_connection_window=15728640
//   Header: header_initializer_with_zstd_priority
//                                          →  zstd accept-encoding + priority
//
// Older Edge versions (edge101/122/127/131) use the older v124/v117
// stacks and are not exposed here.
package edge

import (
	"fmt"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

// Version selects which Edge major version's User-Agent string the
// profile should emit. All Version values share the same TLS / HTTP/2
// fingerprint (v132::build_emulation stack from wreq-util).
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

// Platform selects the OS platform for the UA string.
type Platform int

const (
	Windows Platform = iota
	MacOS
	Linux
	Android
	IOS
)

// ua is a (sec-ch-ua, user-agent) pair for one (v, p) combination.
// Sourced verbatim from wreq-util/src/emulate/profile/chrome.rs's
// edge134..edge148 mod_generator! blocks. Versions with a special
// build number (edge147: 147.0.3912.51) are stored explicitly; the
// other versions use the "N.0.0.0" build tag.
type ua struct {
	secChUa string
	userAg  string
}

// allVersions is the closed set of (v, p) → UA combinations defined
// in wreq-util. The generic Chromium→N.0.0.0 + Edg→N.0.0.0 build
// tags apply to most (v, p); the explicit edge147 entries and the
// edge148 entries with their exact "Not/A)Brand" / "Not.A/Brand" /
// "Not_A Brand" / "Not_A Brand" / "Not-A.Brand" patterns are
// preserved verbatim.
//
// Layout: allVersions[v][p] = ua.
//
// sec-ch-ua tends to be constant within a version (i.e. all five
// platforms of edge143 share the same sec-ch-ua, all five of edge147
// share the same, etc.), but the User-Agent string varies per
// platform. So the table is keyed by (v, p).
var allVersions = map[Version]map[Platform]ua{
	V134: {
		MacOS:   {`"Chromium";v="134", "Microsoft Edge";v="134", "Not-A.Brand";v="99"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0"},
		Android: {`"Chromium";v="134", "Microsoft Edge";v="134", "Not-A.Brand";v="99"`, "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36 EdgA/134.0.0.0"},
		Windows: {`"Chromium";v="134", "Microsoft Edge";v="134", "Not-A.Brand";v="99"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0"},
		Linux:   {`"Chromium";v="134", "Microsoft Edge";v="134", "Not-A.Brand";v="99"`, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0"},
		IOS:     {`"Chromium";v="134", "Microsoft Edge";v="134", "Not-A.Brand";v="99"`, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0"},
	},
	V135: {
		MacOS:   {`"Chromium";v="135", "Not:A-Brand";v="24", "Microsoft Edge";v="135"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0"},
		Android: {`"Chromium";v="135", "Not:A-Brand";v="24", "Microsoft Edge";v="135"`, "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36 EdgA/135.0.0.0"},
		Windows: {`"Chromium";v="135", "Not:A-Brand";v="24", "Microsoft Edge";v="135"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0"},
		Linux:   {`"Chromium";v="135", "Not:A-Brand";v="24", "Microsoft Edge";v="135"`, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0"},
		IOS:     {`"Chromium";v="135", "Not:A-Brand";v="24", "Microsoft Edge";v="135"`, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0"},
	},
	V136: {
		MacOS:   {`"Chromium";v="136", "Not:A-Brand";v="24", "Microsoft Edge";v="136"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0"},
		Android: {`"Chromium";v="136", "Not:A-Brand";v="24", "Microsoft Edge";v="136"`, "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36 EdgA/136.0.0.0"},
		Windows: {`"Chromium";v="136", "Not:A-Brand";v="24", "Microsoft Edge";v="136"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0"},
		Linux:   {`"Chromium";v="136", "Not:A-Brand";v="24", "Microsoft Edge";v="136"`, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0"},
		IOS:     {`"Chromium";v="136", "Not:A-Brand";v="24", "Microsoft Edge";v="136"`, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0"},
	},
	V137: {
		MacOS:   {`"Chromium";v="137", "Not:A-Brand";v="24", "Microsoft Edge";v="137"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0"},
		Android: {`"Chromium";v="137", "Not:A-Brand";v="24", "Microsoft Edge";v="137"`, "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36 EdgA/137.0.0.0"},
		Windows: {`"Chromium";v="137", "Not:A-Brand";v="24", "Microsoft Edge";v="137"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0"},
		Linux:   {`"Chromium";v="137", "Not:A-Brand";v="24", "Microsoft Edge";v="137"`, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0"},
		IOS:     {`"Chromium";v="137", "Not:A-Brand";v="24", "Microsoft Edge";v="137"`, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0"},
	},
	V138: {
		MacOS:   {`"Chromium";v="138", "Not=A?Brand";v="24", "Microsoft Edge";v="138"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0"},
		Android: {`"Chromium";v="138", "Not=A?Brand";v="24", "Microsoft Edge";v="138"`, "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36 EdgA/138.0.0.0"},
		Windows: {`"Chromium";v="138", "Not=A?Brand";v="24", "Microsoft Edge";v="138"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0"},
		Linux:   {`"Chromium";v="138", "Not=A?Brand";v="24", "Microsoft Edge";v="138"`, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0"},
		IOS:     {`"Chromium";v="138", "Not=A?Brand";v="24", "Microsoft Edge";v="138"`, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0"},
	},
	V139: {
		MacOS:   {`"Chromium";v="139", "Not=A?Brand";v="24", "Microsoft Edge";v="139"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0"},
		Android: {`"Chromium";v="139", "Not=A?Brand";v="24", "Microsoft Edge";v="139"`, "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Mobile Safari/537.36 EdgA/139.0.0.0"},
		Windows: {`"Chromium";v="139", "Not=A?Brand";v="24", "Microsoft Edge";v="139"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0"},
		Linux:   {`"Chromium";v="139", "Not=A?Brand";v="24", "Microsoft Edge";v="139"`, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0"},
		IOS:     {`"Chromium";v="139", "Not=A?Brand";v="24", "Microsoft Edge";v="139"`, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0"},
	},
	V140: {
		MacOS:   {`"Chromium";v="140", "Not=A?Brand";v="24", "Microsoft Edge";v="140"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0"},
		Android: {`"Chromium";v="140", "Not=A?Brand";v="24", "Microsoft Edge";v="140"`, "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36 EdgA/140.0.0.0"},
		Windows: {`"Chromium";v="140", "Not=A?Brand";v="24", "Microsoft Edge";v="140"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0"},
		Linux:   {`"Chromium";v="140", "Not=A?Brand";v="24", "Microsoft Edge";v="140"`, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0"},
		IOS:     {`"Chromium";v="140", "Not=A?Brand";v="24", "Microsoft Edge";v="140"`, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0"},
	},
	V141: {
		MacOS:   {`"Chromium";v="141", "Not=A?Brand";v="24", "Microsoft Edge";v="141"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"},
		Android: {`"Chromium";v="141", "Not=A?Brand";v="24", "Microsoft Edge";v="141"`, "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36 EdgA/141.0.0.0"},
		Windows: {`"Chromium";v="141", "Not=A?Brand";v="24", "Microsoft Edge";v="141"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"},
		Linux:   {`"Chromium";v="141", "Not=A?Brand";v="24", "Microsoft Edge";v="141"`, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"},
		IOS:     {`"Chromium";v="141", "Not=A?Brand";v="24", "Microsoft Edge";v="141"`, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"},
	},
	V142: {
		MacOS:   {`"Chromium";v="142", "Microsoft Edge";v="142", "Not_A Brand";v="99"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"},
		Android: {`"Chromium";v="142", "Microsoft Edge";v="142", "Not_A Brand";v="99"`, "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36 EdgA/142.0.0.0"},
		Windows: {`"Chromium";v="142", "Microsoft Edge";v="142", "Not_A Brand";v="99"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"},
		Linux:   {`"Chromium";v="142", "Microsoft Edge";v="142", "Not_A Brand";v="99"`, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"},
		IOS:     {`"Chromium";v="142", "Microsoft Edge";v="142", "Not_A Brand";v="99"`, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"},
	},
	V143: {
		MacOS:   {`"Chromium";v="143", "Microsoft Edge";v="143", "Not_A Brand";v="99"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"},
		Android: {`"Chromium";v="143", "Microsoft Edge";v="143", "Not_A Brand";v="99"`, "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Mobile Safari/537.36 EdgA/143.0.0.0"},
		Windows: {`"Chromium";v="143", "Microsoft Edge";v="143", "Not_A Brand";v="99"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"},
		Linux:   {`"Chromium";v="143", "Microsoft Edge";v="143", "Not_A Brand";v="99"`, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"},
		IOS:     {`"Chromium";v="143", "Microsoft Edge";v="143", "Not_A Brand";v="99"`, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"},
	},
	V144: {
		MacOS:   {`"Not(A:Brand";v="8", "Chromium";v="144", "Microsoft Edge";v="144"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0"},
		Android: {`"Not(A:Brand";v="8", "Chromium";v="144", "Microsoft Edge";v="144"`, "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36 EdgA/144.0.0.0"},
		Windows: {`"Not(A:Brand";v="8", "Chromium";v="144", "Microsoft Edge";v="144"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0"},
		Linux:   {`"Not(A:Brand";v="8", "Chromium";v="144", "Microsoft Edge";v="144"`, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0"},
		IOS:     {`"Not(A:Brand";v="8", "Chromium";v="144", "Microsoft Edge";v="144"`, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0"},
	},
	V145: {
		MacOS:   {`"Chromium";v="145", "Not;A=Brand";v="24", "Microsoft Edge";v="145"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0"},
		Android: {`"Chromium";v="145", "Not;A=Brand";v="24", "Microsoft Edge";v="145"`, "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36 EdgA/145.0.0.0"},
		Windows: {`"Chromium";v="145", "Not;A=Brand";v="24", "Microsoft Edge";v="145"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0"},
		Linux:   {`"Chromium";v="145", "Not;A=Brand";v="24", "Microsoft Edge";v="145"`, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0"},
		IOS:     {`"Chromium";v="145", "Not;A=Brand";v="24", "Microsoft Edge";v="145"`, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0"},
	},
	V146: {
		MacOS:   {`"Chromium";v="146", "Not(A:Brand";v="24", "Microsoft Edge";v="146"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.3856.109"},
		Android: {`"Chromium";v="146", "Not(A:Brand";v="24", "Microsoft Edge";v="146"`, "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.178 Mobile Safari/537.36 EdgA/146.0.3856.97"},
		Windows: {`"Chromium";v="146", "Not(A:Brand";v="24", "Microsoft Edge";v="146"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.3856.109"},
		Linux:   {`"Chromium";v="146", "Not(A:Brand";v="24", "Microsoft Edge";v="146"`, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.3856.109"},
		IOS:     {`"Chromium";v="146", "Not(A:Brand";v="24", "Microsoft Edge";v="146"`, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 EdgiOS/146.0.3856.102 Mobile/15E148 Safari/605.1.15"},
	},
	V147: {
		MacOS:   {`"Microsoft Edge";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.3912.51"},
		Android: {`"Microsoft Edge";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`, "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.55 Mobile Safari/537.36 EdgA/147.0.3912.51"},
		Windows: {`"Microsoft Edge";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.3912.51"},
		Linux:   {`"Microsoft Edge";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.3912.51"},
		IOS:     {`"Microsoft Edge";v="147", "Not.A/Brand";v="8", "Chromium";v="147"`, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 EdgiOS/147.0.3912.51 Mobile/15E148 Safari/605.1.15"},
	},
	V148: {
		MacOS:   {`"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"`, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0"},
		Android: {`"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"`, "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Mobile Safari/537.36 EdgA/148.0.0.0"},
		Windows: {`"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"`, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0"},
		Linux:   {`"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"`, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0"},
		IOS:     {`"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"`, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 EdgiOS/148.0.0.0 Mobile/15E148 Safari/605.1.15"},
	},
}

// Profile returns a tls_client.ClientProfile that mirrors
// v132::build_emulation. Identical for all Version values; the
// (v, p) combination only affects the User-Agent / sec-ch-ua headers.
func Profile() profiles.ClientProfile {
	return profiles.NewClientProfile(
		utls.ClientHelloID{
			Client:               "Edge_v132_Custom",
			RandomExtensionOrder: false,
			Version:              "132",
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
		15728640,
		nil, nil,
		0, false,
		nil, nil, 0, nil, false,
	)
}

// specFactory reproduces the v132 (Chrome-148) ClientHello spec.
// Mirrors wreq-util's tls_options!(7, CURVES_3). Layout follows
// tls-client Chrome_146/Chrome_148 with GREASE at the END of the
// supported_curves list (Chrome-148 Edge fingerprint: original
// edge148/edge148.go's curves order X25519MLKEM, X25519, P-256, P-384
// + GREASE — verified against wreq's v132 Chrome 148 stack).
func specFactory() (utls.ClientHelloSpec, error) {
	return utls.ClientHelloSpec{
		// CIPHER_LIST from chrome/tls.rs (16 ciphers, no SHA1, no 3DES).
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
			// CURVES_3 — GREASE goes at INDEX 0 in Edge's
			// fingerprint (matches the wire order of v132
			// Chrome-148 with real GREASE; wreq's permute
			// always emits GREASE first in supported_curves).
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
				utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
				utls.PSSWithSHA512, utls.PKCS1WithSHA512,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
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

// HeadersFor returns the header set for the given (v, p) combination,
// or an error if wreq-util does not define that combination.
func HeadersFor(v Version, p Platform) (fhttp.Header, error) {
	platforms, ok := allVersions[v]
	if !ok {
		return nil, fmt.Errorf("edge: unsupported version %d", v)
	}
	u, ok := platforms[p]
	if !ok {
		return nil, fmt.Errorf("edge: unsupported platform %d for version %d", p, v)
	}
	// All Edge UAs share the same accept / accept-encoding /
	// accept-language / sec-fetch-* / priority set from
	// header_initializer_with_zstd_priority.
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

// platformSecChUaPlatform returns the sec-ch-ua-platform value for a
// given platform.
func platformSecChUaPlatform(p Platform) []string {
	switch p {
	case Windows:
		return []string{`"Windows"`}
	case MacOS:
		return []string{`"macOS"`}
	case Linux:
		return []string{`"Linux"`}
	case Android:
		return []string{`"Android"`}
	case IOS:
		return []string{`"iOS"`}
	}
	return nil
}

// NewClient returns a tls_client.HttpClient configured for the given
// Edge version (134..148) and platform. permute_extensions is ON
// (matches wreq v132 TLS config).
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
