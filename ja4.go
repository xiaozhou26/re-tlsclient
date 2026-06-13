package tls_client

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	tls "github.com/bogdanfinn/utls"
)

// JA4Fingerprint represents the JA4 and JA4_r fingerprints of a TLS ClientHello.
type JA4Fingerprint struct {
	// JA4 is the standard JA4 hash (12-char truncated SHA256).
	JA4 string
	// JA4_r is the JA4 with random extension ordering (sorted extensions, no GREASE).
	JA4R string
}

// ComputeJA4 computes the JA4 fingerprint from a ClientHelloSpec.
//
// JA4 format:
//
//	Protocol_QUIC_Ciphers_Extensions_SignatureAlgorithms
//
// Protocol: t13 (TLS 1.3), t12 (TLS 1.2), etc.
// QUIC: d (QUIC), q (no QUIC expected), 0 (no QUIC detected)
// Ciphers: first 2 hex chars of sorted cipher suite IDs (SHA256 truncated)
// Extensions: first 2 hex chars of sorted extension IDs (SHA256 truncated)
// SignatureAlgorithms: sorted ALPN selected sig alg IDs (SHA256 truncated)
//
// JA4_r: same as JA4 but extensions are sorted and GREASE extensions are filtered out.
//
// Reference: https://github.com/FoxIO-LLC/ja4
func ComputeJA4(spec tls.ClientHelloSpec, alpn string) JA4Fingerprint {
	// Determine protocol
	hasTLS13 := false
	hasTLS12 := false

	for _, ext := range spec.Extensions {
		if svExt, ok := ext.(*tls.SupportedVersionsExtension); ok {
			for _, v := range svExt.Versions {
				if v == tls.VersionTLS13 || v == tls.GREASE_PLACEHOLDER {
					hasTLS13 = true
				}
				if v == tls.VersionTLS12 {
					hasTLS12 = true
				}
			}
		}
	}

	protocol := "00"
	if hasTLS13 {
		protocol = "13"
	} else if hasTLS12 {
		protocol = "12"
	}

	// QUIC detection (h3 in ALPN)
	_ = alpn // Reserved for future QUIC detection

	// Collect cipher suites (sorted)
	cipherIDs := make([]int, 0, len(spec.CipherSuites))
	for _, cs := range spec.CipherSuites {
		if cs == tls.GREASE_PLACEHOLDER {
			continue
		}
		cipherIDs = append(cipherIDs, int(cs))
	}
	sort.Ints(cipherIDs)

	// Collect extensions for JA4 (sorted by ID, filter GREASE)
	extIDs := make([]int, 0)
	extIDsRaw := make([]int, 0)
	for _, ext := range spec.Extensions {
		var extID uint16
		switch ext.(type) {
		case *tls.UtlsGREASEExtension:
			continue // Skip GREASE
		case *tls.SNIExtension:
			extID = tls.ExtensionServerName
		case *tls.SupportedCurvesExtension:
			extID = tls.ExtensionSupportedCurves
		case *tls.SupportedPointsExtension:
			extID = tls.ExtensionSupportedPoints
		case *tls.SignatureAlgorithmsExtension:
			extID = tls.ExtensionSignatureAlgorithms
		case *tls.ALPNExtension:
			extID = tls.ExtensionALPN
		case *tls.SupportedVersionsExtension:
			extID = tls.ExtensionSupportedVersions
		case *tls.KeyShareExtension:
			extID = tls.ExtensionKeyShare
		case *tls.PSKKeyExchangeModesExtension:
			extID = tls.ExtensionPSKModes
		case *tls.SessionTicketExtension:
			extID = tls.ExtensionSessionTicket
		case *tls.RenegotiationInfoExtension:
			extID = tls.ExtensionRenegotiationInfo
		case *tls.SCTExtension:
			extID = tls.ExtensionSCT
		case *tls.ExtendedMasterSecretExtension:
			extID = tls.ExtensionExtendedMasterSecret
		case *tls.StatusRequestExtension:
			extID = tls.ExtensionStatusRequest
		case *tls.ApplicationSettingsExtensionNew:
			extID = tls.ExtensionALPS
		case *tls.ApplicationSettingsExtension:
			extID = tls.ExtensionALPSOld
		case *tls.UtlsCompressCertExtension:
			extID = tls.ExtensionCompressCertificate
		case *tls.UtlsPaddingExtension:
			extID = tls.ExtensionPadding
		case *tls.UtlsPreSharedKeyExtension:
			extID = tls.ExtensionPreSharedKey
		default:
			// Try to get extension ID from GenericExtension
			if genExt, ok := ext.(*tls.GenericExtension); ok {
				extID = genExt.Id
			} else {
				continue
			}
		}

		extIDs = append(extIDs, int(extID))
		extIDsRaw = append(extIDsRaw, int(extID))
	}
	sort.Ints(extIDs)

	// Collect signature algorithms
	sigAlgIDs := make([]int, 0)
	for _, ext := range spec.Extensions {
		if sigExt, ok := ext.(*tls.SignatureAlgorithmsExtension); ok {
			for _, sa := range sigExt.SupportedSignatureAlgorithms {
				sigAlgIDs = append(sigAlgIDs, int(sa))
			}
		}
	}
	sort.Ints(sigAlgIDs)

	// Compute JA4 hash
	cipherHash := hashSortedIDs(cipherIDs)
	extHash := hashSortedIDs(extIDsRaw)      // JA4 uses raw order
	extHashSorted := hashSortedIDs(extIDs)    // JA4_r uses sorted order
	sigAlgHash := hashSortedIDs(sigAlgIDs)

	ja4Str := fmt.Sprintf("t%sd%s%s%s", protocol, cipherHash, extHash, sigAlgHash)
	ja4RStr := fmt.Sprintf("t%sd%s%s%s", protocol, cipherHash, extHashSorted, sigAlgHash)

	ja4 := sha256Hash12(ja4Str)
	ja4R := sha256Hash12(ja4RStr)

	return JA4Fingerprint{
		JA4:  ja4,
		JA4R: ja4R,
	}
}

// hashSortedIDs computes a 4-char hex string from a sorted list of IDs.
func hashSortedIDs(ids []int) string {
	if len(ids) == 0 {
		return "0000"
	}

	// Concatenate hexadecimal representations
	var sb strings.Builder
	for _, id := range ids {
		sb.WriteString(fmt.Sprintf("%04x", id)) // Use 4-digit hex for each ID
	}

	hash := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(hash[:4])[:4] // Take first 4 hex chars (2 bytes)
}

// sha256Hash12 computes SHA256 and returns the first 12 hex characters.
func sha256Hash12(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])[:12]
}

// ComputeJA4FromJA3 computes JA4 from a JA3 string.
func ComputeJA4FromJA3(ja3String string, signatureAlgorithms []tls.SignatureScheme) JA4Fingerprint {
	parts := strings.Split(ja3String, ",")
	if len(parts) < 5 {
		return JA4Fingerprint{}
	}

	// Protocol
	protocol := "00"
	tlsVersion, _ := strconv.Atoi(parts[0])
	if tlsVersion == 771 {
		protocol = "12"
	} else if tlsVersion == 772 {
		protocol = "13"
	}

	// Ciphers
	cipherStrings := strings.Split(parts[1], "-")
	cipherIDs := make([]int, 0)
	for _, c := range cipherStrings {
		id, err := strconv.Atoi(c)
		if err != nil {
			continue
		}
		cipherIDs = append(cipherIDs, id)
	}
	sort.Ints(cipherIDs)

	// Extensions
	extStrings := strings.Split(parts[2], "-")
	extIDsRaw := make([]int, 0)
	extIDsSorted := make([]int, 0)
	for _, e := range extStrings {
		id, err := strconv.Atoi(e)
		if err != nil {
			continue
		}
		// Skip GREASE extensions (0x0A0A, etc.)
		if id == int(tls.GREASE_PLACEHOLDER) {
			continue
		}
		extIDsRaw = append(extIDsRaw, id)
		extIDsSorted = append(extIDsSorted, id)
	}
	sort.Ints(extIDsSorted)

	// Signature algorithms
	sigAlgIDs := make([]int, 0)
	for _, sa := range signatureAlgorithms {
		sigAlgIDs = append(sigAlgIDs, int(sa))
	}
	sort.Ints(sigAlgIDs)

	cipherHash := hashSortedIDs(cipherIDs)
	extHash := hashSortedIDs(extIDsRaw)
	extHashSorted := hashSortedIDs(extIDsSorted)
	sigAlgHash := hashSortedIDs(sigAlgIDs)

	ja4Str := fmt.Sprintf("t%sd%s%s%s", protocol, cipherHash, extHash, sigAlgHash)
	ja4RStr := fmt.Sprintf("t%sd%s%s%s", protocol, cipherHash, extHashSorted, sigAlgHash)

	return JA4Fingerprint{
		JA4:  sha256Hash12(ja4Str),
		JA4R: sha256Hash12(ja4RStr),
	}
}