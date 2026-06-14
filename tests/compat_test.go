package tests

import (
	"testing"

	"github.com/xiaozhou26/re-tlsclient/profiles"
	"github.com/stretchr/testify/assert"
)

// TestCompatMappedTLSClients verifies that all upstream (bogdanfinn/tls-client)
// MappedTLSClients keys are present and resolve to valid profiles.
// This ensures users can migrate by only changing import paths.
func TestCompatMappedTLSClients(t *testing.T) {
	// All keys that existed in bogdanfinn/tls-client's MappedTLSClients
	upstreamKeys := []string{
		// Chrome
		"chrome_103", "chrome_104", "chrome_105", "chrome_106", "chrome_107",
		"chrome_108", "chrome_109", "chrome_110", "chrome_111", "chrome_112",
		"chrome_116_PSK", "chrome_116_PSK_PQ",
		"chrome_117", "chrome_120", "chrome_124",
		"chrome_130_PSK", "chrome_131", "chrome_131_PSK",
		"chrome_133", "chrome_133_PSK",
		"chrome_144", "chrome_144_PSK",
		"chrome_146", "chrome_146_PSK",

		// Brave
		"brave_146", "brave_146_PSK",

		// Safari
		"safari_15_6_1", "safari_16_0", "safari_ipad_15_6",
		"safari_ios_15_5", "safari_ios_15_6", "safari_ios_16_0",
		"safari_ios_17_0", "safari_ios_18_0", "safari_ios_18_5", "safari_ios_26_0",

		// Firefox
		"firefox_102", "firefox_104", "firefox_105", "firefox_106",
		"firefox_108", "firefox_110", "firefox_117", "firefox_120",
		"firefox_123", "firefox_132", "firefox_133", "firefox_135",
		"firefox_146_PSK", "firefox_147", "firefox_147_PSK", "firefox_148",

		// Opera
		"opera_89", "opera_90", "opera_91",

		// Custom/Mobile
		"cloudscraper",
		"zalando_android_mobile", "zalando_ios_mobile",
		"nike_ios_mobile", "nike_android_mobile",
		"mms_ios", "mms_ios_1", "mms_ios_2", "mms_ios_3",
		"mesh_ios", "mesh_ios_1", "mesh_ios_2",
		"mesh_android", "mesh_android_1", "mesh_android_2",
		"confirmed_ios", "confirmed_android",
		"okhttp4_android_7", "okhttp4_android_8", "okhttp4_android_9",
		"okhttp4_android_10", "okhttp4_android_11", "okhttp4_android_12", "okhttp4_android_13",
	}

	for _, key := range upstreamKeys {
		t.Run(key, func(t *testing.T) {
			profile, ok := profiles.MappedTLSClients[key]
			assert.True(t, ok, "Missing MappedTLSClients key: %s", key)
			if ok {
				// Verify the profile has valid H2 settings
				settings := profile.GetSettings()
				assert.NotEmpty(t, settings, "Profile %s has empty H2 settings", key)

				// Verify the profile has pseudo header order
				pseudoOrder := profile.GetPseudoHeaderOrder()
				assert.NotEmpty(t, pseudoOrder, "Profile %s has empty pseudo header order", key)

				// Verify the profile has a valid client hello ID
				helloId := profile.GetClientHelloId()
				assert.NotEmpty(t, helloId.Client, "Profile %s has empty ClientHelloID.Client", key)
			}
		})
	}
}

// TestCompatProfileVariables verifies that all upstream profile variables exist
// as exported Go variables in the profiles package.
func TestCompatProfileVariables(t *testing.T) {
	// Verify key profile variables that users commonly reference directly
	profileVars := map[string]profiles.ClientProfile{
		// Chrome PSK variants
		"Chrome_116_PSK":    profiles.Chrome_116_PSK,
		"Chrome_116_PSK_PQ": profiles.Chrome_116_PSK_PQ,
		"Chrome_130_PSK":    profiles.Chrome_130_PSK,
		"Chrome_131_PSK":    profiles.Chrome_131_PSK,
		"Chrome_133_PSK":    profiles.Chrome_133_PSK,
		"Chrome_144_PSK":    profiles.Chrome_144_PSK,
		"Chrome_146_PSK":    profiles.Chrome_146_PSK,

		// Chrome legacy
		"Chrome_103": profiles.Chrome_103,
		"Chrome_111": profiles.Chrome_111,
		"Chrome_112": profiles.Chrome_112,

		// Brave
		"Brave_146":     profiles.Brave_146,
		"Brave_146_PSK": profiles.Brave_146_PSK,

		// Safari legacy
		"Safari_15_6_1":   profiles.Safari_15_6_1,
		"Safari_16_0":     profiles.Safari_16_0,
		"Safari_Ipad_15_6": profiles.Safari_Ipad_15_6,
		"Safari_IOS_17_0": profiles.Safari_IOS_17_0,
		"Safari_IOS_18_0": profiles.Safari_IOS_18_0,
		"Safari_IOS_18_5": profiles.Safari_IOS_18_5,
		"Safari_IOS_26_0": profiles.Safari_IOS_26_0,

		// Firefox legacy
		"Firefox_102":     profiles.Firefox_102,
		"Firefox_110":     profiles.Firefox_110,
		"Firefox_146_PSK": profiles.Firefox_146_PSK,
		"Firefox_147_PSK": profiles.Firefox_147_PSK,

		// Opera legacy
		"Opera_89": profiles.Opera_89,
		"Opera_90": profiles.Opera_90,
		"Opera_91": profiles.Opera_91,

		// Custom/Mobile
		"CloudflareCustom":   profiles.CloudflareCustom,
		"ZalandoAndroidMobile": profiles.ZalandoAndroidMobile,
		"NikeIosMobile":      profiles.NikeIosMobile,
		"MMSIos":             profiles.MMSIos,
		"MeshIos":            profiles.MeshIos,
		"ConfirmedIos":       profiles.ConfirmedIos,
	}

	for name, profile := range profileVars {
		t.Run(name, func(t *testing.T) {
			// Each profile should have valid settings
			settings := profile.GetSettings()
			assert.NotEmpty(t, settings, "Profile %s has empty settings", name)

			pseudoOrder := profile.GetPseudoHeaderOrder()
			assert.NotEmpty(t, pseudoOrder, "Profile %s has empty pseudo header order", name)
		})
	}
}

// TestCompatMapCount verifies the MappedTLSClients map has at least
// as many entries as the upstream library.
func TestCompatMapCount(t *testing.T) {
	// Upstream had 90 entries; we should have at least that many
	assert.GreaterOrEqual(t, len(profiles.MappedTLSClients), 90,
		"MappedTLSClients should have at least 90 entries (upstream had 90)")
}
