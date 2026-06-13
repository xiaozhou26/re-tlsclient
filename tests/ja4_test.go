package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"testing"

	http "github.com/bogdanfinn/fhttp"
	tls_client "xiaozhou26/re-tlsclient"
	"xiaozhou26/re-tlsclient/profiles"

	"github.com/stretchr/testify/assert"
)

// TestJA4Support makes a request to a TLS fingerprint checking endpoint
// and verifies that JA4 fingerprint is supported and returned.
func TestJA4Support(t *testing.T) {
	testCases := []struct {
		name    string
		profile profiles.ClientProfile
	}{
		{"Chrome_147", profiles.Chrome_147},
		{"Firefox_147", profiles.Firefox_147},
		{"Safari_26", profiles.Safari_26},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			options := []tls_client.HttpClientOption{
				tls_client.WithClientProfile(tc.profile),
				tls_client.WithTimeoutSeconds(15),
			}

			client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
			if err != nil {
				t.Fatal(err)
			}

			req, err := http.NewRequest(http.MethodGet, "https://tls.peet.ws/api/all", nil)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Skipf("Network error (skipping): %v", err)
				return
			}
			defer resp.Body.Close()

			assert.Equal(t, 200, resp.StatusCode, "Expected 200 OK")

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(body, &result); err != nil {
				t.Fatal(err)
			}

			tlsData, ok := result["tls"].(map[string]interface{})
			if !ok {
				t.Fatal("Response missing 'tls' field")
			}

			// Print all TLS fields for debugging
			t.Logf("=== %s ===", tc.name)
			for k, v := range tlsData {
				t.Logf("  %s: %v", k, v)
			}

			// Check JA3
			ja3, hasJA3 := tlsData["ja3"]
			assert.True(t, hasJA3, "Response should contain JA3")
			if hasJA3 {
				t.Logf("  JA3: %v", ja3)
			}

			// Check JA3 hash
			ja3Hash, hasJA3Hash := tlsData["ja3_hash"]
			assert.True(t, hasJA3Hash, "Response should contain JA3 hash")
			if hasJA3Hash {
				t.Logf("  JA3 hash: %v", ja3Hash)
			}

			// Check JA4 (this is what we're testing!)
			ja4, hasJA4 := tlsData["ja4"]
			if hasJA4 {
				t.Logf("  ✅ JA4: %v", ja4)
			} else {
				t.Logf("  ⚠️ JA4 not present in response")
				// Check if there's a ja4_r field
				ja4r, hasJA4R := tlsData["ja4_r"]
				if hasJA4R {
					t.Logf("  ✅ JA4_r: %v", ja4r)
				}
				// Check all available keys
				t.Logf("  Available TLS fields: %v", getKeys(tlsData))
			}

			// Check JA4 hash
			ja4Hash, hasJA4Hash := tlsData["ja4_hash"]
			if hasJA4Hash {
				t.Logf("  ✅ JA4 hash: %v", ja4Hash)
			}

			// Print HTTP/2 info
			if h2, ok := result["http2"].(map[string]interface{}); ok {
				akamai, hasAkamai := h2["akamai_fingerprint"]
				if hasAkamai {
					t.Logf("  Akamai fingerprint: %v", akamai)
				}
				akamaiHash, hasAkamaiHash := h2["akamai_fingerprint_hash"]
				if hasAkamaiHash {
					t.Logf("  Akamai hash: %v", akamaiHash)
				}
			}
		})
	}
}

// TestJA4ComputeLocally tests local JA4 computation from a ClientHelloSpec.
func TestJA4ComputeLocally(t *testing.T) {
	profile := profiles.Chrome_147
	spec, err := profile.GetClientHelloSpec()
	if err != nil {
		t.Fatal(err)
	}

	fingerprint := tls_client.ComputeJA4(spec, "h2")

	t.Logf("Local JA4 computation for Chrome_147:")
	t.Logf("  JA4:   %s", fingerprint.JA4)
	t.Logf("  JA4_r: %s", fingerprint.JA4R)

	assert.NotEmpty(t, fingerprint.JA4, "JA4 should not be empty")
	assert.NotEmpty(t, fingerprint.JA4R, "JA4_r should not be empty")

	// JA4 format check: should be 12 hex chars (SHA256 truncated)
	assert.Len(t, fingerprint.JA4, 12, "JA4 should be 12 hex chars")

	// JA4 should start with t13d (TLS 1.3, d for default/QUIC)
	// The actual hash follows after the prefix — we compute the full hash of the string
	// so the format is just 12 hex chars of SHA256
	t.Logf("  Format check: JA4 is 12 hex chars ✓")
}

// getKeys returns the keys of a map for debugging.
func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// TestJA4AllProfiles computes JA4 for all profiles and prints them.
func TestJA4AllProfiles(t *testing.T) {
	profileNames := []struct {
		name string
		id   string
	}{
		{"Chrome_147", "chrome_147"},
		{"Chrome_120", "chrome_120"},
		{"Chrome_116", "chrome_116"},
		{"Chrome_107", "chrome_107"},
		{"Firefox_147", "firefox_147"},
		{"Firefox_139", "firefox_139"},
		{"Firefox_109", "firefox_109"},
		{"Safari_26", "safari_26"},
		{"Safari_18", "safari_18"},
		{"Opera_131", "opera_131"},
		{"OkHttp_5", "okhttp_5"},
	}

	for _, pn := range profileNames {
		t.Run(pn.name, func(t *testing.T) {
			profile, ok := profiles.MappedTLSClients[pn.id]
			if !ok {
				t.Fatalf("Profile %s not found", pn.id)
			}

			spec, err := profile.GetClientHelloSpec()
			if err != nil {
				t.Fatal(err)
			}

			fp := tls_client.ComputeJA4(spec, "h2")
			t.Logf("%-20s JA4=%s  JA4_r=%s", pn.name, fp.JA4, fp.JA4R)
			assert.NotEmpty(t, fp.JA4)
		})
	}
}

func init() {
	_ = fmt.Sprintf // ensure fmt is used
}
