package profile

import (
	"testing"
)

// TestExtraProfiles_Lookup 验证 ExtraProfiles 里的 key 都能查到非空 ClientProfile。
// 同名测试在 tests/migrate_test.go 也有，对外用户路径走那边。
func TestExtraProfiles_Lookup(t *testing.T) {
	want := []string{
		"chrome_148", "chrome_132", "chrome_127",
		"edge_148", "edge_127", "edge_122",
		"firefox_151", "firefox_147", "firefox_142",
		"safari_26.4", "safari_18.3.1", "safari_ios_26",
		"opera_131", "opera_120",
		"okhttp_5", "okhttp_3.9",
	}
	for _, name := range want {
		p, ok := GetExtraProfile(name)
		if !ok {
			t.Errorf("ExtraProfile %q not found", name)
			continue
		}
		spec, err := p.GetClientHelloSpec()
		if err != nil {
			t.Errorf("ExtraProfile %q: ClientHelloSpec error: %v", name, err)
			continue
		}
		if len(spec.CipherSuites) == 0 {
			t.Errorf("ExtraProfile %q: empty cipher suites", name)
		}
		if len(spec.Extensions) == 0 {
			t.Errorf("ExtraProfile %q: empty extensions", name)
		}
	}
}

// TestGetExtraProfile_Missing 验证未注册的名字返回 (zero, false)。
func TestGetExtraProfile_Missing(t *testing.T) {
	_, ok := GetExtraProfile("not-a-real-profile-9999")
	if ok {
		t.Error("expected ok=false for unknown profile name")
	}
}
