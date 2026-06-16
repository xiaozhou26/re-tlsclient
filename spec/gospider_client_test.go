package spec

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestBuildClientProfile(t *testing.T) {
	spec, err := ParseGoSpiderSpec(TestGoSpiderSpec)
	if err != nil {
		t.Fatalf("ParseGoSpiderSpec 失败: %v", err)
	}

	parts := strings.Split(TestGoSpiderSpec, "@")
	if len(parts) != 3 {
		t.Fatal("分割 goSpiderSpec 失败")
	}

	tlsRaw, err := hex.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("TLS hex 解码失败: %v", err)
	}

	profile, err := buildClientProfile(tlsRaw, spec.H2)
	if err != nil {
		t.Fatalf("buildClientProfile 失败: %v", err)
	}

	chSpec, err := profile.GetClientHelloSpec()
	if err != nil {
		t.Fatalf("GetClientHelloSpec 失败: %v", err)
	}

	if len(chSpec.CipherSuites) == 0 {
		t.Fatal("CipherSuites 不应为空")
	}
	t.Logf("CipherSuites 数量: %d", len(chSpec.CipherSuites))

	if len(chSpec.Extensions) == 0 {
		t.Fatal("Extensions 不应为空")
	}
	t.Logf("Extensions 数量: %d", len(chSpec.Extensions))

	settings := profile.GetSettings()
	if settings == nil {
		t.Fatal("Settings 不应为 nil")
	}
	t.Logf("Settings: %v", settings)

	settingsOrder := profile.GetSettingsOrder()
	if len(settingsOrder) == 0 {
		t.Fatal("SettingsOrder 不应为空")
	}
	t.Logf("SettingsOrder: %v", settingsOrder)

	connFlow := profile.GetConnectionFlow()
	if connFlow == 0 {
		t.Fatal("ConnectionFlow 不应为 0")
	}
	t.Logf("ConnectionFlow: %d", connFlow)

	pseudoHeaders := profile.GetPseudoHeaderOrder()
	if len(pseudoHeaders) == 0 {
		t.Fatal("PseudoHeaderOrder 不应为空")
	}
	t.Logf("PseudoHeaderOrder: %v", pseudoHeaders)

	headerPrio := profile.GetHeaderPriority()
	t.Logf("HeaderPriority: %v", headerPrio)
}

func TestBuildProfileInvalid(t *testing.T) {
	// 验证 BuildProfile 对非法 spec 返回错误
	_, _, _, _, err := BuildProfile("not-a-spec")
	if err == nil {
		t.Fatal("期望 BuildProfile(invalid) 报错但没报")
	}
	t.Logf("正确返回错误: %v", err)
}
