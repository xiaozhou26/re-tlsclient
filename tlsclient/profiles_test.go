package tlsclient

import (
	"testing"

	"github.com/xiaozhou26/re-tlsclient/profiles"
)

// TestAllProfilesConstruction 验证所有 profile 构造函数都能被调用且不返回空 ClientProfile。
func TestAllProfilesConstruction(t *testing.T) {
	// Chrome: 42 个
	chromeFns := []func() profiles.ClientProfile{
		Chrome100, Chrome101, Chrome104, Chrome105,
		Chrome106, Chrome107, Chrome108, Chrome109, Chrome110, Chrome114, Chrome115,
		Chrome116,
		Chrome117, Chrome118, Chrome119, Chrome120, Chrome123,
		Chrome124, Chrome125, Chrome126, Chrome127, Chrome128, Chrome129, Chrome130,
		Chrome131, Chrome132, Chrome133, Chrome134, Chrome135,
		Chrome136, Chrome137, Chrome138, Chrome139, Chrome140,
		Chrome141, Chrome142, Chrome143, Chrome144, Chrome145,
		Chrome146, Chrome147, Chrome148,
	}
	if len(chromeFns) != 42 {
		t.Errorf("expected 42 Chrome profiles, got %d", len(chromeFns))
	}
	for i, fn := range chromeFns {
		p := fn()
		if p.GetClientHelloId().Version == "" {
			t.Errorf("Chrome profile #%d has empty version", i)
		}
	}

	// Edge: 19 个
	edgeFns := []func() profiles.ClientProfile{
		Edge101, Edge122, Edge127, Edge131,
		Edge134, Edge135, Edge136, Edge137, Edge138, Edge139, Edge140,
		Edge141, Edge142, Edge143, Edge144, Edge145, Edge146, Edge147, Edge148,
	}
	if len(edgeFns) != 19 {
		t.Errorf("expected 19 Edge profiles, got %d", len(edgeFns))
	}
	for i, fn := range edgeFns {
		p := fn()
		if p.GetClientHelloId().Client != "Edge" {
			t.Errorf("Edge profile #%d has client %q, want Edge", i, p.GetClientHelloId().Client)
		}
	}

	// Firefox: 20 个
	firefoxFns := []func() profiles.ClientProfile{
		Firefox109, Firefox117, Firefox128, Firefox133, Firefox135,
		FirefoxPrivate135, FirefoxAndroid135,
		Firefox136, FirefoxPrivate136, Firefox139, Firefox142, Firefox143,
		Firefox144, Firefox145, Firefox146, Firefox147, Firefox148, Firefox149, Firefox150, Firefox151,
	}
	if len(firefoxFns) != 20 {
		t.Errorf("expected 20 Firefox profiles, got %d", len(firefoxFns))
	}
	for i, fn := range firefoxFns {
		p := fn()
		if p.GetClientHelloId().Client != "Firefox" {
			t.Errorf("Firefox profile #%d has client %q, want Firefox", i, p.GetClientHelloId().Client)
		}
	}

	// Safari: 29 个
	safariFns := []func() profiles.ClientProfile{
		Safari15_3, Safari15_5, Safari15_6_1, Safari16, Safari16_5,
		SafariIOS16_5,
		Safari17_0, Safari17_2_1, Safari17_4_1, Safari17_5, Safari17_6,
		SafariIOS17_2, SafariIOS17_4_1,
		Safari18, SafariIPad18, SafariIOS18_1_1,
		Safari18_2, Safari18_3, Safari18_3_1,
		Safari18_5, Safari26, Safari26_1, Safari26_2, Safari26_3, Safari26_4,
		SafariIPad26, SafariIPad26_2, SafariIOS26, SafariIOS26_2,
	}
	if len(safariFns) != 29 {
		t.Errorf("expected 29 Safari profiles, got %d", len(safariFns))
	}

	// Opera: 16 个
	operaFns := []func() profiles.ClientProfile{
		Opera116, Opera117, Opera118, Opera119, Opera120, Opera121, Opera122, Opera123,
		Opera124, Opera125, Opera126, Opera127, Opera128, Opera129, Opera130, Opera131,
	}
	if len(operaFns) != 16 {
		t.Errorf("expected 16 Opera profiles, got %d", len(operaFns))
	}

	// OkHttp: 8 个
	okhttpFns := []func() profiles.ClientProfile{
		OkHttp3_9, OkHttp3_11, OkHttp3_13, OkHttp3_14,
		OkHttp4_9, OkHttp4_10, OkHttp4_12, OkHttp5,
	}
	if len(okhttpFns) != 8 {
		t.Errorf("expected 8 OkHttp profiles, got %d", len(okhttpFns))
	}
}

// TestProfileSpecFactory 验证 SpecFactory 能成功生成 ClientHelloSpec。
func TestProfileSpecFactory(t *testing.T) {
	tests := []struct {
		name string
		p    profiles.ClientProfile
	}{
		{"Chrome148", Chrome148()},
		{"Edge148", Edge148()},
		{"Firefox135", Firefox135()},
		{"Safari18_5", Safari18_5()},
		{"Opera131", Opera131()},
		{"OkHttp4_12", OkHttp4_12()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := tt.p.GetClientHelloSpec()
			if err != nil {
				t.Fatalf("%s: spec factory failed: %v", tt.name, err)
			}
			if len(spec.CipherSuites) == 0 {
				t.Errorf("%s: spec has no cipher suites", tt.name)
			}
		})
	}
}
