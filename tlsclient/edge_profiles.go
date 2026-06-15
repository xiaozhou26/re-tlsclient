package tlsclient

import (
	"github.com/xiaozhou26/re-tlsclient/profiles"
)

// Edge 101-148 的指纹定义。
// Edge 基于 Chromium, 复用 Chrome 的 TLS/HTTP2 配置, 仅 UA 差异。

func Edge101() profiles.ClientProfile { return buildChromeProfile(chrome100JA3, "Edge", "101", chromeVersions, []string{"X25519"}) }
func Edge122() profiles.ClientProfile { return buildChromeProfile(chrome117JA3, "Edge", "122", chromeVersions, []string{"X25519"}) }
func Edge127() profiles.ClientProfile { return buildChromeProfile(chrome124JA3, "Edge", "127", chromeVersions, chromeKeyShareKyberDraft) }
func Edge131() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "131", chromeVersions, chromeKeyShareMLKEM) }

// Edge134-148 复用 Chrome 132 配置 (MLKEM)
func Edge134() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "134", chromeVersions, chromeKeyShareMLKEM) }
func Edge135() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "135", chromeVersions, chromeKeyShareMLKEM) }
func Edge136() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "136", chromeVersions, chromeKeyShareMLKEM) }
func Edge137() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "137", chromeVersions, chromeKeyShareMLKEM) }
func Edge138() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "138", chromeVersions, chromeKeyShareMLKEM) }
func Edge139() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "139", chromeVersions, chromeKeyShareMLKEM) }
func Edge140() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "140", chromeVersions, chromeKeyShareMLKEM) }
func Edge141() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "141", chromeVersions, chromeKeyShareMLKEM) }
func Edge142() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "142", chromeVersions, chromeKeyShareMLKEM) }
func Edge143() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "143", chromeVersions, chromeKeyShareMLKEM) }
func Edge144() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "144", chromeVersions, chromeKeyShareMLKEM) }
func Edge145() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "145", chromeVersions, chromeKeyShareMLKEM) }
func Edge146() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "146", chromeVersions, chromeKeyShareMLKEM) }
func Edge147() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "147", chromeVersions, chromeKeyShareMLKEM) }
func Edge148() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Edge", "148", chromeVersions, chromeKeyShareMLKEM) }
