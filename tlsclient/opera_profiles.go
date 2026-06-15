package tlsclient

import (
	"github.com/xiaozhou26/re-tlsclient/profiles"
)

// Opera 116-131 的指纹定义。
// Opera 基于 Chromium, 复用 Chrome 的 TLS/HTTP2 配置, 仅 UA 差异。

func Opera116() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "116", chromeVersions, chromeKeyShareMLKEM) }
func Opera117() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "117", chromeVersions, chromeKeyShareMLKEM) }
func Opera118() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "118", chromeVersions, chromeKeyShareMLKEM) }
func Opera119() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "119", chromeVersions, chromeKeyShareMLKEM) }
func Opera120() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "120", chromeVersions, chromeKeyShareMLKEM) }
func Opera121() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "121", chromeVersions, chromeKeyShareMLKEM) }
func Opera122() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "122", chromeVersions, chromeKeyShareMLKEM) }
func Opera123() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "123", chromeVersions, chromeKeyShareMLKEM) }
func Opera124() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "124", chromeVersions, chromeKeyShareMLKEM) }
func Opera125() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "125", chromeVersions, chromeKeyShareMLKEM) }
func Opera126() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "126", chromeVersions, chromeKeyShareMLKEM) }
func Opera127() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "127", chromeVersions, chromeKeyShareMLKEM) }
func Opera128() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "128", chromeVersions, chromeKeyShareMLKEM) }
func Opera129() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "129", chromeVersions, chromeKeyShareMLKEM) }
func Opera130() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "130", chromeVersions, chromeKeyShareMLKEM) }
func Opera131() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Opera", "131", chromeVersions, chromeKeyShareMLKEM) }
