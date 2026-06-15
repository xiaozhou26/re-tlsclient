package tlsclient

import (
	"github.com/xiaozhou26/re-tlsclient/profiles"
)

// Chrome 100-148 的指纹定义。
// JA3 字符串 + 共享元数据, 通过 buildChromeProfile 动态构建 ClientProfile。
//
// 数据来源: wreq-util/src/emulate/profile/chrome.rs

// chrome100JA3 Chrome 100-105 共享的 JA3 字符串
const chrome100JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-41,29-23-24,0"

// chrome106JA3 Chrome 106-115 共享的 JA3 (permute 启用)
const chrome106JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-41,29-23-24,0"

// chrome116JA3 Chrome 116 启用 ECH
const chrome116JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-41-17513,29-23-24,0"

// chrome117JA3 Chrome 117-123 启用 PSK + ECH
const chrome117JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-41-17513,29-23-24,0"

// chrome124JA3 Chrome 124-130 启用 Kyber768
const chrome124JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-41-17513-65037,29-23-24,0"

// chrome131JA3 Chrome 131+ 启用 X25519MLKEM768 (新 codepoint)
const chrome131JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-41-17513-65037,29-23-24-25497-256,0"

// Chrome 100-105: 基础配置
func Chrome100() profiles.ClientProfile { return buildChromeProfile(chrome100JA3, "Chrome", "100", chromeVersions, []string{"X25519"}) }
func Chrome101() profiles.ClientProfile { return buildChromeProfile(chrome100JA3, "Chrome", "101", chromeVersions, []string{"X25519"}) }
func Chrome104() profiles.ClientProfile { return buildChromeProfile(chrome100JA3, "Chrome", "104", chromeVersions, []string{"X25519"}) }
func Chrome105() profiles.ClientProfile { return buildChromeProfile(chrome100JA3, "Chrome", "105", chromeVersions, []string{"X25519"}) }

// Chrome 106-115: permute 启用
func Chrome106() profiles.ClientProfile { return buildChromeProfile(chrome106JA3, "Chrome", "106", chromeVersions, []string{"X25519"}) }
func Chrome107() profiles.ClientProfile { return buildChromeProfile(chrome106JA3, "Chrome", "107", chromeVersions, []string{"X25519"}) }
func Chrome108() profiles.ClientProfile { return buildChromeProfile(chrome106JA3, "Chrome", "108", chromeVersions, []string{"X25519"}) }
func Chrome109() profiles.ClientProfile { return buildChromeProfile(chrome106JA3, "Chrome", "109", chromeVersions, []string{"X25519"}) }
func Chrome110() profiles.ClientProfile { return buildChromeProfile(chrome106JA3, "Chrome", "110", chromeVersions, []string{"X25519"}) }
func Chrome114() profiles.ClientProfile { return buildChromeProfile(chrome106JA3, "Chrome", "114", chromeVersions, []string{"X25519"}) }
func Chrome115() profiles.ClientProfile { return buildChromeProfile(chrome106JA3, "Chrome", "115", chromeVersions, []string{"X25519"}) }

// Chrome 116: 启用 ECH
func Chrome116() profiles.ClientProfile { return buildChromeProfile(chrome116JA3, "Chrome", "116", chromeVersions, []string{"X25519"}) }

// Chrome 117-123: 启用 PSK + ECH
func Chrome117() profiles.ClientProfile { return buildChromeProfile(chrome117JA3, "Chrome", "117", chromeVersions, []string{"X25519"}) }
func Chrome118() profiles.ClientProfile { return buildChromeProfile(chrome117JA3, "Chrome", "118", chromeVersions, []string{"X25519"}) }
func Chrome119() profiles.ClientProfile { return buildChromeProfile(chrome117JA3, "Chrome", "119", chromeVersions, []string{"X25519"}) }
func Chrome120() profiles.ClientProfile { return buildChromeProfile(chrome117JA3, "Chrome", "120", chromeVersions, []string{"X25519"}) }
func Chrome123() profiles.ClientProfile { return buildChromeProfile(chrome117JA3, "Chrome", "123", chromeVersions, []string{"X25519"}) }

// Chrome 124-130: 启用 X25519Kyber768Draft00
func Chrome124() profiles.ClientProfile { return buildChromeProfile(chrome124JA3, "Chrome", "124", chromeVersions, chromeKeyShareKyberDraft) }
func Chrome125() profiles.ClientProfile { return buildChromeProfile(chrome124JA3, "Chrome", "125", chromeVersions, chromeKeyShareKyberDraft) }
func Chrome126() profiles.ClientProfile { return buildChromeProfile(chrome124JA3, "Chrome", "126", chromeVersions, chromeKeyShareKyberDraft) }
func Chrome127() profiles.ClientProfile { return buildChromeProfile(chrome124JA3, "Chrome", "127", chromeVersions, chromeKeyShareKyberDraft) }
func Chrome128() profiles.ClientProfile { return buildChromeProfile(chrome124JA3, "Chrome", "128", chromeVersions, chromeKeyShareKyberDraft) }
func Chrome129() profiles.ClientProfile { return buildChromeProfile(chrome124JA3, "Chrome", "129", chromeVersions, chromeKeyShareKyberDraft) }
func Chrome130() profiles.ClientProfile { return buildChromeProfile(chrome124JA3, "Chrome", "130", chromeVersions, chromeKeyShareKyberDraft) }

// Chrome 131+: 启用 X25519MLKEM768
func Chrome131() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "131", chromeVersions, chromeKeyShareMLKEM) }
func Chrome132() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "132", chromeVersions, chromeKeyShareMLKEM) }
func Chrome133() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "133", chromeVersions, chromeKeyShareMLKEM) }
func Chrome134() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "134", chromeVersions, chromeKeyShareMLKEM) }
func Chrome135() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "135", chromeVersions, chromeKeyShareMLKEM) }
func Chrome136() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "136", chromeVersions, chromeKeyShareMLKEM) }
func Chrome137() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "137", chromeVersions, chromeKeyShareMLKEM) }
func Chrome138() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "138", chromeVersions, chromeKeyShareMLKEM) }
func Chrome139() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "139", chromeVersions, chromeKeyShareMLKEM) }
func Chrome140() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "140", chromeVersions, chromeKeyShareMLKEM) }
func Chrome141() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "141", chromeVersions, chromeKeyShareMLKEM) }
func Chrome142() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "142", chromeVersions, chromeKeyShareMLKEM) }
func Chrome143() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "143", chromeVersions, chromeKeyShareMLKEM) }
func Chrome144() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "144", chromeVersions, chromeKeyShareMLKEM) }
func Chrome145() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "145", chromeVersions, chromeKeyShareMLKEM) }
func Chrome146() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "146", chromeVersions, chromeKeyShareMLKEM) }
func Chrome147() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "147", chromeVersions, chromeKeyShareMLKEM) }
func Chrome148() profiles.ClientProfile { return buildChromeProfile(chrome131JA3, "Chrome", "148", chromeVersions, chromeKeyShareMLKEM) }
