package tlsclient

import (
	"github.com/xiaozhou26/re-tlsclient/profiles"
)

// Firefox 109-151 的指纹定义。
// 数据来源: wreq-util/src/emulate/profile/firefox.rs

// firefox109JA3 Firefox 109-127 基础 17 套 cipher
const firefox109JA3 = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0"

// firefox128JA3 Firefox 128+ 切换到 15 套 cipher
const firefox128JA3 = "771,4865-4867-4866-49195-49199-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0"

// firefox133JA3 Firefox 133+ 启用 MLKEM
const firefox133JA3 = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0"

// Firefox 109 基础配置
func Firefox109() profiles.ClientProfile { return buildFirefoxProfile(firefox109JA3, "109", firefoxVersions, firefoxCurves) }
func Firefox117() profiles.ClientProfile { return buildFirefoxProfile(firefox109JA3, "117", firefoxVersions, firefoxCurves) }

// Firefox 128 切换到 15 套 cipher
func Firefox128() profiles.ClientProfile { return buildFirefoxProfile(firefox128JA3, "128", firefoxVersions, firefoxCurves) }

// Firefox 133 启用 X25519MLKEM768
func Firefox133() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "133", firefoxVersions, firefoxCurvesMLKEM) }

// Firefox 135 启用 ECH + PSK + 完整 MLKEM
func Firefox135() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "135", firefoxVersions, firefoxCurvesMLKEM) }

// FirefoxPrivate135 私人模式
func FirefoxPrivate135() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "135-Private", firefoxVersions, firefoxCurvesMLKEM) }

// FirefoxAndroid135 Android 版本
func FirefoxAndroid135() profiles.ClientProfile { return buildFirefoxProfile(firefox128JA3, "135-Android", firefoxVersions, firefoxCurves) }

// Firefox 136-151 复用 Firefox 135 配置
func Firefox136() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "136", firefoxVersions, firefoxCurvesMLKEM) }
func FirefoxPrivate136() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "136-Private", firefoxVersions, firefoxCurvesMLKEM) }
func Firefox139() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "139", firefoxVersions, firefoxCurvesMLKEM) }
func Firefox142() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "142", firefoxVersions, firefoxCurvesMLKEM) }
func Firefox143() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "143", firefoxVersions, firefoxCurvesMLKEM) }
func Firefox144() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "144", firefoxVersions, firefoxCurvesMLKEM) }
func Firefox145() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "145", firefoxVersions, firefoxCurvesMLKEM) }
func Firefox146() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "146", firefoxVersions, firefoxCurvesMLKEM) }
func Firefox147() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "147", firefoxVersions, firefoxCurvesMLKEM) }
func Firefox148() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "148", firefoxVersions, firefoxCurvesMLKEM) }
func Firefox149() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "149", firefoxVersions, firefoxCurvesMLKEM) }
func Firefox150() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "150", firefoxVersions, firefoxCurvesMLKEM) }
func Firefox151() profiles.ClientProfile { return buildFirefoxProfile(firefox133JA3, "151", firefoxVersions, firefoxCurvesMLKEM) }
