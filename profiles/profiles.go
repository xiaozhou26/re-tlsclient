package profiles

import (
	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
)

var DefaultClientProfile = Chrome_147

// MappedTLSClients maps string identifiers to browser profiles.
// Fingerprints are ported from https://github.com/0x676e67/wreq-util
// with backward-compatible aliases from bogdanfinn/tls-client.
var MappedTLSClients = map[string]ClientProfile{
	// Chrome — v100 to v148
	"chrome_100": Chrome_100,
	"chrome_101": Chrome_101,
	"chrome_103": Chrome_103,
	"chrome_104": Chrome_104,
	"chrome_105": Chrome_105,
	"chrome_106": Chrome_106,
	"chrome_107": Chrome_107,
	"chrome_108": Chrome_108,
	"chrome_109": Chrome_109,
	"chrome_110": Chrome_110,
	"chrome_111": Chrome_111,
	"chrome_112": Chrome_112,
	"chrome_114": Chrome_114,
	"chrome_116":     Chrome_116,
	"chrome_116_PSK": Chrome_116_PSK,
	"chrome_117": Chrome_117,
	"chrome_118": Chrome_118,
	"chrome_119": Chrome_119,
	"chrome_120": Chrome_120,
	"chrome_123": Chrome_123,
	"chrome_124": Chrome_124,
	"chrome_126": Chrome_126,
	"chrome_127": Chrome_127,
	"chrome_128": Chrome_128,
	"chrome_129": Chrome_129,
	"chrome_130":     Chrome_130,
	"chrome_130_PSK": Chrome_130_PSK,
	"chrome_131":     Chrome_131,
	"chrome_131_PSK": Chrome_131_PSK,
	"chrome_132": Chrome_132,
	"chrome_133":     Chrome_133,
	"chrome_133_PSK": Chrome_133_PSK,
	"chrome_134": Chrome_134,
	"chrome_135": Chrome_135,
	"chrome_136": Chrome_136,
	"chrome_137": Chrome_137,
	"chrome_138": Chrome_138,
	"chrome_139": Chrome_139,
	"chrome_140": Chrome_140,
	"chrome_141": Chrome_141,
	"chrome_142": Chrome_142,
	"chrome_143": Chrome_143,
	"chrome_144":     Chrome_144,
	"chrome_144_PSK": Chrome_144_PSK,
	"chrome_145": Chrome_145,
	"chrome_146":     Chrome_146,
	"chrome_146_PSK": Chrome_146_PSK,
	"chrome_147": Chrome_147,
	"chrome_148": Chrome_148,

	// Chrome PSK/PQ compatibility aliases (from bogdanfinn/tls-client)
	"chrome_116_PSK_PQ": Chrome_116_PSK_PQ,

	// Brave
	"brave_146":     Brave_146,
	"brave_146_PSK": Brave_146_PSK,

	// Edge — v131 to v148
	"edge_131": Edge_131,
	"edge_134": Edge_134,
	"edge_135": Edge_135,
	"edge_136": Edge_136,
	"edge_137": Edge_137,
	"edge_138": Edge_138,
	"edge_139": Edge_139,
	"edge_140": Edge_140,
	"edge_141": Edge_141,
	"edge_142": Edge_142,
	"edge_143": Edge_143,
	"edge_144": Edge_144,
	"edge_145": Edge_145,
	"edge_146": Edge_146,
	"edge_147": Edge_147,
	"edge_148": Edge_148,

	// Safari — macOS
	"safari_15_6_1": Safari_15_6_1,
	"safari_16_0":   Safari_16_0,
	"safari_18":     Safari_18,
	"safari_18_2":   Safari_18_2,
	"safari_18_3":   Safari_18_3,
	"safari_26":     Safari_26,
	"safari_26_1":   Safari_26_1,
	"safari_26_2":   Safari_26_2,

	// Safari — iPad
	"safari_ipad_15_6": Safari_Ipad_15_6,

	// Safari — iOS
	"safari_ios_15_5": Safari_IOS_15_5,
	"safari_ios_15_6": Safari_IOS_15_6,
	"safari_ios_16_0": Safari_IOS_16_0,
	"safari_ios_17_0": Safari_IOS_17_0,
	"safari_ios_18":   Safari_IOS_18,
	"safari_ios_18_0": Safari_IOS_18_0,
	"safari_ios_18_5": Safari_IOS_18_5,
	"safari_ios_26":   Safari_IOS_26,
	"safari_ios_26_0": Safari_IOS_26_0,

	// Firefox — v102 to v151
	"firefox_102":     Firefox_102,
	"firefox_104":     Firefox_104,
	"firefox_105":     Firefox_105,
	"firefox_106":     Firefox_106,
	"firefox_108":     Firefox_108,
	"firefox_109":     Firefox_109,
	"firefox_110":     Firefox_110,
	"firefox_117":     Firefox_117,
	"firefox_120":     Firefox_120,
	"firefox_123":     Firefox_123,
	"firefox_128":     Firefox_128,
	"firefox_132":     Firefox_132,
	"firefox_133":     Firefox_133,
	"firefox_135":     Firefox_135,
	"firefox_136":     Firefox_136,
	"firefox_139":     Firefox_139,
	"firefox_142":     Firefox_142,
	"firefox_143":     Firefox_143,
	"firefox_144":     Firefox_144,
	"firefox_145":     Firefox_145,
	"firefox_146":     Firefox_146,
	"firefox_146_PSK": Firefox_146_PSK,
	"firefox_147":     Firefox_147,
	"firefox_147_PSK": Firefox_147_PSK,
	"firefox_148":     Firefox_148,
	"firefox_149":     Firefox_149,
	"firefox_150":     Firefox_150,
	"firefox_151":     Firefox_151,

	// Opera — v89 to v131
	"opera_89":  Opera_89,
	"opera_90":  Opera_90,
	"opera_91":  Opera_91,
	"opera_116": Opera_116,
	"opera_117": Opera_117,
	"opera_118": Opera_118,
	"opera_119": Opera_119,
	"opera_120": Opera_120,
	"opera_121": Opera_121,
	"opera_122": Opera_122,
	"opera_123": Opera_123,
	"opera_124": Opera_124,
	"opera_125": Opera_125,
	"opera_126": Opera_126,
	"opera_127": Opera_127,
	"opera_128": Opera_128,
	"opera_129": Opera_129,
	"opera_130": Opera_130,
	"opera_131": Opera_131,

	// OkHttp — Android
	"okhttp_4": OkHttp4,
	"okhttp_5": OkHttp5,
	// OkHttp backward-compatible aliases (from bogdanfinn/tls-client)
	"okhttp4_android_7":  Okhttp4Android7,
	"okhttp4_android_8":  Okhttp4Android8,
	"okhttp4_android_9":  Okhttp4Android9,
	"okhttp4_android_10": Okhttp4Android10,
	"okhttp4_android_11": Okhttp4Android11,
	"okhttp4_android_12": Okhttp4Android12,
	"okhttp4_android_13": Okhttp4Android13,

	// Custom/Mobile profiles (from bogdanfinn/tls-client)
	"cloudscraper":          CloudflareCustom,
	"zalando_android_mobile": ZalandoAndroidMobile,
	"zalando_ios_mobile":     ZalandoIosMobile,
	"nike_ios_mobile":        NikeIosMobile,
	"nike_android_mobile":    NikeAndroidMobile,
	"mms_ios":                MMSIos,
	"mms_ios_1":              MMSIos,
	"mms_ios_2":              MMSIos2,
	"mms_ios_3":              MMSIos3,
	"mesh_ios":               MeshIos,
	"mesh_ios_1":             MeshIos,
	"mesh_ios_2":             MeshIos2,
	"mesh_android":           MeshAndroid,
	"mesh_android_1":         MeshAndroid,
	"mesh_android_2":         MeshAndroid2,
	"confirmed_ios":          ConfirmedIos,
	"confirmed_android":      ConfirmedAndroid,
}

type ClientProfile struct {
	clientHelloId          tls.ClientHelloID
	headerPriority         *http2.PriorityParam
	settings               map[http2.SettingID]uint32
	settingsOrder          []http2.SettingID
	priorities             []http2.Priority
	pseudoHeaderOrder      []string
	connectionFlow         uint32
	streamID               uint32
	allowHTTP              bool
	http3Settings          map[uint64]uint64
	http3SettingsOrder     []uint64
	http3PriorityParam     uint32
	http3PseudoHeaderOrder []string
	http3SendGreaseFrames  bool
}

func NewClientProfile(clientHelloId tls.ClientHelloID, settings map[http2.SettingID]uint32, settingsOrder []http2.SettingID, pseudoHeaderOrder []string, connectionFlow uint32, priorities []http2.Priority, headerPriority *http2.PriorityParam, streamID uint32, allowHTTP bool, http3Settings map[uint64]uint64, http3SettingsOrder []uint64, http3PriorityParam uint32, http3PseudoHeaderOrder []string, http3SendGreaseFrames bool) ClientProfile {
	return ClientProfile{
		clientHelloId:          clientHelloId,
		settings:               settings,
		settingsOrder:          settingsOrder,
		pseudoHeaderOrder:      pseudoHeaderOrder,
		connectionFlow:         connectionFlow,
		priorities:             priorities,
		headerPriority:         headerPriority,
		streamID:               streamID,
		allowHTTP:              allowHTTP,
		http3Settings:          http3Settings,
		http3SettingsOrder:     http3SettingsOrder,
		http3PriorityParam:     http3PriorityParam,
		http3PseudoHeaderOrder: http3PseudoHeaderOrder,
		http3SendGreaseFrames:  http3SendGreaseFrames,
	}
}

func (c ClientProfile) GetClientHelloSpec() (tls.ClientHelloSpec, error) {
	return c.clientHelloId.ToSpec()
}

func (c ClientProfile) GetClientHelloStr() string {
	return c.clientHelloId.Str()
}

func (c ClientProfile) GetSettings() map[http2.SettingID]uint32 {
	return c.settings
}

func (c ClientProfile) GetSettingsOrder() []http2.SettingID {
	return c.settingsOrder
}

func (c ClientProfile) GetConnectionFlow() uint32 {
	return c.connectionFlow
}

func (c ClientProfile) GetPseudoHeaderOrder() []string {
	return c.pseudoHeaderOrder
}

func (c ClientProfile) GetHeaderPriority() *http2.PriorityParam {
	return c.headerPriority
}

func (c ClientProfile) GetClientHelloId() tls.ClientHelloID {
	return c.clientHelloId
}

func (c ClientProfile) GetPriorities() []http2.Priority {
	return c.priorities
}

func (c ClientProfile) GetStreamID() uint32 {
	return c.streamID
}

func (c ClientProfile) GetAllowHTTP() bool {
	return c.allowHTTP
}

func (c ClientProfile) GetHttp3Settings() map[uint64]uint64 {
	return c.http3Settings
}

func (c ClientProfile) GetHttp3SettingsOrder() []uint64 {
	return c.http3SettingsOrder
}

func (c ClientProfile) GetHttp3PriorityParam() uint32 {
	return c.http3PriorityParam
}

func (c ClientProfile) GetHttp3PseudoHeaderOrder() []string {
	return c.http3PseudoHeaderOrder
}

func (c ClientProfile) GetHttp3SendGreaseFrames() bool {
	return c.http3SendGreaseFrames
}
