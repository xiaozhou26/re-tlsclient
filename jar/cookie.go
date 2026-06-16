package jar

import (
	"net/url"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
)

// Jar 是 tls-client CookieJar 的薄包装，提供 map 风格 API 与 Clear。
// 通过 ClientOption.CookieJar 注入到 NewClient 后生效。
type Jar struct {
	tls_client.CookieJar
}

// NewJar 创建一个新的 Jar。
func NewJar() *Jar {
	jar := tls_client.NewCookieJar()

	return &Jar{
		CookieJar: jar,
	}
}

// Clear 清除所有Cookie。
func (j *Jar) Clear() {
	j.CookieJar = tls_client.NewCookieJar()
}

// SetCookiesByMap 将 map 格式的 Cookie 设置到 Jar 中。
func (j *Jar) SetCookiesByMap(urlStr string, cookies map[string]string) error {
	u, err := url.Parse(urlStr)
	if err != nil {
		return err
	}

	var cookieList []*fhttp.Cookie
	for name, value := range cookies {
		cookieList = append(cookieList, &fhttp.Cookie{
			Name:  name,
			Value: value,
		})
	}
	j.SetCookies(u, cookieList)
	return nil
}
