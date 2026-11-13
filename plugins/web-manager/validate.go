// SPDX-License-Identifier: Apache-2.0
// 输入校验：域名 / 站点 ID / 上游地址 / 站点根目录 / 端口 / IP 黑名单。
package main

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	reSiteID  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	reLabel   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reSiteName = regexp.MustCompile(`^[\p{Han}\w][\p{Han}\w .-]{0,63}$`)
	reDBName  = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)
	reDBUser  = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,31}$`)
)

// ValidDomain 校验单个域名（支持 *.wildcard、IP、localhost），返回小写规范化结果。
func ValidDomain(d string) (string, bool) {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" || len(d) > 253 {
		return "", false
	}
	if strings.ContainsAny(d, "/\\?#@% \t") {
		return "", false
	}
	wild := false
	if strings.HasPrefix(d, "*.") {
		wild = true
		d = d[2:]
	}
	if d == "localhost" {
		return "", false // 面板/本机保留字，不允许做站点域名
	}
	if _, err := netip.ParseAddr(d); err == nil {
		if wild {
			return "", false
		}
		return d, true // IP 虚拟主机
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, l := range labels {
		if !reLabel.MatchString(l) {
			return "", false
		}
	}
	out := d
	if wild {
		out = "*." + d
	}
	return out, true
}

// ValidDomains 批量校验并去重。
func ValidDomains(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range in {
		d, ok := ValidDomain(raw)
		if !ok {
			return nil, fmt.Errorf("非法域名: %q", raw)
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("至少需要一个域名")
	}
	return out, nil
}

// ValidUpstream 校验反向代理上游地址。
func ValidUpstream(u string) (string, error) {
	u = strings.TrimSpace(u)
	pu, err := url.Parse(u)
	if err != nil {
		return "", fmt.Errorf("上游地址无法解析")
	}
	if pu.Scheme != "http" && pu.Scheme != "https" {
		return "", fmt.Errorf("上游地址必须是 http:// 或 https:// 开头")
	}
	if pu.Host == "" {
		return "", fmt.Errorf("上游地址缺少主机")
	}
	if pu.Fragment != "" || pu.User != nil {
		return "", fmt.Errorf("上游地址包含不允许的部分")
	}
	return u, nil
}

// systemMounts 明确禁止作为站点根目录的系统敏感区。
var systemRoots = []string{"/proc", "/sys", "/dev", "/run"}

// ValidRoot 校验静态站点根目录：绝对路径、无 ..、不在系统禁区。
func ValidRoot(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("目录不能为空")
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("目录必须是绝对路径（如 /www/wwwroot/mysite）")
	}
	clean := filepath.Clean(p)
	if clean == "/" {
		return "", fmt.Errorf("不允许把整个 / 作为站点目录")
	}
	for _, s := range systemRoots {
		if clean == s || strings.HasPrefix(clean, s+"/") {
			return "", fmt.Errorf("系统目录 %s 禁止作为站点目录", s)
		}
	}
	return clean, nil
}

// ValidPort 校验端口范围。
func ValidPort(p int) bool { return p >= 1 && p <= 65535 }

// ValidIndexFiles 校验默认文档名（纯文件名，禁止路径分隔符）。
func ValidIndexFiles(in []string) ([]string, error) {
	out := []string{}
	for _, f := range in {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if len(f) > 128 || strings.ContainsAny(f, "/\\:") || f == "." || f == ".." || strings.ContainsRune(f, 0) {
			return nil, fmt.Errorf("非法默认文档名: %q", f)
		}
		out = append(out, f)
	}
	return out, nil
}

// ValidIPList 校验 IP / CIDR 黑名单。
func ValidIPList(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			if _, err := netip.ParsePrefix(s); err != nil {
				return nil, fmt.Errorf("非法 CIDR: %q", s)
			}
		} else {
			if _, err := netip.ParseAddr(s); err != nil {
				return nil, fmt.Errorf("非法 IP: %q", s)
			}
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, nil
}

// NormalizeSiteID 由名称推导站点 ID：仅保留 [a-z0-9-]。
func NormalizeSiteID(name string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '-', r == '_', r == ' ', r == '.':
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
		if b.Len() >= 63 {
			break
		}
	}
	id := strings.Trim(b.String(), "-")
	if id == "" || !reSiteID.MatchString(id) {
		id = "site"
	}
	return id
}

// ValidSiteName 展示名：非空、长度限制、无控制字符。
func ValidSiteName(n string) (string, bool) {
	n = strings.TrimSpace(n)
	if n == "" || !reSiteName.MatchString(n) {
		return "", false
	}
	return n, true
}

// remoteIP 从 RemoteAddr 提取 IP。
func remoteIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// ---------- 数据库输入校验（严格白名单，杜绝 SQL 注入面） ----------

// ValidDBName 库名：字母开头 + 字母数字下划线，≤64 字符。
func ValidDBName(n string) error {
	if !reDBName.MatchString(n) {
		return fmt.Errorf("库名须以字母开头，仅含字母/数字/下划线（≤64 字符）")
	}
	if strings.EqualFold(n, "mysql") || strings.EqualFold(n, "information_schema") ||
		strings.EqualFold(n, "performance_schema") || strings.EqualFold(n, "sys") {
		return fmt.Errorf("系统库名禁止使用")
	}
	return nil
}

// ValidDBUser 账号名：字母开头 + 字母数字下划线，≤32 字符。
func ValidDBUser(u string) error {
	if !reDBUser.MatchString(u) {
		return fmt.Errorf("账号须以字母开头，仅含字母/数字/下划线（≤32 字符）")
	}
	if strings.EqualFold(u, "root") {
		return fmt.Errorf("root 为保留账号")
	}
	return nil
}

// ValidDBPassword 密码：8-64 位，拒绝 SQL 字面量敏感字符（' 与 \）与空白。
func ValidDBPassword(p string) error {
	if len(p) < 8 || len(p) > 64 {
		return fmt.Errorf("密码长度须在 8-64 位")
	}
	if strings.ContainsAny(p, `'\\`+" \t\r\n\x00") {
		return fmt.Errorf("密码含不允许的字符（引号/反斜杠/空白）")
	}
	return nil
}
