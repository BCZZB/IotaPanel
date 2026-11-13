// SPDX-License-Identifier: Apache-2.0
// 防护模式（guard）HTTP 检测管线：IP 名单 → CC/人机验证 → 规则引擎 → 反向代理。
// 拦截页与挑战页风格参考雷池社区版。

package main

import (
	"bytes"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ---------- 请求数据（规则引擎输入） ----------

type reqField struct {
	name string
	vars []string
}

// ReqData 从 HTTP 请求提取的检测数据（各字段预生成深度解码变体）
type ReqData struct {
	Method  string
	Host    string
	path    []string
	query   []string
	headers []string
	ua      []string
	referer []string
	cookie  []string
	body    []string
}

func (d *ReqData) fieldsFor(t Target) []reqField {
	var out []reqField
	if t.has(TPath) {
		out = append(out, reqField{"path", d.path})
	}
	if t.has(TQuery) {
		out = append(out, reqField{"query", d.query})
	}
	if t.has(THeaders) {
		out = append(out, reqField{"headers", d.headers})
	}
	if t.has(TUA) {
		out = append(out, reqField{"user-agent", d.ua})
	}
	if t.has(TReferer) {
		out = append(out, reqField{"referer", d.referer})
	}
	if t.has(TCookie) {
		out = append(out, reqField{"cookie", d.cookie})
	}
	if t.has(TBody) {
		out = append(out, reqField{"body", d.body})
	}
	return out
}

// extractReqData 提取检测数据；有条件地读取并还原请求体（≤ bodyMax）
func extractReqData(r *http.Request, bodyMax int64) *ReqData {
	d := &ReqData{Method: r.Method, Host: r.Host}
	rawPath := r.URL.EscapedPath()
	if rawPath == "" {
		rawPath = r.URL.Path
	}
	d.path = variants(rawPath)
	if r.URL.RawQuery != "" {
		d.query = variants(r.URL.RawQuery)
	}
	// Header 拼接（限制总量，防超大头拖慢检测）
	var hb strings.Builder
	total := 0
	for k, vv := range r.Header {
		for _, v := range vv {
			total += len(k) + len(v)
			if total > 16<<10 {
				goto headersDone
			}
			hb.WriteString(k)
			hb.WriteString(": ")
			hb.WriteString(v)
			hb.WriteString("\n")
		}
	}
headersDone:
	d.headers = variants(hb.String())
	if ua := r.Header.Get("User-Agent"); ua != "" {
		d.ua = variants(ua)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		d.referer = variants(ref)
	}
	if ck := r.Header.Get("Cookie"); ck != "" {
		d.cookie = variants(ck)
	}
	if body, ok := inspectBody(r, bodyMax); ok {
		d.body = variants(body)
	}
	return d
}

// inspectBody 读取可检测的请求体（文本类 Content-Type），读后完整还原供反代转发
func inspectBody(r *http.Request, max int64) (string, bool) {
	if r.Body == nil || r.Body == http.NoBody || max <= 0 {
		return "", false
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return "", false
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if !(strings.Contains(ct, "form") || strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml") || strings.Contains(ct, "text") || ct == "") {
		return "", false // 二进制体不检测，直接透传
	}
	buf := make([]byte, max+1)
	n, err := io.ReadFull(r.Body, buf)
	if n > int(max) { // 超限：前 max 字节检测，剩余原样接回
		prefix := buf[:max]
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(prefix), r.Body), r.Body}
		r.ContentLength = -1
		return string(prefix), true
	}
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", false // 读取异常：放弃检测但不吞掉请求
	}
	full := buf[:n]
	r.Body = io.NopCloser(bytes.NewReader(full))
	r.ContentLength = int64(n)
	return string(full), true
}

// ---------- 站点路由 ----------

func matchSite(cfg *Config, host string) *Site {
	host = strings.ToLower(strings.TrimSpace(strings.Split(host, ":")[0]))
	var fallback *Site
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		for _, d := range s.Domains {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "*" {
				if fallback == nil {
					fallback = s
				}
				continue
			}
			if matchDomain(d, host) {
				return s
			}
		}
	}
	return fallback
}

func matchDomain(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:]) // ".example.com"
	}
	return false
}

func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------- 反向代理缓存 ----------

type siteProxy struct {
	chain []*httputil.ReverseProxy
	rr    atomic.Uint32
}

func (p *siteProxy) next() *httputil.ReverseProxy {
	if len(p.chain) == 0 {
		return nil
	}
	i := p.rr.Add(1)
	return p.chain[int(i)%len(p.chain)]
}

func buildProxies(cfg *Config) map[string]*siteProxy {
	m := map[string]*siteProxy{}
	for _, s := range cfg.Sites {
		sp := &siteProxy{}
		for _, b := range s.Backends {
			b = strings.TrimSpace(b)
			if b == "" {
				continue
			}
			u, err := url.Parse("http://" + b)
			if err != nil {
				continue
			}
			rp := httputil.NewSingleHostReverseProxy(u)
			rp.FlushInterval = 100 * time.Millisecond
			rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = io.WriteString(w, miniPage("502 上游不可达", "微盾 WAF 无法连接上游服务：<code>%s</code>", html.EscapeString(err.Error())))
			}
			sp.chain = append(sp.chain, rp)
		}
		if len(sp.chain) > 0 {
			m[s.ID] = sp
		}
	}
	return m
}

// ---------- 防护模式主处理器 ----------

// guardHandler 防护模式完整检测管线（一次请求的完整裁决）
func (e *Engine) guardHandler(w http.ResponseWriter, r *http.Request) {
	cfg := e.cfg.Load()
	e.stats.secCount.Add(1)
	e.stats.total.Add(1)

	ip := clientIP(r, cfg.TrustProxy)
	ipAddr, err := parseIP(ip)
	if err != nil {
		ipAddr = netip.Addr{}
	}

	// 站点路由
	site := matchSite(cfg, r.Host)
	if site == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusMisdirectedRequest)
		_, _ = io.WriteString(w, miniPage("421 未匹配站点", "没有站点匹配 Host <code>%s</code>，请在微盾 WAF 管理页配置保护站点。", html.EscapeString(r.Host)))
		return
	}

	// 站点防护关闭：直接转发（仍保留 CC 计数）
	if site.Mode == "off" {
		if cfg.CC.Enabled {
			e.limiter.Allow(ip)
		}
		e.proxyPass(w, r, site, ip)
		return
	}

	// IP 白名单：跳过一切检测
	if _, ok := e.ipWhite.Load().Contains(ipAddr); ok {
		e.proxyPass(w, r, site, ip)
		return
	}
	// IP 黑名单：直接拦截（探针模式同样执行）
	if ent, ok := e.ipBlack.Load().Contains(ipAddr); ok {
		e.doBlock(w, r, site, ip, "IP-BLACKLIST", "IP 黑名单", ent.Reason)
		return
	}
	// 威胁情报信誉黑名单（CrowdSec 社区块表 / 1Panel 恶意 IP 组）
	if cfg.ThreatIntelBlock && e.threats.contains(ipAddr) {
		e.doBlock(w, r, site, ip, "THREAT-INTEL", "威胁情报信誉黑名单", "IP 命中 CrowdSec 社区信誉源")
		return
	}

	// HTTP 方法白名单（1Panel「HTTP 规则」允许列表）
	if len(cfg.HTTPMethods) > 0 && !methodAllowed(r.Method, cfg.HTTPMethods) {
		e.doBlock(w, r, site, ip, "HTTP-METHOD", "HTTP 方法白名单", "不允许的方法 "+r.Method)
		return
	}

	// 搜索引擎蜘蛛放行速率限制（1Panel 蜘蛛池）；规则引擎仍检测
	isBot := cfg.AllowSpiders && isSpider(r.Header.Get("User-Agent"))

	// CC 防护 / 人机验证
	if cfg.CC.Enabled && !e.limiter.Allow(ip) && !isBot {
		if cfg.CC.Action == "block" {
			e.doBlock(w, r, site, ip, "CC-LIMIT", "CC 频率限制", "请求频率超过阈值")
			return
		}
		if ck, err := r.Cookie(challengeCookie); err == nil && e.verifyChallenge(ck.Value, ip, cfg.CC.PowBits) {
			// 已通过人机验证：放行本请求（令牌桶已扣减，验证有效期内不再反复挑战）
			e.proxyPass(w, r, site, ip)
			return
		}
		e.doChallenge(w, r, ip)
		return
	}

	// URL 频率限制（1Panel「URL 模式」：每 IP+URL 独立计数；蜘蛛放行）
	if cfg.URLRate.Enabled && !e.urlLim.Allow(ip+"|"+r.URL.Path) && !isBot {
		if cfg.URLRate.BanSecs > 0 {
			if e.autoban.RecordBlock(ip) {
				e.addBlacklistEntry(IPEntry{
					CIDR:    ip,
					Reason:  "URL 频率限制触发自动拉黑",
					Expires: time.Now().Add(time.Duration(cfg.URLRate.BanSecs) * time.Second).Unix(),
				})
				e.events.Add(Event{Kind: "ban", IP: ip, Rule: "URL-RATE-BAN",
					Desc: fmt.Sprintf("URL 频率超限封禁 %d 秒", cfg.URLRate.BanSecs), Host: r.Host})
			}
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, "429 Too Many Requests\n")
		return
	}

	// 规则引擎全量检测
	rd := extractReqData(r, cfg.BodyMax)
	hit := e.rules.Load().Inspect(rd)
	if hit == nil {
		e.proxyPass(w, r, site, ip)
		return
	}

	// 命中：观察 or 拦截
	ruleID, ruleDesc, snippet := "", "", hit.Snippet
	if hit.Rule != nil {
		ruleID, ruleDesc = hit.Rule.ID, hit.Rule.Desc
	} else if hit.Custom != nil {
		ruleID, ruleDesc = hit.Custom.ID, "自定义规则: "+hit.Custom.Name
	}

	if site.Mode == "monitor" || (hit.Custom != nil && hit.Custom.Action == "monitor") {
		e.stats.monitored.Add(1)
		e.events.Add(Event{
			Kind: "monitor", IP: ip, Method: r.Method, Host: r.Host,
			Path: truncate(rd.path[0], 200), Rule: ruleID, Desc: ruleDesc,
			Detail: "命中字段 " + hit.Field + ": " + snippet, Site: site.ID,
		})
		w.Header().Set("X-WAF-Mode", "monitor")
		w.Header().Set("X-WAF-Hit", ruleID)
		e.proxyPass(w, r, site, ip)
		return
	}

	e.doBlock(w, r, site, ip, ruleID, ruleDesc, "命中字段 "+hit.Field+": "+snippet)

	// 自动拉黑
	if cfg.AutoBan.Enabled && e.autoban.RecordBlock(ip) {
		e.addBlacklistEntry(IPEntry{
			CIDR:    ip,
			Reason:  "自动拉黑：短时间内多次触发拦截规则",
			Expires: time.Now().Add(time.Duration(cfg.AutoBan.Minutes) * time.Minute).Unix(),
		})
		e.events.Add(Event{Kind: "ban", IP: ip, Rule: "AUTO-BAN",
			Desc: fmt.Sprintf("已自动拉黑 %d 分钟", cfg.AutoBan.Minutes), Host: r.Host})
	}
}

// proxyPass 转发到站点上游（注入 X-Forwarded-*）
func (e *Engine) proxyPass(w http.ResponseWriter, r *http.Request, site *Site, ip string) {
	m := *e.proxies.Load()
	sp := m[site.ID]
	if sp == nil || sp.next() == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, miniPage("502 无可用上游", "站点 <b>%s</b> 没有可用的上游地址，请检查站点配置。", html.EscapeString(site.Name)))
		return
	}
	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
		r.Header.Set("X-Forwarded-For", prior+", "+ip)
	} else {
		r.Header.Set("X-Forwarded-For", ip)
	}
	r.Header.Set("X-Real-IP", ip)
	// 404 频率限制：包装响应以捕获上游 404 状态码（1Panel「404 频率限制」）
	cfg := e.cfg.Load()
	if cfg.NotFound.Enabled {
		nf := &nfWriter{ResponseWriter: w}
		sp.next().ServeHTTP(nf, r)
		if nf.status == http.StatusNotFound && e.nfBanner.RecordBlock(ip) {
			if cfg.NotFound.BanSecs > 0 {
				e.addBlacklistEntry(IPEntry{
					CIDR:    ip,
					Reason:  "404 频率限制触发自动拉黑",
					Expires: time.Now().Add(time.Duration(cfg.NotFound.BanSecs) * time.Second).Unix(),
				})
				e.events.Add(Event{Kind: "ban", IP: ip, Rule: "404-RATE-BAN",
					Desc: fmt.Sprintf("404 频率超限封禁 %d 秒", cfg.NotFound.BanSecs), Host: r.Host})
			}
		}
		return
	}
	sp.next().ServeHTTP(w, r)
}

// doBlock 拦截并记录
func (e *Engine) doBlock(w http.ResponseWriter, r *http.Request, site *Site, ip, ruleID, ruleDesc, detail string) {
	e.stats.blocked.Add(1)
	e.stats.ipBlock(ip)
	evID := "evt-" + randHex(6)
	e.events.Add(Event{
		ID: evID, Kind: "block", IP: ip, Method: r.Method, Host: r.Host,
		Path: truncate(r.URL.RequestURI(), 200), Rule: ruleID, Desc: ruleDesc, Detail: detail, Site: site.ID,
	})
	e.ExtendGuard() // 有威胁：保持防护模式
	cfg := e.cfg.Load()
	bp := cfg.BlockPage
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, renderBlockPage(
		html.EscapeString(bp.Title), html.EscapeString(bp.Line1), html.EscapeString(bp.Line2),
		evID, html.EscapeString(ruleID+" "+ruleDesc), html.EscapeString(ip),
		time.Now().Format("2006-01-02 15:04:05")))
}

// doChallenge 下发人机验证挑战页
func (e *Engine) doChallenge(w http.ResponseWriter, r *http.Request, ip string) {
	e.stats.challenged.Add(1)
	e.ExtendGuard()
	cfg := e.cfg.Load()
	nonce := randHex(12)
	exp := time.Now().Add(time.Duration(cfg.CC.VerifySecs) * time.Second).Unix()
	sig := e.signChallenge(nonce, exp, ip)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = io.WriteString(w, renderChallengePage(nonce, cfg.CC.PowBits, strconv.FormatInt(exp, 10), sig))
}

// renderBlockPage 渲染拦截页（占位符替换——CSS 中的 % 与 fmt 动词冲突，禁用 Sprintf）
func renderBlockPage(title, line1, line2, evID, rule, ip, ts string) string {
	return strings.NewReplacer(
		"{{TITLE}}", title, "{{L1}}", line1, "{{L2}}", line2,
		"{{EVID}}", evID, "{{RULE}}", rule, "{{IP}}", ip, "{{TIME}}", ts,
	).Replace(blockPageHTML)
}

// renderChallengePage 渲染挑战页（同上，占位符替换）
func renderChallengePage(nonce string, bits int, exp, sig string) string {
	return strings.NewReplacer(
		"{{NONCE}}", nonce, "{{BITS}}", strconv.Itoa(bits),
		"{{EXP}}", exp, "{{SIG}}", sig,
	).Replace(challengePageHTML)
}

// ---------- 页面模板 ----------

const pageStyle = `
  :root { color-scheme: light; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: "PingFang SC", "Microsoft YaHei", system-ui, sans-serif;
         min-height: 100vh; display: flex; align-items: center; justify-content: center;
         background: #f4f4f0; color: #33393f; padding: 24px; }
  .box { background: #fff; border: 1px solid #e4e0d6; border-radius: 12px;
         padding: 36px 40px; max-width: 560px; width: 100%; box-shadow: 0 6px 24px rgba(0,0,0,.06); }
  h1 { font-size: 20px; margin-bottom: 10px; }
  p { font-size: 14px; line-height: 1.7; color: #5b6470; }
  .shield { font-size: 42px; margin-bottom: 14px; }
  table { width: 100%; margin: 18px 0; font-size: 13px; border-collapse: collapse; }
  td { padding: 6px 0; border-bottom: 1px dashed #eceae2; color: #7e8a94; }
  td:last-child { text-align: right; color: #33393f; font-weight: 600; word-break: break-all; }
  code { background: #f4f4f0; padding: 1px 6px; border-radius: 4px; font-size: 12px; }
  .foot { margin-top: 14px; font-size: 12px; color: #a0a8b0; }
`

// blockPageHTML 雷池风格拦截页（{{TITLE}}/{{L1}}/{{L2}}/{{EVID}}/{{RULE}}/{{IP}}/{{TIME}} 占位）
const blockPageHTML = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}} · 微盾 WAF</title><style>` + pageStyle + `</style></head>
<body><div class="box">
  <div class="shield">🛡️</div>
  <h1>{{TITLE}}</h1>
  <p>{{L1}}</p>
  <table>
    <tr><td>事件 ID</td><td>{{EVID}}</td></tr>
    <tr><td>命中规则</td><td>{{RULE}}</td></tr>
    <tr><td>客户端 IP</td><td>{{IP}}</td></tr>
    <tr><td>时间</td><td>{{TIME}}</td></tr>
  </table>
  <p>{{L2}}</p>
  <div class="foot">IotaPanel · 微盾 WAF</div>
</div></body></html>`

// challengePageHTML 人机验证挑战页（{{NONCE}}/{{BITS}}/{{EXP}}/{{SIG}} 占位）
const challengePageHTML = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>人机验证 · 微盾 WAF</title><style>` + pageStyle + `</style></head>
<body><div class="box">
  <div class="shield">🤖</div>
  <h1>正在进行人机验证</h1>
  <p id="status">正在计算验证凭据，通常 1 秒内完成…</p>
  <noscript><p style="color:#c46a5a">您的请求频率过高，且浏览器未启用 JavaScript，无法完成人机验证。请稍后再试。</p></noscript>
  <div class="foot">IotaPanel · 微盾 WAF</div>
</div>
<script>
(function () {
  var NONCE = "{{NONCE}}", BITS = {{BITS}}, EXP = "{{EXP}}";
  function fnv(s) {
    var h = 0x811c9dc5;
    for (var i = 0; i < s.length; i++) {
      h = (h ^ s.charCodeAt(i)) >>> 0;
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h >>> 0;
  }
  function solve() {
    var mask = (1 << BITS) - 1;
    for (var n = 0; n < 1 << 30; n++) {
      if ((fnv(NONCE + ":" + n) & mask) === 0) return n;
    }
    return -1;
  }
  try {
    var n = solve();
    if (n < 0) throw new Error("no solution");
    document.cookie = "waf_cv=" + NONCE + "." + n + "." + EXP + "." + "{{SIG}}" + "; path=/; max-age=" + (60 * 60 * 24);
    document.getElementById("status").textContent = "验证通过，正在跳转…";
    setTimeout(function () { location.replace(location.pathname + location.search); }, 120);
  } catch (e) {
    document.getElementById("status").textContent = "验证失败，请刷新页面重试。";
  }
})();
</script></body></html>`

// miniPage 小型提示页（参数：标题、说明、格式化详情）
func miniPage(title, format string, args ...any) string {
	detail := fmt.Sprintf(format, args...)
	return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>` + title + `</title><style>` + pageStyle + `</style></head>
<body><div class="box"><div class="shield">🛡️</div><h1>` + title + `</h1><p>` + detail + `</p>
<div class="foot">IotaPanel · 微盾 WAF</div></div></body></html>`
}
