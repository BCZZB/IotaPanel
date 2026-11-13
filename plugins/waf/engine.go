// SPDX-License-Identifier: Apache-2.0
// 双态引擎——「微盾 WAF」的核心，也是本项目低占用哲学的落点：
//
//   ┌────────── 探针模式（平时）──────────┐
//   │ 纯 TCP 直通：偷看首个数据块（≤8KB）│
//   │ · Host 提取路由（字节扫描，非解析）│
//   │ · IP 黑白名单（一次查表）          │
//   │ · 令牌桶计数（O(1)）               │
//   │ · 字面量特征集（大小写折叠后 Contains）│
//   │ 干净流量 → io.Copy 双向直通，零 HTTP 解析 │
//   └────────────────┬───────────────────┘
//     特征命中 / 频率超限 / 流量异常
//   ┌────────────────▼───────────────────┐
//   │ 防护模式（攻击期）                  │
//   │ 完整 HTTP 解析 + 深度解码变体       │
//   │ 12 组内置规则 + 自定义规则           │
//   │ CC 防护 + 人机验证（PoW 挑战）      │
//   │ 拦截/观察 + 事件日志 + 自动拉黑      │
//   └────────────────┬───────────────────┘
//     威胁平息 calm_secs 秒后自动降级回探针

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	stateProbe int32 = iota // 探针（低占用直通）
	stateGuard              // 防护（全量检测）
)

//go:embed web
var webFS embed.FS

// Engine 双态引擎
type Engine struct {
	store  *Store
	secret []byte

	cfg     atomic.Pointer[Config]
	rules   atomic.Pointer[RuleSet]
	ipBlack atomic.Pointer[IPList]
	ipWhite atomic.Pointer[IPList]
	proxies atomic.Pointer[map[string]*siteProxy]

	limiter  *Limiter // 每 IP 令牌桶（CC + 升级判定）
	connRate *Limiter // 全局连接速率（DoS 升级判定）
	autoban  *AutoBanner
	events   *EventLog
	stats    *Stats

	// v0.2.0 融合防护运行时
	urlLim   *Limiter     // 每「IP+URL」令牌桶（1Panel URL 频率）
	nfBanner *AutoBanner  // 404 频率追踪（1Panel 404 封禁）
	threats  *threatList  // 威胁情报信誉黑名单（CrowdSec/1Panel 恶意 IP 组）

	state      atomic.Int32
	guardUntil atomic.Int64

	httpSrv  *http.Server
	selfCert atomic.Pointer[tls.Certificate]

	lnMu   sync.Mutex
	lnHTTP net.Listener
	lnTLS  net.Listener
	stop   chan struct{}
}

// NewEngine 构建引擎并完成首次配置编译
func NewEngine(store *Store, cfg *Config) *Engine {
	e := &Engine{
		store:    store,
		secret:   store.Secret(),
		limiter:  NewLimiter(cfg.CC.Capacity, cfg.CC.Window),
		connRate: NewLimiter(cfg.EscalateConnsPerMin, 60),
		autoban:  NewAutoBanner(cfg.AutoBan.Threshold, cfg.AutoBan.Window),
		events:   NewEventLog(store.EventsPath()),
		stats:    NewStats(),
		urlLim:   NewLimiter(cfg.URLRate.Capacity, cfg.URLRate.Window),
		nfBanner: NewAutoBanner(cfg.NotFound.Capacity, cfg.NotFound.Window),
		threats:  &threatList{},
		stop:     make(chan struct{}),
	}
	e.cfg.Store(cfg)
	e.ipBlack.Store(ParseIPList(cfg.IPBlacklist))
	e.ipWhite.Store(ParseIPList(cfg.IPWhitelist))
	proxies := buildProxies(cfg)
	e.proxies.Store(&proxies)
	rs, rsErr := BuildRuleSet(cfg, e.stats)
	e.rules.Store(rs) // 内置规则始终可用；自定义规则错误仅告警
	if rsErr != nil {
		log.Printf("[waf] 规则编译警告: %v", rsErr)
	}
	e.httpSrv = &http.Server{
		Handler:           http.HandlerFunc(e.guardHandler),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	return e
}

// Start 启动流量入口与后台协程
func (e *Engine) Start() {
	cfg := e.cfg.Load()
	e.startEntry(cfg.HTTPEntry, false)
	e.startEntry(cfg.HTTPSEntry, true)
	go e.tickLoop()
	go e.threatLoop()
	log.Printf("[waf] 引擎启动：探针模式（HTTP 入口 %s，HTTPS 入口 %s）",
		orDefault(cfg.HTTPEntry, "未启用"), orDefault(cfg.HTTPSEntry, "未启用"))
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// Stop 优雅退出
func (e *Engine) Stop() {
	close(e.stop)
	e.lnMu.Lock()
	if e.lnHTTP != nil {
		e.lnHTTP.Close()
	}
	if e.lnTLS != nil {
		e.lnTLS.Close()
	}
	e.lnMu.Unlock()
	e.events.Close()
}

// ---------- 监听器生命周期 ----------

func (e *Engine) startEntry(addr string, tlsMode bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[waf] 入口监听失败 %s: %v（可在管理页修改端口后保存重启）", addr, err)
		return
	}
	if tlsMode {
		e.lnMu.Lock()
		e.lnTLS = ln
		e.lnMu.Unlock()
		go e.acceptTLSLoop(ln)
		log.Printf("[waf] HTTPS 入口就绪: %s", addr)
	} else {
		e.lnMu.Lock()
		e.lnHTTP = ln
		e.lnMu.Unlock()
		go e.acceptLoop(ln)
		log.Printf("[waf] HTTP 入口就绪: %s", addr)
	}
}

func (e *Engine) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go e.handleConn(c)
	}
}

func (e *Engine) acceptTLSLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(15 * time.Second))
			tc := tls.Server(c, e.tlsConfig())
			if err := tc.Handshake(); err != nil {
				return
			}
			_ = c.SetDeadline(time.Time{})
			e.handleConn(tc)
		}(c)
	}
}

// restartEntries 端口变更时重建监听器
func (e *Engine) restartEntries(newCfg *Config) {
	e.lnMu.Lock()
	oldHTTP, oldTLS := e.lnHTTP, e.lnTLS
	e.lnHTTP, e.lnTLS = nil, nil
	e.lnMu.Unlock()
	if oldHTTP != nil {
		oldHTTP.Close()
	}
	if oldTLS != nil {
		oldTLS.Close()
	}
	time.Sleep(200 * time.Millisecond) // 等待内核释放端口
	e.startEntry(newCfg.HTTPEntry, false)
	e.startEntry(newCfg.HTTPSEntry, true)
}

// Apply 热更新配置（管理页保存后调用）
func (e *Engine) Apply(newCfg *Config) {
	old := e.cfg.Load()
	newCfg.normalize()
	if rs, err := BuildRuleSet(newCfg, e.stats); err == nil {
		e.rules.Store(rs)
	} else {
		log.Printf("[waf] 规则编译警告: %v", err)
	}
	e.ipBlack.Store(ParseIPList(newCfg.IPBlacklist))
	e.ipWhite.Store(ParseIPList(newCfg.IPWhitelist))
	proxies := buildProxies(newCfg)
	e.proxies.Store(&proxies)
	e.limiter.Update(newCfg.CC.Capacity, newCfg.CC.Window)
	e.connRate.Update(newCfg.EscalateConnsPerMin, 60)
	e.autoban = NewAutoBanner(newCfg.AutoBan.Threshold, newCfg.AutoBan.Window)
	e.urlLim.Update(newCfg.URLRate.Capacity, newCfg.URLRate.Window)
	e.nfBanner = NewAutoBanner(newCfg.NotFound.Capacity, newCfg.NotFound.Window)
	e.cfg.Store(newCfg)
	if old.HTTPEntry != newCfg.HTTPEntry || old.HTTPSEntry != newCfg.HTTPSEntry {
		e.restartEntries(newCfg)
	}
	log.Printf("[waf] 配置已热更新（站点 %d 个，规则组 %d 个启用）",
		len(newCfg.Sites), countEnabledGroups(newCfg))
}

func countEnabledGroups(cfg *Config) int {
	n := 0
	for _, on := range cfg.RuleGroups {
		if on {
			n++
		}
	}
	return n
}

// ---------- 状态机 ----------

// State 当前模式：probe / guard
func (e *Engine) State() string {
	if e.state.Load() == stateGuard {
		return "guard"
	}
	return "probe"
}

// Escalate 升级到防护模式（幂等；附带升级原因）
func (e *Engine) Escalate(reason string) {
	first := e.state.CompareAndSwap(stateProbe, stateGuard)
	if first {
		e.stats.escalations.Add(1)
		cfg := e.cfg.Load()
		e.events.Add(Event{
			Kind: "escalate", IP: "-", Rule: "ENGINE",
			Desc: "探针 → 防护模式", Detail: reason,
		})
		log.Printf("[waf] ⚠ 检测到威胁，升级防护模式: %s（无威胁 %d 秒后自动降级）", reason, cfg.CalmSecs)
	}
	e.ExtendGuard()
}

// ExtendGuard 威胁续期：把防护模式再保持一个冷静期
func (e *Engine) ExtendGuard() {
	cfg := e.cfg.Load()
	e.guardUntil.Store(time.Now().Add(time.Duration(cfg.CalmSecs) * time.Second).Unix())
}

// Deescalate 手动降级回探针
func (e *Engine) Deescalate() {
	if e.state.CompareAndSwap(stateGuard, stateProbe) {
		e.events.Add(Event{Kind: "deescalate", IP: "-", Rule: "ENGINE", Desc: "防护 → 探针模式", Detail: "手动降级"})
		log.Printf("[waf] 已手动降级回探针模式")
	}
}

// GuardRemain 防护模式剩余秒数
func (e *Engine) GuardRemain() int64 {
	r := e.guardUntil.Load() - time.Now().Unix()
	if r < 0 {
		return 0
	}
	return r
}

// tickLoop 每秒：QPS 快照 + 自动降级
func (e *Engine) tickLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			e.stats.Tick()
			if e.state.Load() == stateGuard && time.Now().Unix() > e.guardUntil.Load() {
				if e.state.CompareAndSwap(stateGuard, stateProbe) {
					e.events.Add(Event{Kind: "deescalate", IP: "-", Rule: "ENGINE", Desc: "防护 → 探针模式", Detail: "威胁已平息（冷静期结束）"})
					log.Printf("[waf] 威胁平息，自动降级回探针模式（低占用直通）")
				}
			}
		case <-e.stop:
			return
		}
	}
}

// ---------- 连接处理（探针快速路径的核心） ----------

func (e *Engine) handleConn(c net.Conn) {
	defer c.Close()
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	ipStr, _ := splitHostPort(c.RemoteAddr().String())
	ipAddr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return
	}
	cfg := e.cfg.Load()
	e.stats.total.Add(1)
	e.stats.secCount.Add(1)

	// 全局连接速率（DoS 升级信号）——探针/防护均计数
	if !e.connRate.Allow("__global__") {
		e.Escalate("全局连接速率异常（疑似 DoS/洪水）")
	}

	// IP 黑名单永远生效（探针模式同样执行：代价仅一次查表）
	if ent, ok := e.ipBlack.Load().Contains(ipAddr); ok {
		e.stats.blocked.Add(1)
		e.stats.ipBlock(ipStr)
		e.events.Add(Event{Kind: "block", IP: ipStr, Rule: "IP-BLACKLIST", Desc: "IP 黑名单", Detail: ent.Reason})
		e.writeMini(c, 403, "403 IP 已被拦截", "该 IP 已被列入黑名单。"+ent.Reason)
		return
	}

	// 威胁情报信誉黑名单（CrowdSec 社区块表 / 1Panel 恶意 IP 组）：同样探针即拦截
	// 由 threat_intel_block 总开关控制；默认关闭（部署在受信反代/隧道之后时，对端通常是
	// 127.0.0.1 这类回环地址，直接查信誉库会误拦全部流量）。
	if cfg.ThreatIntelBlock && e.threats.contains(ipAddr) {
		e.stats.blocked.Add(1)
		e.stats.ipBlock(ipStr)
		e.events.Add(Event{Kind: "block", IP: ipStr, Rule: "THREAT-INTEL", Desc: "威胁情报信誉黑名单", Detail: "IP 命中 CrowdSec 社区信誉源"})
		e.writeMini(c, 403, "403 IP 已被拦截", "该 IP 命中威胁情报信誉黑名单。")
		return
	}

	// 已处于防护模式：全部交给完整检测管线
	if e.state.Load() == stateGuard {
		e.serveGuardConn(c, nil)
		return
	}

	// ===== 探针模式：快速路径 =====
	head, ok := peekHead(c)
	if !ok || len(head) == 0 {
		return
	}

	// 非 HTTP 明文（如误把 TLS 打到 HTTP 口）：交防护管线给标准错误
	if !looksLikeHTTP(head) {
		e.serveGuardConn(c, head)
		return
	}

	host := extractHost(head)
	site := matchSite(cfg, host)
	if site == nil {
		e.writeMini(c, 421, "421 未匹配站点", "没有保护站点匹配 Host "+host)
		return
	}

	// CC 计数（探针同样计数，超限即升级并交由防护管线处理）
	if cfg.CC.Enabled && !e.limiter.Allow(ipStr) {
		e.Escalate("IP " + ipStr + " 请求频率超过 CC 阈值")
		e.serveGuardConn(c, head)
		return
	}

	// 快速特征扫描（字面量集合，无正则；命中即升级并交由规则引擎裁决）
	if sig := fastSignatureScan(head); sig != "" {
		e.Escalate("快速特征命中: " + sig)
		e.serveGuardConn(c, head)
		return
	}

	// 干净流量：纯 TCP 直通（零 HTTP 解析、零规则匹配）
	e.pipeThrough(c, head, site)
}

// peekHead 读取首个数据块（≤8KB 或读到头部结束），用于路由与特征扫描
func peekHead(c net.Conn) ([]byte, bool) {
	buf := make([]byte, 8<<10)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	n := 0
	for n < len(buf) {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
		if bytes.Contains(buf[:n], []byte("\r\n\r\n")) {
			break // 头部已读全
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	return buf[:n], n > 0
}

// looksLikeHTTP 是否以常见 HTTP 方法开头
func looksLikeHTTP(head []byte) bool {
	for _, m := range [...][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
		[]byte("HEAD "), []byte("OPTIONS "), []byte("PATCH "), []byte("TRACE "),
		[]byte("CONNECT "), []byte("PROPFIND "), []byte("REPORT "),
	} {
		if bytes.HasPrefix(head, m) {
			return true
		}
	}
	return false
}

// extractHost 从原始请求头字节中提取 Host（轻量字节扫描，不做完整解析）
func extractHost(head []byte) string {
	rest := head
	for len(rest) > 0 {
		line, next, _ := bytes.Cut(rest, []byte("\r\n"))
		rest = next
		if len(line) == 0 {
			break
		}
		if len(line) > 5 && (bytes.EqualFold(line[:5], []byte("Host:"))) {
			return strings.TrimSpace(string(line[5:]))
		}
	}
	return ""
}

// fastSignatureScan 快速特征：大小写折叠后做字面量子串匹配（含一层 URL 解码；
// 出现 % 或 + 均触发解码——query 中 + 即空格，union+select 形态必须还原后再匹配）
func fastSignatureScan(head []byte) string {
	low := lowerBytes(head)
	for _, s := range fastSignatures {
		if bytes.Contains(low, s.pat) {
			return s.display
		}
	}
	if bytes.IndexByte(head, '%') >= 0 || bytes.IndexByte(head, '+') >= 0 {
		if dec, err := url.QueryUnescape(string(head)); err == nil {
			dl := lowerBytes([]byte(dec))
			for _, s := range fastSignatures {
				if bytes.Contains(dl, s.pat) {
					return s.display
				}
			}
		}
	}
	return ""
}

type fastSig struct {
	pat     []byte // 小写字面量
	display string
}

var fastSignatures = func() []fastSig {
	raw := []string{
		"union select", "union all select", "or 1=1", "' or '", "' and '", "select+from",
		"information_schema", "sleep(", "benchmark(", "extractvalue(", "updatexml(",
		"load_file", "into outfile", "xp_cmdshell", "waitfor delay", "/*!", "'; drop", "' --",
		"../..", "..%2f", "%2e%2e", "/etc/passwd", "/etc/shadow", "/proc/self/environ",
		"<script", "javascript:", "onerror=", "onload=", "onmouseover=", "eval(",
		"document.cookie", "fromcharcode", "srcdoc=", "data:text/html", "vbscript:",
		"<?php", "<%eval", "eval(base64_decode", "assert($_", "system($_", "shell_exec($_",
		"php://filter", "php://input", "c99shell", "r57shell", "filesman", "b374k",
		"sqlmap", "nikto", "masscan", "nmap scripting", "acunetix", "nessus", "nuclei",
		"dirbuster", "gobuster", "wfuzz", "hydra", "metasploit", "havij",
		"/.env", "/.git", "/.svn", "/.ds_store", "id_rsa", ".htpasswd", "wp-config.php.bak",
		"wget http", "curl http", ";wget", "|wget", "`id`", "$(id", "$(cat", "rm -rf",
		"nc -e", "bash -i", "powershell -enc", "certutil -urlcache",
		"rO0AB", "ysoserial", "commons-collections",
		"169.254.169.254", "metadata.google.internal",
		"%0d%0a",
	}
	out := make([]fastSig, 0, len(raw))
	for _, s := range raw {
		pat := lowerBytes([]byte(s))
		out = append(out, fastSig{pat: pat, display: s})
	}
	return out
}()

// pipeThrough 纯 TCP 双向直通（探针模式干净流量的零解析转发）
func (e *Engine) pipeThrough(c net.Conn, head []byte, site *Site) {
	for _, b := range site.Backends {
		b = strings.TrimSpace(b)
		if b == "" {
			continue
		}
		up, err := net.DialTimeout("tcp", b, 5*time.Second)
		if err != nil {
			continue
		}
		go func(up net.Conn, head []byte) {
			defer up.Close()
			if len(head) > 0 {
				_, _ = up.Write(head)
			}
			_, _ = io.Copy(up, c)
		}(up, head)
		_, _ = io.Copy(c, up)
		return
	}
	e.writeMini(c, 502, "502 上游不可达", "站点 "+site.Name+" 的上游服务无法连接。")
}

// ---------- 单连接注入 http.Server（防护管线） ----------

// serveGuardConn 把连接（连同已读的 head）交给防护模式的 HTTP 检测管线
func (e *Engine) serveGuardConn(c net.Conn, head []byte) {
	var conn net.Conn = c
	if len(head) > 0 {
		conn = &prefixConn{Conn: c, prefix: bytes.NewReader(head)}
	}
	l := newOneShotListener(conn)
	_ = e.httpSrv.Serve(l)
}

// prefixConn 在真实连接前回放已偷读的数据
type prefixConn struct {
	net.Conn
	prefix *bytes.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if p.prefix.Len() > 0 {
		return p.prefix.Read(b)
	}
	return p.Conn.Read(b)
}

// oneShotListener 只 Accept 一次；连接关闭后 Serve 返回
type oneShotListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newOneShotListener(c net.Conn) *oneShotListener {
	return &oneShotListener{conn: &closeSignalingConn{Conn: c, done: make(chan struct{})}}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.conn != nil {
		c := l.conn
		l.conn = nil
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneShotListener) Close() error   { return nil }
func (l *oneShotListener) Addr() net.Addr { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "waf-oneshot" }

type closeSignalingConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *closeSignalingConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

// ---------- TLS（SNI + 自签兜底） ----------

func (e *Engine) tlsConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cfg := e.cfg.Load()
			host := strings.ToLower(strings.Split(hello.ServerName, ":")[0])
			if site := matchSite(cfg, host); site != nil && site.CertFile != "" && site.KeyFile != "" {
				if cert, err := tls.LoadX509KeyPair(site.CertFile, site.KeyFile); err == nil {
					return &cert, nil
				}
			}
			cert := e.selfCert.Load()
			if cert == nil {
				c := e.ensureSelfSigned()
				return c, nil
			}
			return cert, nil
		},
		MinVersion: tls.VersionTLS12,
	}
}

func (e *Engine) ensureSelfSigned() *tls.Certificate {
	if c := e.selfCert.Load(); c != nil {
		return c
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "IotaWAF"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
	e.selfCert.Store(&cert)
	return &cert
}

// ---------- 工具 ----------

func splitHostPort(addr string) (string, string) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, ""
	}
	return h, p
}

func parseIP(s string) (netip.Addr, error) {
	return netip.ParseAddr(strings.TrimSpace(s))
}

// writeMini 直接向裸连接写一个极简 HTTP 响应（探针模式拒绝/错误时用）
func (e *Engine) writeMini(c net.Conn, code int, title, detail string) {
	body := miniPage(title, "%s", detail)
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, title, len(body), body)
	_ = c.SetWriteDeadline(time.Time{})
}

// addBlacklistEntry 追加黑名单（自动拉黑用，直接改内存并落盘）
func (e *Engine) addBlacklistEntry(ent IPEntry) {
	cfg := e.cfg.Load().Clone()
	cfg.IPBlacklist = append(cfg.IPBlacklist, ent)
	if err := e.store.SaveConfig(cfg); err != nil {
		log.Printf("[waf] 自动拉黑落盘失败: %v", err)
	}
	e.ipBlack.Store(ParseIPList(cfg.IPBlacklist))
	e.cfg.Store(cfg)
}
