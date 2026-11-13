// SPDX-License-Identifier: Apache-2.0
// 虚拟主机 Web 服务器：按 Host 路由站点，支持静态站点 / 反向代理 / SSL(SNI) / 强制 HTTPS / IP 黑名单 / 访问统计。
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RuntimeSite 运行时站点：配置快照 + 原子计数器 + 预构建的代理。
type RuntimeSite struct {
	site    *Site
	reqs    atomic.Uint64
	bytes   atomic.Uint64
	proxy   *httputil.ReverseProxy
	rootReal string          // 解析符号链接后的根目录（防逃逸）
	blocked []netip.Prefix   // 预解析 IP 黑名单
}

// WebServer 站点服务引擎。
type WebServer struct {
	app  *App
	srv  *http.Server

	mu      sync.RWMutex
	exact   map[string]*RuntimeSite // 精确域名
	wild    map[string]*RuntimeSite // "*.example.com" 通配
	byID    map[string]*RuntimeSite
	certs   map[string]tls.Certificate // 域名 -> 证书
	fallback tls.Certificate

	bindHTTP string
	httpPort int
	httpsPort int
	httpLn   net.Listener
	httpsLn  net.Listener
	httpErr  string
	httpsErr string
	stopCh   chan struct{}
	stopped  bool
}

// NewWebServer 创建并启动站点服务器。
func NewWebServer(app *App) (*WebServer, error) {
	ws := &WebServer{
		app:    app,
		exact:  map[string]*RuntimeSite{},
		wild:   map[string]*RuntimeSite{},
		byID:   map[string]*RuntimeSite{},
		certs:  map[string]tls.Certificate{},
		stopCh: make(chan struct{}),
	}
	if err := ws.ensureFallbackCert(); err != nil {
		return nil, fmt.Errorf("初始化兜底证书: %w", err)
	}
	ws.srv = &http.Server{
		Handler:           ws,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	cfg := app.store.Config()
	ws.bindHTTP, ws.httpPort, ws.httpsPort = cfg.BindHTTP, cfg.HTTPPort, cfg.HTTPSPort
	ws.Reload(app.store.Sites())
	ws.applyListeners()

	// 统计持久化：每 60 秒一次，仅在脏时写盘（无常驻高频轮询）
	go ws.statsLoop()
	return ws, nil
}

// ---------- 站点路由 ----------

// Reload 用新配置整体替换运行时表（保留计数器）。
// 全程持写锁：并发 Reload 串行化，防止读 old 时与其他 Reload 的写竞争、丢失更新。
func (ws *WebServer) Reload(sites []*Site) {
	ws.mu.Lock()
	old := ws.byID
	exact := map[string]*RuntimeSite{}
	wild := map[string]*RuntimeSite{}
	byID := map[string]*RuntimeSite{}
	certs := map[string]tls.Certificate{}

	for _, st := range sites {
		rs := &RuntimeSite{site: st}
		if prev, ok := old[st.ID]; ok { // 热更新：计数器续接
			rs.reqs.Store(prev.reqs.Load())
			rs.bytes.Store(prev.bytes.Load())
		} else { // 冷启动：从持久化快照恢复
			rs.reqs.Store(st.Requests)
			rs.bytes.Store(st.BytesOut)
		}
		for _, d := range st.Domains {
			if strings.HasPrefix(d, "*.") {
				wild[d] = rs
			} else {
				exact[d] = rs
			}
		}
		byID[st.ID] = rs

		// 预构建：静态/PHP 根目录解析 / 反代 / 黑名单
		if st.Type == "static" || st.Type == "php" {
			if real, err := filepath.EvalSymlinks(st.Root); err == nil {
				rs.rootReal = real
			} else {
				rs.rootReal = filepath.Clean(st.Root)
			}
		}
		if st.Type == "proxy" && st.Upstream != "" {
			if u, err := url.Parse(st.Upstream); err == nil {
				rs.proxy = buildProxy(u)
			}
		}
		for _, ip := range st.BlockedIPs {
			if strings.Contains(ip, "/") {
				if p, err := netip.ParsePrefix(ip); err == nil {
					rs.blocked = append(rs.blocked, p)
				}
			} else if a, err := netip.ParseAddr(ip); err == nil {
				rs.blocked = append(rs.blocked, netip.PrefixFrom(a.Unmap(), a.BitLen()))
			}
		}

		// 加载 SSL 证书
		if st.HasSSL {
			cert, err := tls.LoadX509KeyPair(
				filepath.Join(ws.app.certDir, st.ID, "cert.pem"),
				filepath.Join(ws.app.certDir, st.ID, "key.pem"),
			)
			if err != nil {
				log.Printf("[web-manager] 站点 %s 证书加载失败（按无证书处理）: %v", st.ID, err)
				continue
			}
			for _, d := range st.Domains {
				certs[d] = cert
			}
		}
	}

	ws.exact, ws.wild, ws.byID, ws.certs = exact, wild, byID, certs
	ws.mu.Unlock() // 先释放站点表锁，再碰 PHP 管理器（避免锁嵌套）

	// PHP pool 增删时同步 fpm 配置（运行中则平滑 reload）
	if ws.app.php != nil {
		var phpSites []*Site
		for _, st := range sites {
			if st.Type == "php" {
				phpSites = append(phpSites, st)
			}
		}
		ws.app.php.RebuildPools(phpSites)
	}
}

// lookup 按 Host 查站点：精确 -> 通配父域。
func (ws *WebServer) lookup(host string) *RuntimeSite {
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host, "]") {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	host = strings.ToLower(host)
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	if rs, ok := ws.exact[host]; ok {
		return rs
	}
	if i := strings.IndexByte(host, '.'); i >= 0 && i+1 < len(host) {
		if rs, ok := ws.wild["*"+host[i:]]; ok {
			return rs
		}
	}
	return nil
}

// SiteByID 运行时站点（统计合并用）。
func (ws *WebServer) SiteByID(id string) *RuntimeSite {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	return ws.byID[id]
}

// StatsSnapshot 所有站点计数快照。
func (ws *WebServer) StatsSnapshot() map[string][2]uint64 {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	m := make(map[string][2]uint64, len(ws.byID))
	for id, rs := range ws.byID {
		m[id] = [2]uint64{rs.reqs.Load(), rs.bytes.Load()}
	}
	return m
}

func buildProxy(target *url.URL) *httputil.ReverseProxy {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host // 保留原 Host 透传给上游
			pr.SetXForwarded()
		},
		FlushInterval: 100 * time.Millisecond, // 兼容流式/SSE
		Transport: &http.Transport{
			Proxy:                 nil, // 不走环境代理，直连上游
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:          20,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[web-manager] 代理错误 %s: %v", r.Host, err)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintln(w, "502 Bad Gateway：上游服务不可用")
		},
	}
	return rp
}

// ---------- 请求处理 ----------

func (ws *WebServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// ACME HTTP-01 验证应答：先于虚拟主机路由 / HTTPS 跳转 / 黑名单，保证任何配置下都可达
	if isACMEChallengePath(r.URL.Path) && ws.app.acme != nil {
		ws.app.acme.ServeChallenge(w, r)
		return
	}
	host := strings.ToLower(strings.TrimSpace(r.Host))
	rs := ws.lookup(host)
	if rs == nil || !rs.site.Enabled {
		ws.notFoundPage(w, host)
		return
	}
	// IP 黑名单（只认直连地址，不信任可伪造的 XFF）
	if len(rs.blocked) > 0 {
		if a, err := netip.ParseAddr(remoteIP(r.RemoteAddr)); err == nil {
			a = a.Unmap()
			for _, p := range rs.blocked {
				if p.Contains(a) {
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return
				}
			}
		}
	}
	if strings.ContainsRune(r.URL.Path, 0) || strings.ContainsRune(r.URL.RawQuery, 0) {
		http.Error(w, "400 Bad Request", http.StatusBadRequest)
		return
	}
	rs.reqs.Add(1)
	cw := &countingWriter{ResponseWriter: w, n: &rs.bytes}
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if rs.site.HasSSL && rs.site.RedirectHTTPS && r.TLS == nil {
		http.Redirect(cw, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}
	if rs.site.Type == "proxy" {
		if rs.proxy != nil {
			rs.proxy.ServeHTTP(cw, r)
		} else {
			http.Error(cw, "502 Bad Gateway：上游未配置", http.StatusBadGateway)
		}
		return
	}
	if rs.site.Type == "php" {
		ws.servePHP(rs, cw, r)
		return
	}
	ws.serveStatic(rs, cw, r)
}

// ---------- PHP（FastCGI → php-fpm） ----------

// cgiHeaderParser CGI 响应头解析：缓存至头部结束（CRLFCRLF），其后透传。
type cgiHeaderParser struct {
	buf     []byte
	done    bool
	maxHead int
}

// feed 返回需要立即写给客户端的字节（头部结束后）。
func (p *cgiHeaderParser) feed(chunk []byte) (passthrough []byte, err error) {
	if p.done {
		return chunk, nil
	}
	p.buf = append(p.buf, chunk...)
	if len(p.buf) > p.maxHead {
		return nil, fmt.Errorf("CGI 响应头过大")
	}
	if idx := headerEndIndex(p.buf); idx >= 0 {
		p.done = true
		return p.buf[idx:], nil
	}
	return nil, nil
}

// headerEndIndex 定位 \r\n\r\n。
func headerEndIndex(b []byte) int {
	return bytes.Index(b, []byte("\r\n\r\n"))
}

// servePHP 将请求转交 php-fpm（RESPONDER），支持 PATH_INFO 与静态旁路。
func (ws *WebServer) servePHP(rs *RuntimeSite, w http.ResponseWriter, r *http.Request) {
	if ws.app.php == nil {
		http.Error(w, "503 PHP 运行时不可用", http.StatusServiceUnavailable)
		return
	}
	// 1. 解析 URL → 脚本路径 + PATH_INFO（伪静态：/article/1 → index.php/article/1）
	upath := path.Clean("/" + r.URL.Path)
	scriptPath, pathInfo, scriptName, found := resolvePHPScript(ws, rs, upath)
	if !found {
		// 未命中任何候选：静态文件直出（css/js/img），否则 404
		if fi, err := os.Stat(filepath.Join(rs.site.Root, filepath.FromSlash(upath))); err == nil && fi.Mode().IsRegular() {
			ws.serveStatic(rs, w, r)
			return
		}
		http.NotFound(w, r)
		return
	}

	sock, err := ws.app.php.Ensure(rs.site.ID)
	if err != nil {
		http.Error(w, "503 "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	_ = sock // Ensure 已保证 fpm 与该站点 pool 就绪；实际连接由 ConnPool 内部解析
	defer ws.app.php.Touch()

	// 2. 构造 FastCGI 环境（RFC 3875 核心子集）
	var body io.Reader
	if r.Body != nil {
		body = r.Body
	}
	contentLen := r.Header.Get("Content-Length")
	params := [][2]string{
		{"SCRIPT_NAME", scriptName},
		{"SCRIPT_FILENAME", scriptPath},
		{"DOCUMENT_ROOT", rs.site.Root},
		{"REQUEST_URI", r.URL.RequestURI()},
		{"REQUEST_METHOD", r.Method},
		{"QUERY_STRING", r.URL.RawQuery},
		{"CONTENT_TYPE", r.Header.Get("Content-Type")},
		{"CONTENT_LENGTH", contentLen},
		{"SERVER_SOFTWARE", "IotaPanel-web-manager/1.1"},
		{"SERVER_PROTOCOL", r.Proto},
		{"REMOTE_ADDR", remoteIP(r.RemoteAddr)},
		{"GATEWAY_INTERFACE", "CGI/1.1"},
		{"PATH_INFO", pathInfo},
	}
	for k, vs := range r.Header {
		if k == "Content-Length" || k == "Content-Type" {
			continue // 已单独传
		}
		name := "HTTP_" + strings.ToUpper(strings.ReplaceAll(k, "-", "_"))
		params = append(params, [2]string{name, vs[0]})
	}

	// 3. 执行 + 流式回写（头解析 → 状态码/头 → 透传体）
	pool := ws.app.php.ConnPool(rs.site.ID)
	conn, err := pool.get()
	if err != nil {
		http.Error(w, "502 Bad Gateway：PHP 运行时未就绪", http.StatusBadGateway)
		return
	}
	parser := &cgiHeaderParser{maxHead: 64 * 1024}
	headerWritten := false
	broken := false

	_, err = fcgiDo(conn, params, body, func(chunk []byte) {
		if len(chunk) == 0 {
			return
		}
		if !headerWritten {
			pass, ferr := parser.feed(chunk)
			if ferr != nil {
				broken = true
				return
			}
			if !parser.done {
				return
			}
			if applyCGIHeader(w, parser.buf) {
				headerWritten = true
			} else {
				broken = true
				return
			}
			if len(pass) > 0 && !broken {
				w.Write(pass)
			}
			return
		}
		if !broken {
			w.Write(chunk)
		}
	})
	if broken {
		pool.put(conn, true)
		return
	}
	if err != nil {
		pool.put(conn, true)
		if !headerWritten {
			http.Error(w, "502 Bad Gateway：PHP 执行异常", http.StatusBadGateway)
		}
		return
	}
	pool.put(conn, false)
	if !headerWritten && !parser.done {
		http.Error(w, "502 Bad Gateway：PHP 无有效响应", http.StatusBadGateway)
	}
}

// applyCGIHeader 解析 CGI 头并写入 ResponseWriter（含 Status: 支持）。
func applyCGIHeader(w http.ResponseWriter, raw []byte) bool {
	head := string(raw)
	if i := headerEndIndex(raw); i >= 0 {
		head = string(raw[:i])
	}
	status := 200
	extra := http.Header{}
	for _, line := range strings.Split(head, "\r\n") {
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i < 0 {
			return false // 畸形头
		}
		k, v := strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
		switch strings.ToLower(k) {
		case "status":
			if n, _ := strconv.Atoi(strings.Fields(v)[0]); n > 0 {
				status = n
			}
		case "content-type":
			w.Header().Set("Content-Type", v)
		default:
			extra.Add(k, v)
		}
	}
	for k, vs := range extra {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(status)
	return true
}

// resolvePHPScript URL → (脚本绝对路径, PATH_INFO, SCRIPT_NAME, 是否命中)。
// 顺序：精确 php 文件 → 目录 index.php → 前缀回退到 index.php（伪静态）。
func resolvePHPScript(ws *WebServer, rs *RuntimeSite, upath string) (script, pathInfo, scriptName string, ok bool) {
	candidates := []struct{ rel, pi, sn string }{
		{upath, "", upath}, // /foo.php
	}
	if strings.HasSuffix(upath, "/") || upath == "/" {
		for _, idx := range append([]string{"index.php"}, rs.site.Index...) {
			if strings.HasSuffix(idx, ".php") {
				candidates = append(candidates, struct{ rel, pi, sn string }{path.Join(upath, idx), "", path.Join(upath, idx)})
			}
		}
		candidates = append(candidates, struct{ rel, pi, sn string }{path.Join(upath, "index.php"), "", path.Join(upath, "index.php")})
	}
	for _, c := range candidates {
		full := filepath.Join(rs.site.Root, filepath.FromSlash(c.rel))
		if real, err := filepath.EvalSymlinks(full); err == nil {
			// 越界防护（同静态）
			if real == rs.rootReal || strings.HasPrefix(real+string(os.PathSeparator), rs.rootReal+string(os.PathSeparator)) {
				if fi, err := os.Stat(real); err == nil && fi.Mode().IsRegular() && strings.HasSuffix(real, ".php") {
					return real, c.pi, c.sn, true
				}
			}
		}
	}
	// 伪静态回退：/article/1 → index.php + PATH_INFO
	// 若请求路径本身是存在的静态文件（css/js/img），优先静态直出，不进 PHP
	if !phpStaticExists(rs, upath) {
		if idx := filepath.Join(rs.site.Root, "index.php"); fileExists(idx) {
			return idx, upath, "/index.php", true
		}
	}
	return "", "", "", false
}

// phpStaticExists 判断请求路径是否为站点内真实存在的常规文件（供 PHP 旁路直出）。
func phpStaticExists(rs *RuntimeSite, upath string) bool {
	full := filepath.Join(rs.site.Root, filepath.FromSlash(upath))
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return false
	}
	if real != rs.rootReal && !strings.HasPrefix(real+string(os.PathSeparator), rs.rootReal+string(os.PathSeparator)) {
		return false
	}
	fi, err := os.Stat(real)
	return err == nil && fi.Mode().IsRegular()
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// serveStatic 静态文件服务（路径清洗 + 符号链接逃逸防护）。
func (ws *WebServer) serveStatic(rs *RuntimeSite, w http.ResponseWriter, r *http.Request) {
	upath := path.Clean("/" + r.URL.Path) // 归一化，.. 在 Join 前被折叠
	full := filepath.Join(rs.site.Root, filepath.FromSlash(upath))

	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// 符号链接逃逸防护：解析后的真实路径必须仍在根目录内
	if real != rs.rootReal && !strings.HasPrefix(real+string(os.PathSeparator), rs.rootReal+string(os.PathSeparator)) {
		log.Printf("[web-manager] 拦截越界访问 site=%s path=%s -> %s", rs.site.ID, upath, real)
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}
	fi, err := os.Stat(real)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if fi.IsDir() {
		// 目录需以 / 结尾，保证相对链接正确
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, path.Clean("/"+r.URL.Path)+"/", http.StatusMovedPermanently)
			return
		}
		ws.serveDirIndex(rs, w, r, real)
		return
	}
	if !fi.Mode().IsRegular() {
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}
	f, err := os.Open(real)
	if err != nil {
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}
	defer f.Close()
	http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
}

// serveDirIndex 目录请求：优先默认文档，其次目录浏览。
func (ws *WebServer) serveDirIndex(rs *RuntimeSite, w http.ResponseWriter, r *http.Request, dir string) {
	for _, idx := range rs.site.Index {
		if idx == "" {
			continue
		}
		p := filepath.Join(dir, idx)
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(real+string(os.PathSeparator), rs.rootReal+string(os.PathSeparator)) && real != rs.rootReal {
			continue
		}
		fi, err := os.Stat(real)
		if err != nil || fi.IsDir() {
			continue
		}
		f, err := os.Open(real)
		if err != nil {
			continue
		}
		defer f.Close()
		http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
		return
	}
	if rs.site.AutoIndex {
		ws.dirListing(w, r, dir)
		return
	}
	http.Error(w, "403 Forbidden：目录浏览已关闭", http.StatusForbidden)
}

// dirListing 安全的目录浏览（全部 HTML 转义）。
func (ws *WebServer) dirListing(w http.ResponseWriter, r *http.Request, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return entries[i].Name() < entries[j].Name()
	})
	var b strings.Builder
	b.WriteString("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>")
	b.WriteString(html.EscapeString(r.URL.Path))
	b.WriteString("</title><style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem}table{width:100%;border-collapse:collapse}td,th{padding:.4rem .6rem;text-align:left;border-bottom:1px solid #ddd}a{color:#0969da;text-decoration:none}</style></head><body><h3>Index of ")
	b.WriteString(html.EscapeString(r.URL.Path))
	b.WriteString("</h3><table><tr><th>名称</th><th>大小</th><th>修改时间</th></tr><tr><td colspan=3><a href=\"../\">../</a></td></tr>")
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue // 隐藏文件不展示
		}
		name := html.EscapeString(e.Name())
		href := url.QueryEscape(e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		size, mtime := "-", info.ModTime().Format("2006-01-02 15:04")
		if !e.IsDir() {
			size = fmt.Sprintf("%d B", info.Size())
		} else {
			name += "/"
			href += "/"
		}
		fmt.Fprintf(&b, "<tr><td><a href=\"%s\">%s</a></td><td>%s</td><td>%s</td></tr>", html.EscapeString(href), name, size, mtime)
	}
	b.WriteString("</table></body></html>")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, b.String())
}

func (ws *WebServer) notFoundPage(w http.ResponseWriter, host string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, "404 Not Found：没有绑定到 %s 的站点\n", host)
}

// ---------- TLS ----------

func (ws *WebServer) getCert(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSpace(chi.ServerName))
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	if name != "" {
		if c, ok := ws.certs[name]; ok {
			return &c, nil
		}
		if i := strings.IndexByte(name, '.'); i >= 0 {
			if c, ok := ws.certs["*"+name[i:]]; ok {
				return &c, nil
			}
		}
	}
	return &ws.fallback, nil // 无匹配证书：兜底自签，返回加密但未认证的握手
}

// ensureFallbackCert 生成/加载兜底自签证书（ECDSA P-256，一次生成长期使用）。
func (ws *WebServer) ensureFallbackCert() error {
	certPath := filepath.Join(ws.app.etcDir, "fallback-cert.pem")
	keyPath := filepath.Join(ws.app.etcDir, "fallback-key.pem")
	if _, err := os.Stat(certPath); err == nil {
		if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
			ws.fallback = c
			return nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "web-manager-fallback"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	ws.fallback = c
	return nil
}

// ---------- 监听器管理 ----------

func (ws *WebServer) applyListeners() {
	cfg := ws.app.store.Config()

	ws.mu.Lock()
	defer ws.mu.Unlock()
	if ws.stopped {
		return
	}
	// HTTP
	if ws.httpLn == nil || ws.httpPort != cfg.HTTPPort || ws.bindHTTP != cfg.BindHTTP {
		if ws.httpLn != nil {
			ws.httpLn.Close()
			ws.httpLn = nil
		}
		ws.bindHTTP, ws.httpPort = cfg.BindHTTP, cfg.HTTPPort
		if ln, err := net.Listen("tcp", net.JoinHostPort(cfg.BindHTTP, fmt.Sprintf("%d", cfg.HTTPPort))); err != nil {
			ws.httpErr = err.Error()
			log.Printf("[web-manager] HTTP 监听失败 :%d: %v", cfg.HTTPPort, err)
		} else {
			ws.httpErr = ""
			ws.httpLn = ln
			go ws.srv.Serve(ln)
			log.Printf("[web-manager] HTTP 监听已启动 %s:%d（站点服务）", cfg.BindHTTP, cfg.HTTPPort)
		}
	}
	// HTTPS
	if ws.httpsLn == nil || ws.httpsPort != cfg.HTTPSPort {
		if ws.httpsLn != nil {
			ws.httpsLn.Close()
			ws.httpsLn = nil
		}
		ws.httpsPort = cfg.HTTPSPort
		if cfg.HTTPSPort > 0 {
			raw, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.HTTPSPort))
			if err != nil {
				ws.httpsErr = err.Error()
				log.Printf("[web-manager] HTTPS 监听失败 :%d: %v", cfg.HTTPSPort, err)
			} else {
				ws.httpsErr = ""
				tlsCfg := &tls.Config{
					MinVersion:     tls.VersionTLS12,
					GetCertificate: ws.getCert,
				}
				ws.httpsLn = tls.NewListener(raw, tlsCfg)
				go ws.srv.Serve(ws.httpsLn)
				log.Printf("[web-manager] HTTPS 监听已启动 :%d（SNI 多证书）", cfg.HTTPSPort)
			}
		}
	}
}

// ListenerStatus 监听状态（供管理 API）。
func (ws *WebServer) ListenerStatus() (httpUp, httpsUp bool, httpErr, httpsErr string) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	return ws.httpLn != nil, ws.httpsLn != nil, ws.httpErr, ws.httpsErr
}

// SetHTTPSPort 关闭 HTTPS 监听（端口设 0 时）。
func (ws *WebServer) StopHTTPSIfDisabled(port int) {
	if port <= 0 {
		ws.mu.Lock()
		if ws.httpsLn != nil {
			ws.httpsLn.Close()
			ws.httpsLn = nil
		}
		ws.httpsPort = 0
		ws.mu.Unlock()
	}
}

// Close 停止站点监听。
func (ws *WebServer) Close() {
	ws.mu.Lock()
	ws.stopped = true
	if ws.httpLn != nil {
		ws.httpLn.Close()
	}
	if ws.httpsLn != nil {
		ws.httpsLn.Close()
	}
	ws.mu.Unlock()
	close(ws.stopCh)
}

func (ws *WebServer) statsLoop() {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			snap := ws.StatsSnapshot()
			if len(snap) > 0 {
				ws.app.store.FlushStats(snap)
			}
		case <-ws.stopCh:
			return
		}
	}
}

// countingWriter 计数字节的 ResponseWriter，透传 Flush/Hijack（流式与 WebSocket 必需）。
type countingWriter struct {
	http.ResponseWriter
	n *atomic.Uint64
}

func (c *countingWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.n.Add(uint64(n))
	return n, err
}

func (c *countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (c *countingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := c.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("ResponseWriter 不支持 Hijack")
}
