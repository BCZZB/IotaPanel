// SPDX-License-Identifier: Apache-2.0
// 管理 API：站点 CRUD / 域名 / SSL / 端口配置，含安全中间件（CSRF、限流、体积限制、审计）。
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxBodyBytes = 2 << 20 // 2MB（足够 PEM 证书）

// ---------- 速率限制（简单令牌桶，按 IP） ----------

type bucket struct {
	tokens float64
	last   time.Time
}

type ipLimiter struct {
	mu sync.Mutex
	m  map[string]*bucket
}

func newIPLimiter() *ipLimiter { return &ipLimiter{m: map[string]*bucket{}} }

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	// 溢出保护：表过大时清理陈旧条目
	if len(l.m) > 4096 {
		for k, b := range l.m {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.m, k)
			}
		}
	}
	b, ok := l.m[ip]
	if !ok {
		b = &bucket{tokens: 30, last: now}
		l.m[ip] = b
	}
	// 速率 5 req/s，容量 30
	b.tokens += now.Sub(b.last).Seconds() * 5
	if b.tokens > 30 {
		b.tokens = 30
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ---------- App ----------

// App 插件应用对象。
type App struct {
	pluginName string
	home       string
	etcDir     string
	dataDir    string
	sitesDir   string
	certDir    string
	store      *Store
	web        *WebServer
	php        *PHPManager
	mysql      *MySQLManager
	acme       *ACMEManager
	limiter    *ipLimiter
	adminPort  string
	startedAt  time.Time
}

func (a *App) audit(format string, args ...any) {
	log.Printf("[audit] "+format, args...)
}

// ---------- 路由与安全中间件 ----------

func (a *App) adminMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleIndex)
	mux.HandleFunc("GET /api/status", a.handleStatus)
	mux.HandleFunc("GET /api/sites", a.handleListSites)
	mux.HandleFunc("POST /api/sites", a.handleCreateSite)
	mux.HandleFunc("GET /api/sites/{id}", a.handleGetSite)
	mux.HandleFunc("PUT /api/sites/{id}", a.handleUpdateSite)
	mux.HandleFunc("DELETE /api/sites/{id}", a.handleDeleteSite)
	mux.HandleFunc("POST /api/sites/{id}/enable", a.handleEnable(true))
	mux.HandleFunc("POST /api/sites/{id}/disable", a.handleEnable(false))
	mux.HandleFunc("POST /api/sites/{id}/domains", a.handleAddDomains)
	mux.HandleFunc("DELETE /api/sites/{id}/domains/{domain}", a.handleRemoveDomain)
	mux.HandleFunc("PUT /api/sites/{id}/ssl", a.handleSetSSL)
	mux.HandleFunc("DELETE /api/sites/{id}/ssl", a.handleRemoveSSL)
	mux.HandleFunc("GET /api/config", a.handleGetConfig)
	mux.HandleFunc("PUT /api/config", a.handlePutConfig)
	mux.HandleFunc("GET /api/php/status", a.handlePHPStatus)
	mux.HandleFunc("PUT /api/php/config", a.handlePHPConfig)
	mux.HandleFunc("POST /api/php/stop", a.handlePHPStop)

	mux.HandleFunc("GET /api/dbs", a.handleListDBs)
	mux.HandleFunc("POST /api/dbs", a.handleCreateDB)
	mux.HandleFunc("DELETE /api/dbs/{id}", a.handleDeleteDB)
	mux.HandleFunc("PUT /api/dbs/{id}/password", a.handleDBPassword)
	mux.HandleFunc("GET /api/mysql/status", a.handleMySQLStatus)
	mux.HandleFunc("PUT /api/mysql/config", a.handleMySQLConfig)
	mux.HandleFunc("POST /api/mysql/stop", a.handleMySQLStop)

	mux.HandleFunc("GET /api/acme/config", a.handleACMEGet)
	mux.HandleFunc("PUT /api/acme/config", a.handleACMESet)
	mux.HandleFunc("POST /api/acme/register", a.handleACMERegister)
	mux.HandleFunc("POST /api/acme/renew", a.handleACMERenewNow)
	mux.HandleFunc("POST /api/acme/portcheck", a.handleACMEPortCheck)
	mux.HandleFunc("POST /api/sites/{id}/ssl/acme", a.handleSiteIssueCert)
	return a.secure(mux)
}

// secure 统一安全中间件：安全响应头 + 限流 + CSRF。
func (a *App) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")

		ip := remoteIP(r.RemoteAddr)
		if !a.limiter.allow(ip) {
			writeErr(w, http.StatusTooManyRequests, "请求过于频繁，请稍后再试")
			return
		}
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
			if !a.csrfOK(r) {
				a.audit("CSRF 拦截 ip=%s %s %s", ip, r.Method, r.URL.Path)
				writeErr(w, http.StatusForbidden, "禁止：跨站请求校验失败")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// csrfOK 三层放行策略：
//  1. 携带面板网关注入的 X-Panel-Plugin 标记（浏览器跨站无法伪造自定义头）
//  2. Origin 与 Host / X-Forwarded-Host 同源
//  3. 无 Origin 且来源为回环（本机 curl 调试）
func (a *App) csrfOK(r *http.Request) bool {
	if v := r.Header.Get("X-Panel-Plugin"); v != "" {
		return v == a.pluginName
	}
	if o := r.Header.Get("Origin"); o != "" {
		oh := ""
		if i := strings.Index(o, "://"); i >= 0 {
			oh = o[i+3:]
		} else {
			oh = o
		}
		if oh == r.Host {
			return true
		}
		if fh := r.Header.Get("X-Forwarded-Host"); fh != "" && oh == fh {
			return true
		}
		return false
	}
	return isLoopback(r.RemoteAddr)
}

func isLoopback(addr string) bool {
	ip := remoteIP(addr)
	if a, err := netip.ParseAddr(ip); err == nil {
		return a.IsLoopback()
	}
	return false
}

// ---------- 工具 ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"ok": false, "error": msg})
}

func writeOK(w http.ResponseWriter, v any) {
	if v == nil {
		v = map[string]any{"ok": true}
	}
	if m, okm := v.(map[string]any); okm {
		if _, has := m["ok"]; !has {
			m["ok"] = true
		}
	}
	writeJSON(w, http.StatusOK, v)
}

// readJSON 严格读取（体积上限 + 未知字段拒绝）。
func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("请求体格式错误: %v", err)
	}
	return nil
}

// siteView 站点视图（合并实时统计）。
func (a *App) siteView(st *Site) map[string]any {
	reqs, bytes := st.Requests, st.BytesOut
	if rs := a.web.SiteByID(st.ID); rs != nil {
		reqs, bytes = rs.reqs.Load(), rs.bytes.Load()
	}
	sslDays := -1
	if st.HasSSL && !st.SSLNotAfter.IsZero() {
		sslDays = int(time.Until(st.SSLNotAfter).Hours() / 24)
	}
	return map[string]any{
		"id": st.ID, "name": st.Name, "type": st.Type, "domains": st.Domains,
		"root": st.Root, "upstream": st.Upstream, "enabled": st.Enabled,
		"index": st.Index, "autoIndex": st.AutoIndex, "redirectHttps": st.RedirectHTTPS,
		"blockedIps": st.BlockedIPs, "hasSsl": st.HasSSL, "sslDomains": st.SSLDomains,
		"sslDays": sslDays, "sslAuto": st.SSLAuto, "sslProvider": st.SSLProvider,
		"requests": reqs, "bytesOut": bytes,
		"createdAt": st.CreatedAt.Format("2006-01-02 15:04"),
	}
}

// ---------- 页面 ----------

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "页面资源缺失", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// ---------- 状态 ----------

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Config()
	httpUp, httpsUp, httpErr, httpsErr := a.web.ListenerStatus()
	var totalReq, totalBytes uint64
	for _, v := range a.web.StatsSnapshot() {
		totalReq += v[0]
		totalBytes += v[1]
	}
	writeOK(w, map[string]any{
		"httpPort": cfg.HTTPPort, "httpsPort": cfg.HTTPSPort,
		"httpUp": httpUp, "httpsUp": httpsUp,
		"httpErr": httpErr, "httpsErr": httpsErr,
		"siteCount": len(a.store.Sites()),
		"totalRequests": totalReq, "totalBytes": totalBytes,
		"uptime": int(time.Since(a.startedAt).Seconds()),
	})
}

func (a *App) handleListSites(w http.ResponseWriter, r *http.Request) {
	list := []map[string]any{}
	for _, st := range a.store.Sites() {
		list = append(list, a.siteView(st))
	}
	writeOK(w, map[string]any{"sites": list})
}

func (a *App) handleGetSite(w http.ResponseWriter, r *http.Request) {
	st := a.store.Get(r.PathValue("id"))
	if st == nil {
		writeErr(w, http.StatusNotFound, "站点不存在")
		return
	}
	writeOK(w, map[string]any{"site": a.siteView(st)})
}

// ---------- 创建站点 ----------

func (a *App) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string   `json:"name"`
		Domains  []string `json:"domains"`
		Type     string   `json:"type"`
		Root     string   `json:"root"`
		Upstream string   `json:"upstream"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	domains, err := ValidDomains(req.Domains)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	typ := req.Type
	if typ != "static" && typ != "proxy" && typ != "php" {
		writeErr(w, http.StatusBadRequest, "类型必须是 static、proxy 或 php")
		return
	}
	// PHP 站点：运行时必须可用
	if typ == "php" {
		if a.php == nil || a.php.binPath == "" {
			writeErr(w, http.StatusBadRequest, "服务器未安装 php-fpm（安装后重启插件）")
			return
		}
		if !a.store.Config().PHP.Enabled {
			writeErr(w, http.StatusBadRequest, "PHP 运行时未启用，请先在「PHP 设置」中开启")
			return
		}
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = domains[0]
	}
	if _, ok := ValidSiteName(name); !ok {
		writeErr(w, http.StatusBadRequest, "站点名称不合法")
		return
	}
	upstream := ""
	if typ == "proxy" {
		upstream, err = ValidUpstream(req.Upstream)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	// 域名唯一性检查
	for _, st := range a.store.Sites() {
		for _, d := range st.Domains {
			for _, nd := range domains {
				if d == nd {
					writeErr(w, http.StatusConflict, fmt.Sprintf("域名 %s 已绑定到站点 %s", nd, st.Name))
					return
				}
			}
		}
	}
	// 站点 ID：优先从名称推导；纯中文名无法推导时回退用首个域名
	id := NormalizeSiteID(name)
	if id == "site" {
		if d := NormalizeSiteID(domains[0]); d != "site" {
			id = d
		}
	}
	if a.store.Get(id) != nil {
		for i := 2; i < 1000; i++ {
			cand := fmt.Sprintf("%s-%d", id, i)
			if len(cand) > 63 {
				break
			}
			if a.store.Get(cand) == nil {
				id = cand
				break
			}
		}
		if a.store.Get(id) != nil {
			writeErr(w, http.StatusConflict, "站点 ID 冲突，请换一个名称")
			return
		}
	}
	// 根目录：默认沙箱，可自定义（静态与 PHP 站点均需要）
	root := filepath.Join(a.sitesDir, id, "htdocs")
	if (typ == "static" || typ == "php") && strings.TrimSpace(req.Root) != "" {
		root, err = ValidRoot(req.Root)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "创建站点目录失败: "+err.Error())
		return
	}
	st := &Site{
		ID: id, Name: name, Type: typ, Domains: domains, Root: root,
		Upstream: upstream, Enabled: true,
		Index:     []string{"index.html", "index.htm"},
		CreatedAt: time.Now(),
	}
	a.store.Add(st)
	if err := a.store.SaveSites(); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	a.web.Reload(a.store.Sites())
	a.audit("创建站点 id=%s type=%s domains=%v root=%s ip=%s", id, typ, domains, root, remoteIP(r.RemoteAddr))
	writeOK(w, map[string]any{"site": a.siteView(st)})
}

// ---------- 更新站点（整体替换快照） ----------

func (a *App) handleUpdateSite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	old := a.store.Get(id)
	if old == nil {
		writeErr(w, http.StatusNotFound, "站点不存在")
		return
	}
	var req struct {
		Name         string   `json:"name"`
		Root         string   `json:"root"`
		Upstream     string   `json:"upstream"`
		Index        []string `json:"index"`
		AutoIndex    *bool    `json:"autoIndex"`
		RedirectHTTPS *bool   `json:"redirectHttps"`
		BlockedIPs   []string `json:"blockedIps"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	next := *old // 复制快照
	if req.Name != "" {
		if _, ok := ValidSiteName(req.Name); !ok {
			writeErr(w, http.StatusBadRequest, "站点名称不合法")
			return
		}
		next.Name = strings.TrimSpace(req.Name)
	}
	if req.Index != nil {
		idx, err := ValidIndexFiles(req.Index)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if len(idx) == 0 {
			idx = []string{"index.html"}
		}
		next.Index = idx
	}
	if req.AutoIndex != nil {
		next.AutoIndex = *req.AutoIndex
	}
	if req.RedirectHTTPS != nil {
		next.RedirectHTTPS = *req.RedirectHTTPS
	}
	if req.BlockedIPs != nil {
		ips, err := ValidIPList(req.BlockedIPs)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		next.BlockedIPs = ips
	}
	if (old.Type == "static" || old.Type == "php") && strings.TrimSpace(req.Root) != "" {
		root, err := ValidRoot(req.Root)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := os.MkdirAll(root, 0o755); err != nil {
			writeErr(w, http.StatusInternalServerError, "创建目录失败: "+err.Error())
			return
		}
		next.Root = root
	}
	if old.Type == "proxy" && strings.TrimSpace(req.Upstream) != "" {
		up, err := ValidUpstream(req.Upstream)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		next.Upstream = up
	}
	a.store.Update(id, &next)
	if err := a.store.SaveSites(); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	a.web.Reload(a.store.Sites())
	a.audit("更新站点 id=%s ip=%s", id, remoteIP(r.RemoteAddr))
	writeOK(w, map[string]any{"site": a.siteView(&next)})
}

// ---------- 启用/停用 ----------

func (a *App) handleEnable(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		old := a.store.Get(id)
		if old == nil {
			writeErr(w, http.StatusNotFound, "站点不存在")
			return
		}
		next := *old
		next.Enabled = enabled
		a.store.Update(id, &next)
		if err := a.store.SaveSites(); err != nil {
			writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
			return
		}
		a.web.Reload(a.store.Sites())
		a.audit("站点状态 id=%s enabled=%v ip=%s", id, enabled, remoteIP(r.RemoteAddr))
		writeOK(w, map[string]any{"site": a.siteView(&next)})
	}
}

// ---------- 删除站点 ----------

func (a *App) handleDeleteSite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st := a.store.Remove(id)
	if st == nil {
		writeErr(w, http.StatusNotFound, "站点不存在")
		return
	}
	deleteData := r.URL.Query().Get("deleteData") == "1"
	// 只清理沙箱内目录与证书，绝不递归删除用户自定义路径
	sandboxPrefix := filepath.Join(a.sitesDir) + string(os.PathSeparator)
	if deleteData && strings.HasPrefix(st.Root+string(os.PathSeparator), sandboxPrefix) {
		_ = os.RemoveAll(filepath.Dir(st.Root))
	}
	_ = os.RemoveAll(filepath.Join(a.certDir, id))
	if err := a.store.SaveSites(); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	a.web.Reload(a.store.Sites())
	a.audit("删除站点 id=%s deleteData=%v ip=%s", id, deleteData, remoteIP(r.RemoteAddr))
	writeOK(w, nil)
}

// ---------- 域名管理 ----------

func (a *App) handleAddDomains(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	old := a.store.Get(id)
	if old == nil {
		writeErr(w, http.StatusNotFound, "站点不存在")
		return
	}
	var req struct {
		Domains []string `json:"domains"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	add, err := ValidDomains(req.Domains)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 唯一性：站内 + 全局
	owned := map[string]bool{}
	for _, d := range old.Domains {
		owned[d] = true
	}
	for _, st := range a.store.Sites() {
		if st.ID == id {
			continue
		}
		for _, d := range st.Domains {
			owned[d] = true
		}
	}
	for _, d := range add {
		if owned[d] {
			writeErr(w, http.StatusConflict, fmt.Sprintf("域名 %s 已被占用", d))
			return
		}
	}
	next := *old
	next.Domains = append(append([]string{}, old.Domains...), add...)
	a.store.Update(id, &next)
	if err := a.store.SaveSites(); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	a.web.Reload(a.store.Sites())
	a.audit("添加域名 id=%s domains=%v ip=%s", id, add, remoteIP(r.RemoteAddr))
	writeOK(w, map[string]any{"site": a.siteView(&next)})
}

func (a *App) handleRemoveDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	domain, _ := ValidDomain(r.PathValue("domain"))
	old := a.store.Get(id)
	if old == nil {
		writeErr(w, http.StatusNotFound, "站点不存在")
		return
	}
	if domain == "" {
		writeErr(w, http.StatusBadRequest, "域名不合法")
		return
	}
	next := *old
	next.Domains = nil
	found := false
	for _, d := range old.Domains {
		if d == domain {
			found = true
			continue
		}
		next.Domains = append(next.Domains, d)
	}
	if !found {
		writeErr(w, http.StatusNotFound, "域名不存在")
		return
	}
	if len(next.Domains) == 0 {
		writeErr(w, http.StatusBadRequest, "至少保留一个域名")
		return
	}
	a.store.Update(id, &next)
	if err := a.store.SaveSites(); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	a.web.Reload(a.store.Sites())
	a.audit("移除域名 id=%s domain=%s ip=%s", id, domain, remoteIP(r.RemoteAddr))
	writeOK(w, map[string]any{"site": a.siteView(&next)})
}

// ---------- SSL ----------

func (a *App) handleSetSSL(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	old := a.store.Get(id)
	if old == nil {
		writeErr(w, http.StatusNotFound, "站点不存在")
		return
	}
	var req struct {
		Cert string `json:"cert"` // PEM 全文
		Key  string `json:"key"`  // PEM 全文
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	certPEM, keyPEM := strings.TrimSpace(req.Cert), strings.TrimSpace(req.Key)
	if certPEM == "" || keyPEM == "" {
		writeErr(w, http.StatusBadRequest, "证书与私钥均不能为空")
		return
	}
	// 先在内存验证配对与可解析性
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "证书/私钥无效或不成对: "+err.Error())
		return
	}
	warnings := []string{}
	sslDomains := []string{}
	notAfter := time.Time{}
	if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil {
		notAfter = leaf.NotAfter
		if time.Now().After(notAfter) {
			warnings = append(warnings, "警告：证书已过期")
		}
		sslDomains = append(sslDomains, leaf.Subject.CommonName)
		sslDomains = append(sslDomains, leaf.DNSNames...)
		covered := false
		for _, d := range old.Domains {
			for _, sd := range append(leaf.DNSNames, leaf.Subject.CommonName) {
				if d == sd || (strings.HasPrefix(sd, "*.") && strings.HasSuffix(d, sd[1:])) {
					covered = true
				}
			}
		}
		if !covered {
			warnings = append(warnings, "提示：证书未覆盖站点绑定的域名（浏览器可能告警），已按原样保存")
		}
	}
	dir := filepath.Join(a.certDir, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		writeErr(w, http.StatusInternalServerError, "创建证书目录失败")
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte(certPEM), 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, "写入证书失败")
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), []byte(keyPEM), 0o600); err != nil {
		writeErr(w, http.StatusInternalServerError, "写入私钥失败")
		return
	}
	next := *old
	next.HasSSL = true
	next.SSLDomains = sslDomains
	next.SSLNotAfter = notAfter
	next.SSLAuto = false // 手动证书接管
	next.SSLProvider = ""
	a.store.Update(id, &next)
	if err := a.store.SaveSites(); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	a.web.Reload(a.store.Sites())
	a.audit("设置 SSL id=%s ip=%s", id, remoteIP(r.RemoteAddr))
	writeOK(w, map[string]any{"site": a.siteView(&next), "warnings": warnings})
}

func (a *App) handleRemoveSSL(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	old := a.store.Get(id)
	if old == nil {
		writeErr(w, http.StatusNotFound, "站点不存在")
		return
	}
	next := *old
	next.HasSSL = false
	next.SSLDomains = nil
	next.SSLNotAfter = time.Time{}
	next.SSLAuto = false
	next.SSLProvider = ""
	next.RedirectHTTPS = false
	a.store.Update(id, &next)
	_ = os.RemoveAll(filepath.Join(a.certDir, id))
	if err := a.store.SaveSites(); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	a.web.Reload(a.store.Sites())
	a.audit("移除 SSL id=%s ip=%s", id, remoteIP(r.RemoteAddr))
	writeOK(w, map[string]any{"site": a.siteView(&next)})
}

// ---------- SSL 自动申请（ACME） ----------

func (a *App) handleACMEGet(w http.ResponseWriter, r *http.Request) {
	if a.acme == nil {
		writeErr(w, http.StatusServiceUnavailable, "ACME 模块未初始化")
		return
	}
	writeOK(w, a.acme.Status())
}

// handleACMESet 保存证书自动申请设置。
func (a *App) handleACMESet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider      string `json:"provider"`
		Email         string `json:"email"`
		ZeroSSLAPIKey string `json:"zeroSslApiKey"`
		EABKid        string `json:"eabKid"`
		EABHmacKey    string `json:"eabHmacKey"`
		HTTPPort      *int   `json:"httpPort"`
		AutoRenew     *bool  `json:"autoRenew"`
		RenewDays     *int   `json:"renewDays"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ca, ok := acmeCAByID(req.Provider)
	if !ok {
		writeErr(w, http.StatusBadRequest, "未知的证书 CA")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || !strings.Contains(email, "@") || len(email) > 254 {
		writeErr(w, http.StatusBadRequest, "请填写有效的邮箱（用于 CA 账号与到期提醒）")
		return
	}
	if len(req.ZeroSSLAPIKey) > 128 || len(req.EABKid) > 256 || len(req.EABHmacKey) > 512 {
		writeErr(w, http.StatusBadRequest, "API Key / EAB 参数过长")
		return
	}

	cfg := a.store.Config()
	acfg := cfg.ACME
	acfg.Provider = ca.ID
	acfg.Email = email
	acfg.ZeroSSLAPIKey = strings.TrimSpace(req.ZeroSSLAPIKey)
	acfg.EABKid = strings.TrimSpace(req.EABKid)
	acfg.EABHmacKey = strings.TrimSpace(req.EABHmacKey)
	if req.HTTPPort != nil {
		if *req.HTTPPort < 0 || *req.HTTPPort > 65535 {
			writeErr(w, http.StatusBadRequest, "HTTP-01 端口范围 0-65535（0 表示仅用主监听端口）")
			return
		}
		acfg.HTTPPort = *req.HTTPPort
	}
	if req.AutoRenew != nil {
		acfg.AutoRenew = *req.AutoRenew
	}
	if req.RenewDays != nil {
		if *req.RenewDays < 7 || *req.RenewDays > 60 {
			writeErr(w, http.StatusBadRequest, "续期提前天数范围 7-60 天")
			return
		}
		acfg.RenewDays = *req.RenewDays
	}
	cfg.ACME = acfg
	a.store.SetConfig(cfg)
	if err := a.store.SaveConfig(); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	a.acme.ApplyConfig()
	a.audit("更新 SSL 自动申请设置 ca=%s email=%s httpPort=%d ip=%s", acfg.Provider, email, acfg.HTTPPort, remoteIP(r.RemoteAddr))
	writeOK(w, a.acme.Status())
}

// handleACMERegister 注册/校验当前 CA 账号（连通性测试）。
func (a *App) handleACMERegister(w http.ResponseWriter, r *http.Request) {
	if a.acme == nil {
		writeErr(w, http.StatusServiceUnavailable, "ACME 模块未初始化")
		return
	}
	info, err := a.acme.Register()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeOK(w, info)
}

// handleACMERenewNow 手动触发一次到期巡检。
func (a *App) handleACMERenewNow(w http.ResponseWriter, r *http.Request) {
	if a.acme == nil {
		writeErr(w, http.StatusServiceUnavailable, "ACME 模块未初始化")
		return
	}
	results := a.acme.RenewDue()
	if results == nil {
		results = map[string]string{}
	}
	writeOK(w, map[string]any{"results": results})
}

// handleACMEPortCheck 公网 80 端口连通性检测（HTTP-01 验证前置条件）。
// body: {"host":"example.com"} 或 {"siteId":"xxx"}（检测该站点全部域名）。
func (a *App) handleACMEPortCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host   string `json:"host"`
		SiteID string `json:"siteId"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var hosts []string
	if req.SiteID != "" {
		st := a.store.Get(req.SiteID)
		if st == nil {
			writeErr(w, http.StatusNotFound, "站点不存在")
			return
		}
		for _, d := range st.Domains {
			if strings.HasPrefix(d, "*.") {
				continue // 通配符走 DNS 验证，80 端口无关
			}
			hosts = append(hosts, d)
		}
	} else {
		h := strings.TrimSpace(req.Host)
		if h == "" || len(h) > 253 || strings.ContainsAny(h, "/ \t") {
			writeErr(w, http.StatusBadRequest, "请填写要检测的域名或 IP")
			return
		}
		hosts = []string{h}
	}
	if len(hosts) == 0 {
		writeErr(w, http.StatusBadRequest, "没有可检测的域名")
		return
	}
	writeOK(w, map[string]any{"results": checkDomainsPort(hosts)})
}

// handleSiteIssueCert 一键申请/续期站点证书（同步，可能耗时 10-60 秒）。
func (a *App) handleSiteIssueCert(w http.ResponseWriter, r *http.Request) {
	if a.acme == nil {
		writeErr(w, http.StatusServiceUnavailable, "ACME 模块未初始化")
		return
	}
	id := r.PathValue("id")
	st, err := a.acme.Issue(id)
	if err != nil {
		a.audit("自动签发失败 id=%s err=%v", id, err)
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeOK(w, map[string]any{"site": a.siteView(st)})
}

// ---------- PHP 运行时管理 ----------

func (a *App) handlePHPStatus(w http.ResponseWriter, r *http.Request) {
	if a.php == nil {
		writeOK(w, map[string]any{"available": false, "enabled": false})
		return
	}
	st := a.php.Status()
	st["version"] = a.php.FPMVersion()
	writeOK(w, st)
}

// handlePHPConfig 更新 PHP 运行时配置（开关 / workers / 空闲回收）。
func (a *App) handlePHPConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled      *bool `json:"enabled"`
		MaxChildren  *int  `json:"maxChildren"`
		IdleStopSecs *int  `json:"idleStopSecs"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 开启前校验运行时可用
	if req.Enabled != nil && *req.Enabled {
		if a.php == nil || a.php.binPath == "" {
			writeErr(w, http.StatusBadRequest, "服务器未检测到 php-fpm，无法开启（安装 php-fpm 后重启插件）")
			return
		}
	}
	cfg := a.store.Config()
	if req.MaxChildren != nil {
		if *req.MaxChildren < 1 || *req.MaxChildren > 50 {
			writeErr(w, http.StatusBadRequest, "maxChildren 须在 1-50（低占用建议 1-4）")
			return
		}
		cfg.PHP.MaxChildren = *req.MaxChildren
	}
	if req.IdleStopSecs != nil {
		if *req.IdleStopSecs < 30 || *req.IdleStopSecs > 86400 {
			writeErr(w, http.StatusBadRequest, "idleStopSecs 须在 30-86400 秒")
			return
		}
		cfg.PHP.IdleStopSecs = *req.IdleStopSecs
	}
	if req.Enabled != nil {
		cfg.PHP.Enabled = *req.Enabled
	}
	a.store.SetConfig(cfg)
	if err := a.store.SaveConfig(); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	// 关闭时立即停掉 fpm；开启时不动（等首个请求再拉起）
	if !cfg.PHP.Enabled {
		a.php.Stop()
	} else {
		a.php.RebuildPools(a.phpSites())
	}
	a.audit("PHP 配置更新 enabled=%v maxChildren=%d idle=%ds ip=%s",
		cfg.PHP.Enabled, cfg.PHP.MaxChildren, cfg.PHP.IdleStopSecs, remoteIP(r.RemoteAddr))
	writeOK(w, map[string]any{"config": cfg.PHP})
}

func (a *App) handlePHPStop(w http.ResponseWriter, r *http.Request) {
	if a.php != nil {
		a.php.Stop()
	}
	a.audit("手动停止 php-fpm ip=%s", remoteIP(r.RemoteAddr))
	writeOK(w, nil)
}

// phpSites 当前 PHP 站点列表。
func (a *App) phpSites() []*Site {
	var out []*Site
	for _, st := range a.store.Sites() {
		if st.Type == "php" {
			out = append(out, st)
		}
	}
	return out
}

// ---------- 数据库管理 ----------

// dbView 数据库视图（含运行态大小）。
func (a *App) dbView(d *Database) map[string]any {
	v := map[string]any{
		"id": d.ID, "name": d.Name, "user": d.User, "remark": d.Remark,
		"createdAt": d.CreatedAt.Format("2006-01-02 15:04"),
	}
	// 已在运行才查大小（information_schema）；列表展示绝不唤醒 mysqld，未运行显示 "-"
	if a.mysql != nil && a.mysql.Running() {
		if out, err := a.mysql.Exec(
			fmt.Sprintf("SELECT COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables WHERE table_schema='%s'", d.Name)); err == nil {
			var size uint64
			fmt.Sscanf(strings.TrimSpace(out), "%d", &size)
			v["size"] = size
		}
	}
	return v
}

// handleListDBs 数据库列表（附带运行状态）。
func (a *App) handleListDBs(w http.ResponseWriter, r *http.Request) {
	dbs := a.store.Databases()
	list := make([]map[string]any, 0, len(dbs))
	for _, d := range dbs {
		list = append(list, a.dbView(d))
	}
	var st map[string]any
	if a.mysql != nil {
		st = a.mysql.Status()
	} else {
		st = map[string]any{"available": false, "enabled": false}
	}
	writeOK(w, map[string]any{"databases": list, "mysql": st})
}

// handleCreateDB 创建数据库 + 专属账号（自动拉起 mysqld，用完自动回收）。
func (a *App) handleCreateDB(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		User     string `json:"user"`
		Password string `json:"password"`
		Remark   string `json:"remark"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ValidDBName(req.Name); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.User == "" {
		req.User = req.Name
	}
	if err := ValidDBUser(req.User); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ValidDBPassword(req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Remark = strings.TrimSpace(req.Remark)
	if len([]rune(req.Remark)) > 100 {
		writeErr(w, http.StatusBadRequest, "备注最多 100 字")
		return
	}
	if a.store.DBExistsName(req.Name) {
		writeErr(w, http.StatusConflict, "数据库 " + req.Name + " 已存在")
		return
	}
	if a.store.DBExistsUser(req.User) {
		writeErr(w, http.StatusConflict, "账号 " + req.User + " 已存在")
		return
	}
	if a.mysql == nil || a.mysql.binPath == "" {
		writeErr(w, http.StatusBadRequest, "服务器未检测到 mysqld（安装 mariadb / mysql-server 后重启插件）")
		return
	}
	if !a.store.Config().MySQL.Enabled {
		writeErr(w, http.StatusBadRequest, "数据库运行时未启用（先在「数据库设置」中开启）")
		return
	}
	// 执行 SQL（触发按需启动）
	sqls := fmt.Sprintf(
		"CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"+
			"CREATE USER IF NOT EXISTS '%s'@'localhost' IDENTIFIED BY '%s';"+
			"CREATE USER IF NOT EXISTS '%s'@'127.0.0.1' IDENTIFIED BY '%s';"+
			"GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost';"+
			"GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'127.0.0.1';"+
			"FLUSH PRIVILEGES;",
		req.Name, req.User, req.Password, req.User, req.Password,
		req.Name, req.User, req.Name, req.User)
	if _, err := a.mysql.Exec(sqls); err != nil {
		writeErr(w, http.StatusInternalServerError, "创建失败: "+err.Error())
		return
	}
	d := &Database{
		ID: req.Name, Name: req.Name, User: req.User, Password: req.Password,
		Remark: req.Remark, CreatedAt: time.Now(),
	}
	a.store.AddDB(d)
	if err := a.store.SaveDBs(); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	a.audit("创建数据库 %s user=%s ip=%s", req.Name, req.User, remoteIP(r.RemoteAddr))
	writeOK(w, map[string]any{"database": a.dbView(d)})
}

// handleDeleteDB 删除数据库与账号（数据目录同步 DROP）。
func (a *App) handleDeleteDB(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d := a.store.GetDB(id)
	if d == nil {
		writeErr(w, http.StatusNotFound, "数据库不存在")
		return
	}
	if a.mysql != nil && a.store.Config().MySQL.Enabled {
		sqls := fmt.Sprintf(
			"DROP DATABASE IF EXISTS `%s`;DROP USER IF EXISTS '%s'@'localhost';DROP USER IF EXISTS '%s'@'127.0.0.1';FLUSH PRIVILEGES;",
			d.Name, d.User, d.User)
		if _, err := a.mysql.Exec(sqls); err != nil {
			writeErr(w, http.StatusInternalServerError, "删除失败: "+err.Error())
			return
		}
	}
	a.store.RemoveDB(id)
	if err := a.store.SaveDBs(); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	a.audit("删除数据库 %s ip=%s", d.Name, remoteIP(r.RemoteAddr))
	writeOK(w, nil)
}

// handleDBPassword 修改账号密码。
func (a *App) handleDBPassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d := a.store.GetDB(id)
	if d == nil {
		writeErr(w, http.StatusNotFound, "数据库不存在")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ValidDBPassword(req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if a.mysql != nil && a.store.Config().MySQL.Enabled {
		sqls := fmt.Sprintf(
			"ALTER USER '%s'@'localhost' IDENTIFIED BY '%s';ALTER USER '%s'@'127.0.0.1' IDENTIFIED BY '%s';FLUSH PRIVILEGES;",
			d.User, req.Password, d.User, req.Password)
		if _, err := a.mysql.Exec(sqls); err != nil {
			writeErr(w, http.StatusInternalServerError, "修改失败: "+err.Error())
			return
		}
	}
	next := *d
	next.Password = req.Password
	a.store.UpdateDB(id, &next)
	if err := a.store.SaveDBs(); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	a.audit("修改数据库密码 %s ip=%s", d.Name, remoteIP(r.RemoteAddr))
	writeOK(w, nil)
}

// handleMySQLStatus 数据库运行时状态。
func (a *App) handleMySQLStatus(w http.ResponseWriter, r *http.Request) {
	if a.mysql == nil {
		writeOK(w, map[string]any{"available": false, "enabled": false})
		return
	}
	writeOK(w, a.mysql.Status())
}

// handleMySQLConfig 数据库运行时配置（开关 / 空闲回收 / 代理端口）。
func (a *App) handleMySQLConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled      *bool `json:"enabled"`
		IdleStopSecs *int  `json:"idleStopSecs"`
		Port         *int  `json:"port"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Enabled != nil && *req.Enabled {
		if a.mysql == nil || a.mysql.binPath == "" {
			writeErr(w, http.StatusBadRequest, "服务器未检测到 mysqld，无法开启（安装 mariadb 后重启插件）")
			return
		}
	}
	cfg := a.store.Config()
	if req.IdleStopSecs != nil {
		if *req.IdleStopSecs < 30 || *req.IdleStopSecs > 86400 {
			writeErr(w, http.StatusBadRequest, "idleStopSecs 须在 30-86400 秒")
			return
		}
		cfg.MySQL.IdleStopSecs = *req.IdleStopSecs
	}
	if req.Port != nil {
		if !ValidPort(*req.Port) {
			writeErr(w, http.StatusBadRequest, "端口 1-65535")
			return
		}
		if fmt.Sprintf("%d", *req.Port) == a.adminPort || *req.Port == cfg.HTTPPort || *req.Port == cfg.HTTPSPort {
			writeErr(w, http.StatusBadRequest, "端口与面板/站点端口冲突")
			return
		}
		cfg.MySQL.Port = *req.Port
	}
	if req.Enabled != nil {
		cfg.MySQL.Enabled = *req.Enabled
	}
	a.store.SetConfig(cfg)
	if err := a.store.SaveConfig(); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	if a.mysql != nil {
		a.mysql.ApplyConfig() // 重建/撤下唤醒代理；关闭时立即停 mysqld
	}
	a.audit("MySQL 配置更新 enabled=%v port=%d idle=%ds ip=%s",
		cfg.MySQL.Enabled, cfg.MySQL.Port, cfg.MySQL.IdleStopSecs, remoteIP(r.RemoteAddr))
	writeOK(w, map[string]any{"config": cfg.MySQL})
}

func (a *App) handleMySQLStop(w http.ResponseWriter, r *http.Request) {
	if a.mysql != nil {
		a.mysql.Stop()
	}
	a.audit("手动停止 mysqld ip=%s", remoteIP(r.RemoteAddr))
	writeOK(w, nil)
}

// ---------- 端口配置 ----------

func (a *App) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Config()
	writeOK(w, map[string]any{"config": cfg})
}

func (a *App) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HTTPPort  *int    `json:"httpPort"`
		HTTPSPort *int    `json:"httpsPort"`
		BindHTTP  *string `json:"bindHttp"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg := a.store.Config()
	if req.HTTPPort != nil {
		if !ValidPort(*req.HTTPPort) {
			writeErr(w, http.StatusBadRequest, "HTTP 端口 1-65535")
			return
		}
		cfg.HTTPPort = *req.HTTPPort
	}
	if req.HTTPSPort != nil {
		if *req.HTTPSPort != 0 && !ValidPort(*req.HTTPSPort) {
			writeErr(w, http.StatusBadRequest, "HTTPS 端口 1-65535（0 为关闭）")
			return
		}
		cfg.HTTPSPort = *req.HTTPSPort
	}
	if req.BindHTTP != nil {
		b := strings.TrimSpace(*req.BindHTTP)
		if b != "" {
			if ip := net.ParseIP(b); ip == nil && b != "0.0.0.0" {
				writeErr(w, http.StatusBadRequest, "监听地址必须是合法 IP 或 0.0.0.0")
				return
			}
			cfg.BindHTTP = b
		}
	}
	if cfg.HTTPPort == cfg.HTTPSPort && cfg.HTTPSPort != 0 {
		writeErr(w, http.StatusBadRequest, "HTTP 与 HTTPS 端口不能相同")
		return
	}
	if fmt.Sprintf("%d", cfg.HTTPPort) == a.adminPort || fmt.Sprintf("%d", cfg.HTTPSPort) == a.adminPort {
		writeErr(w, http.StatusBadRequest, "端口不能与插件管理端口 " + a.adminPort + " 冲突")
		return
	}
	a.store.SetConfig(cfg)
	if err := a.store.SaveConfig(); err != nil {
		writeErr(w, http.StatusInternalServerError, "保存失败: "+err.Error())
		return
	}
	a.web.applyListeners()
	a.web.StopHTTPSIfDisabled(cfg.HTTPSPort)
	if a.acme != nil {
		a.acme.ApplyConfig() // 主端口变更可能需要补开/关闭 ACME 独立 80 监听
	}
	a.audit("更新端口配置 http=%d https=%d ip=%s", cfg.HTTPPort, cfg.HTTPSPort, remoteIP(r.RemoteAddr))
	httpUp, httpsUp, httpErr, httpsErr := a.web.ListenerStatus()
	writeOK(w, map[string]any{
		"config": cfg, "httpUp": httpUp, "httpsUp": httpsUp,
		"httpErr": httpErr, "httpsErr": httpsErr,
	})
}
