// SPDX-License-Identifier: Apache-2.0
// ACME v2 (RFC 8555) 客户端 + 证书生命周期管理器 —— 纯标准库实现，零第三方依赖。
//
// 能力：
//   - 多家免费 CA：Let's Encrypt（正式/测试）、ZeroSSL、Buypass（正式/测试）、Google Trust Services
//   - HTTP-01 域名验证：由插件自身 Web 服务应答 /.well-known/acme-challenge/（主监听端口 +
//     可选的独立 80 端口监听，二者都拦截在虚拟主机路由之前，跳转/黑名单均不影响验证）
//   - 全自动：一键签发（ECDSA P-256）、到期前自动续期（默认提前 30 天，每 12 小时巡检）
//   - ZeroSSL 支持 API Key 自动获取 EAB；Google / 手动 EAB（kid + hmacKey）
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- CA 目录 ----------

type acmeCA struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	DirURL  string `json:"dirUrl"`
	NeedEAB bool   `json:"needEab"` // 是否必须 EAB（外部账号绑定）
	Note    string `json:"note,omitempty"`
}

// acmeCAs 支持的免费 CA（目录地址均为官方 ACME endpoint）。
var acmeCAs = []acmeCA{
	{ID: "letsencrypt", Name: "Let's Encrypt（推荐，无需注册）",
		DirURL: "https://acme-v02.api.letsencrypt.org/directory"},
	{ID: "le-staging", Name: "Let's Encrypt（测试环境，不限额，浏览器不信任）",
		DirURL: "https://acme-staging-v02.api.letsencrypt.org/directory"},
	{ID: "zerossl", Name: "ZeroSSL（填一次 API Key 即全自动）",
		DirURL: "https://acme.zerossl.com/v2/DV90", NeedEAB: true},
	{ID: "buypass", Name: "Buypass Go SSL（无需注册，挪威 CA）",
		DirURL: "https://api.buypass.com/acme/directory"},
	{ID: "buypass-test", Name: "Buypass（测试环境）",
		DirURL: "https://api.test4.buypass.no/acme/directory"},
	{ID: "google", Name: "Google Trust Services（需 GCP 控制台获取 EAB）",
		DirURL: "https://dv.acme-v02.api.pki.goog/directory", NeedEAB: true},
}

func acmeCAByID(id string) (acmeCA, bool) {
	for _, c := range acmeCAs {
		if c.ID == id {
			return c, true
		}
	}
	return acmeCA{}, false
}

// ---------- JOSE (ES256) 基础件 ----------

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64u(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// jwkJSON 账户公钥的规范 JWK JSON（键序固定，用于 thumbprint 与 EAB 载荷）。
func jwkJSON(pub *ecdsa.PublicKey) []byte {
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return []byte(fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, b64u(x), b64u(y)))
}

// jwkThumbprint RFC 7638。
func jwkThumbprint(pub *ecdsa.PublicKey) string {
	sum := sha256.Sum256(jwkJSON(pub))
	return b64u(sum[:])
}

// signES256Flattened 生成 JWS JSON 扁平序列化（ACME 要求的请求体格式）。
func signES256Flattened(key *ecdsa.PrivateKey, protected, payload []byte) []byte {
	input := b64u(protected) + "." + b64u(payload)
	sum := sha256.Sum256([]byte(input))
	r, s, _ := ecdsa.Sign(rand.Reader, key, sum[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	body := map[string]string{
		"protected":  b64u(protected),
		"payload":    b64u(payload),
		"signature":  b64u(sig),
	}
	out, _ := json.Marshal(body)
	return out
}

// eabJWS 外部账号绑定：用 CA 下发的 HMAC Key（HS256）对账户 JWK 签名（扁平 JSON 格式）。
func eabJWS(kid, hmacKeyB64 string, accountJWK []byte, url string) (string, error) {
	key, err := unb64u(strings.TrimSpace(hmacKeyB64))
	if err != nil {
		if k2, err2 := base64.StdEncoding.DecodeString(strings.TrimSpace(hmacKeyB64)); err2 == nil {
			key = k2
		} else {
			return "", fmt.Errorf("EAB HMAC Key 不是合法 base64")
		}
	}
	protected, _ := json.Marshal(map[string]string{"alg": "HS256", "kid": kid, "url": url})
	input := b64u(protected) + "." + b64u(accountJWK)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(input))
	body := map[string]string{
		"protected": b64u(protected),
		"payload":   b64u(accountJWK),
		"signature": b64u(mac.Sum(nil)),
	}
	out, _ := json.Marshal(body)
	return string(out), nil
}

// ---------- ACME 客户端 ----------

type acmeClient struct {
	dirURL string
	key    *ecdsa.PrivateKey
	kid    string // 账号 URL；空表示未注册
	dir    map[string]string
	nonce  string
	profiles map[string]bool // CA 目录 meta.profiles（空表=未声明，客户端可不用 profile）
	hc     *http.Client
}

func newACMEClient(dirURL string, key *ecdsa.PrivateKey, kid string) *acmeClient {
	return &acmeClient{
		dirURL: dirURL, key: key, kid: kid,
		hc: &http.Client{Timeout: 30 * time.Second},
	}
}

// acmeError 解析 RFC 7807 problem+json。
type acmeError struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func (e *acmeError) Error() string {
	if e.Detail == "" {
		return e.Type
	}
	return e.Detail
}

func (c *acmeClient) fetchDirectory() error {
	resp, body, err := c.httpDo("GET", c.dirURL)
	if err != nil {
		return fmt.Errorf("获取 CA 目录失败: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CA 目录返回 %d: %s", resp.StatusCode, lastLines(body, 2))
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("CA 目录格式异常: %v", err)
	}
	dir := map[string]string{}
	profiles := map[string]bool{}
	for k, v := range raw { // 值可能是 URL 字符串（取用）或对象（如 meta，单独解析）
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			dir[k] = s
			continue
		}
		if k == "meta" { // draft-aaron-acme-profiles：meta.profiles 列出可用 profile
			var meta struct {
				Profiles map[string]json.RawMessage `json:"profiles"`
			}
			if json.Unmarshal(v, &meta) == nil {
				for p := range meta.Profiles {
					profiles[p] = true
				}
			}
		}
	}
	for _, k := range []string{"newNonce", "newAccount", "newOrder"} {
		if dir[k] == "" {
			return fmt.Errorf("CA 目录缺少 %s 端点", k)
		}
	}
	c.dir = dir
	c.profiles = profiles
	return nil
}

// newNonce 取初始 nonce（HEAD）。
func (c *acmeClient) freshNonce() error {
	req, _ := http.NewRequest("HEAD", c.dir["newNonce"], nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		c.nonce = n
		return nil
	}
	return fmt.Errorf("未获取到 nonce")
}

// postJWS 签名请求；payload nil = POST-as-GET。返回响应与响应体。
func (c *acmeClient) postJWS(url string, payload []byte) (*http.Response, []byte, error) {
	if c.dir == nil {
		if err := c.fetchDirectory(); err != nil {
			return nil, nil, err
		}
	}
	var resp *http.Response
	var body []byte
	var err error
	for attempt := 0; attempt < 2; attempt++ { // badNonce 重试一次
		if c.nonce == "" {
			if err := c.freshNonce(); err != nil {
				return nil, nil, err
			}
		}
		header := map[string]any{"alg": "ES256", "nonce": c.nonce, "url": url}
		if c.kid != "" {
			header["kid"] = c.kid
		} else { // 未注册：用 JWK 自证身份
			header["jwk"] = json.RawMessage(jwkJSON(&c.key.PublicKey))
		}
		protected, _ := json.Marshal(header)
		signed := signES256Flattened(c.key, protected, payload) // 注意：不可命名 body，会遮蔽外层返回值
		req, _ := http.NewRequest("POST", url, bytes.NewReader(signed))
		req.Header.Set("Content-Type", "application/jose+json")
		resp, err = c.hc.Do(req)
		if err != nil {
			return nil, nil, err
		}
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if n := resp.Header.Get("Replay-Nonce"); n != "" {
			c.nonce = n
		}
		if resp.StatusCode == http.StatusBadRequest && bytesContainsType(body, "badNonce") {
			c.nonce = ""
			continue
		}
		break
	}
	return resp, body, nil
}

func bytesContainsType(body []byte, sub string) bool {
	return strings.Contains(string(body), sub)
}

func mapKeys(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// ---------- 公网端口连通性检测（check-host.net 多节点探测） ----------

// portCheckResult 单次检测结论。
type portCheckResult struct {
	Host      string `json:"host"`
	Reachable bool   `json:"reachable"`
	Detail    string `json:"detail"`
}

// checkPortOnce 检测 host:port 是否公网可达（多节点 TCP 探测）。
// 第三个返回值 skip=true 表示检测服务不可用，应跳过预检不阻塞签发。
func checkPortOnce(hostport string) (reachable bool, detail string, skip bool) {
	hc := &http.Client{Timeout: 8 * time.Second}
	q := "https://check-host.net/check-tcp?host=" + url.QueryEscape(hostport) + "&max_nodes=2"
	req, _ := http.NewRequest("GET", q, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return false, "", true
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	var init struct {
		RequestID string `json:"request_id"`
		OK        int    `json:"ok"`
	}
	if json.Unmarshal(body, &init) != nil || init.RequestID == "" || init.OK != 1 {
		return false, "", true
	}
	// 轮询探测结果（节点结果为 null 表示进行中）
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(1200 * time.Millisecond)
		req, _ := http.NewRequest("GET", "https://check-host.net/check-result/"+init.RequestID, nil)
		req.Header.Set("Accept", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		var result map[string]json.RawMessage
		if json.Unmarshal(body, &result) != nil {
			continue
		}
		total, okCount := 0, 0
		var errs []string
		for _, raw := range result {
			var arr []map[string]any
			if json.Unmarshal(raw, &arr) != nil || len(arr) == 0 {
				continue // 仍在进行中
			}
			total++
			if _, has := arr[0]["time"]; has {
				okCount++
			} else if e, has := arr[0]["error"].(string); has {
				errs = append(errs, e)
			}
		}
		if total > 0 {
			if okCount > 0 {
				return true, fmt.Sprintf("%d/%d 个探测节点可连通", okCount, total), false
			}
			return false, strings.Join(errs, "; "), false
		}
	}
	return false, "探测超时", true
}

// checkDomainsPort 并发检测多个域名的 80 端口（HTTP-01 验证端口，CA 固定回源 80）。
func checkDomainsPort(domains []string) []portCheckResult {
	results := make([]portCheckResult, len(domains))
	var wg sync.WaitGroup
	for i, d := range domains {
		wg.Add(1)
		go func(i int, d string) {
			defer wg.Done()
			ok, detail, skip := checkPortOnce(d + ":80")
			results[i] = portCheckResult{Host: d, Reachable: ok, Detail: detail}
			if skip {
				results[i].Detail = "检测服务不可用，已跳过"
			}
		}(i, d)
	}
	wg.Wait()
	return results
}

// httpDo 普通请求（目录获取等）。
func (c *acmeClient) httpDo(method, url string) (*http.Response, []byte, error) {
	req, _ := http.NewRequest(method, url, nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, data, nil
}

// problem 解析 RFC 7807 problem+json（附带状态码与原文，便于排障）。
func (c *acmeClient) problem(status int, body []byte) error {
	var pe acmeError
	if err := json.Unmarshal(body, &pe); err == nil && (pe.Type != "" || pe.Detail != "") {
		if pe.Detail == "" {
			pe.Detail = pe.Type
		}
		return fmt.Errorf("HTTP %d: %s", status, pe.Detail)
	}
	return fmt.Errorf("HTTP %d: %s", status, lastLines(body, 2))
}

// register 注册（或已存在时复用）账号；成功后 kid 写回。
func (c *acmeClient) register(email, eabKid, eabHmac string) error {
	payload := map[string]any{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:" + email},
	}
	if eabKid != "" && eabHmac != "" {
		eab, err := eabJWS(eabKid, eabHmac, jwkJSON(&c.key.PublicKey), c.dir["newAccount"])
		if err != nil {
			return err
		}
		payload["externalAccountBinding"] = json.RawMessage(eab)
	}
	pb, _ := json.Marshal(payload)
	resp, body, err := c.postJWS(c.dir["newAccount"], pb)
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK:
		kid := resp.Header.Get("Location")
		if kid == "" {
			return fmt.Errorf("CA 未返回账号地址")
		}
		c.kid = kid
		return nil
	case resp.StatusCode == http.StatusConflict: // 已注册
		kid := resp.Header.Get("Location")
		if kid == "" {
			return fmt.Errorf("账号已存在但未返回地址")
		}
		c.kid = kid
		return nil
	default:
		return fmt.Errorf("账号注册失败: %v", c.problem(resp.StatusCode, body))
	}
}

// acmeOrder 订单。
type acmeOrder struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
	Error          *struct {
		Type   string `json:"type"`
		Detail string `json:"detail"`
	} `json:"error"`
}

// acmeAuthz 验证授权。
type acmeAuthz struct {
	Status     string `json:"status"`
	Identifier struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifier"`
	Challenges []struct {
		Type  string `json:"type"`
		Token string `json:"token"`
		URL   string `json:"url"`
	} `json:"challenges"`
}

// newOrder 创建订单（dns / ip 混合标识符）。返回订单自查 URL（Location 头）与订单对象。
// hasIP：是否含 IP 标识符。LE 的 classic/tlsserver profile 不允许 IP，需请求 shortlived。
func (c *acmeClient) newOrder(idents []acmeIdentifier, hasIP bool) (string, *acmeOrder, error) {
	order := map[string]any{"identifiers": idents}
	if hasIP {
		if len(c.profiles) > 0 && !c.profiles["shortlived"] {
			return "", nil, fmt.Errorf("该 CA 不支持 IP 地址证书（可用 profile: %v）", mapKeys(c.profiles))
		}
		if c.profiles["shortlived"] {
			order["profile"] = "shortlived" // 唯一支持 IP 的 profile（证书有效期约 6 天）
		}
		// profiles 为空（如部分 CA 未实现 draft）：直接尝试不带 profile 下单，由 CA 裁决
	}
	pb, _ := json.Marshal(order)
	resp, body, err := c.postJWS(c.dir["newOrder"], pb)
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode != http.StatusCreated {
		return "", nil, fmt.Errorf("创建订单失败: %v", c.problem(resp.StatusCode, body))
	}
	var o acmeOrder
	if err := json.Unmarshal(body, &o); err != nil {
		return "", nil, err
	}
	orderURL := resp.Header.Get("Location")
	if orderURL == "" {
		return "", nil, fmt.Errorf("CA 未返回订单地址")
	}
	return orderURL, &o, nil
}

type acmeIdentifier struct {
	Type  string `json:"type"` // "dns" | "ip"
	Value string `json:"value"`
}

// getAuthz 拉取授权详情。
func (c *acmeClient) getAuthz(url string) (*acmeAuthz, error) {
	resp, body, err := c.postJWS(url, nil) // POST-as-GET
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取验证详情失败: %v", c.problem(resp.StatusCode, body))
	}
	var a acmeAuthz
	if err := json.Unmarshal(body, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// answerChallenge 应答 HTTP-01 challenge。
func (c *acmeClient) answerChallenge(url string) error {
	pb, _ := json.Marshal(map[string]any{})
	resp, body, err := c.postJWS(url, pb)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("应答验证失败: %v", c.problem(resp.StatusCode, body))
	}
	return nil
}

// pollOrder 轮询订单状态直至目标态或超时。
func (c *acmeClient) pollOrder(url string, want []string, timeout time.Duration) (*acmeOrder, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, body, err := c.postJWS(url, nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("查询订单失败: %v", c.problem(resp.StatusCode, body))
		}
		var o acmeOrder
		if err := json.Unmarshal(body, &o); err != nil {
			return nil, err
		}
		if o.Error != nil {
			return nil, fmt.Errorf("订单失败: %s", o.Error.Detail)
		}
		for _, w := range want {
			if o.Status == w {
				return &o, nil
			}
		}
		if o.Status == "invalid" {
			return nil, fmt.Errorf("订单被拒绝（status=invalid，常见原因：80 端口不可达 / 域名未解析到本机）")
		}
		time.Sleep(2 * time.Second)
	}
	return nil, fmt.Errorf("等待 CA 校验超时")
}

// finalize 提交 CSR。
func (c *acmeClient) finalize(url string, csrDER []byte) error {
	pb, _ := json.Marshal(map[string]string{"csr": b64u(csrDER)})
	resp, body, err := c.postJWS(url, pb)
	if err != nil {
		return err
	}
	// 200（处理中）或 201 均为受理
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("提交 CSR 失败: %v", c.problem(resp.StatusCode, body))
	}
	return nil
}

// downloadCert 下载证书链（PEM）。
func (c *acmeClient) downloadCert(url string) ([]byte, error) {
	resp, body, err := c.postJWS(url, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("下载证书失败: %v", c.problem(resp.StatusCode, body))
	}
	if !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		return nil, fmt.Errorf("CA 返回内容不是 PEM 证书")
	}
	return body, nil
}

// ---------- 证书管理器 ----------

type acmeAccount struct {
	KID       string    `json:"kid"`
	CreatedAt time.Time `json:"createdAt"`
}

type ACMEManager struct {
	app *App

	mu  sync.Mutex // 串行化签发/注册（同一时间最多一个 ACME 流程）
	busy atomic.Bool

	chMu       sync.RWMutex
	challenges map[string]string // token -> keyAuth（HTTP-01 应答表）

	lnMu   sync.Mutex
	ln     net.Listener
	lnPort int
	lnErr  string

	lastRenew map[string]string // siteID -> 结果描述（展示用）
	lrMu      sync.Mutex        // lastRenew 专用小锁（避免读状态被长时签发阻塞）
	stopCh    chan struct{}
}

func NewACMEManager(app *App) *ACMEManager {
	m := &ACMEManager{
		app:       app,
		challenges: map[string]string{},
		lastRenew: map[string]string{},
		stopCh:    make(chan struct{}),
	}
	m.applyListener()
	go m.renewLoop()
	return m
}

// applyListener 按配置维护独立 HTTP-01 监听（默认 80，供 CA 回源验证）。
func (m *ACMEManager) applyListener() {
	cfg := m.app.store.Config()
	want := 0
	if cfg.ACME.HTTPPort > 0 && cfg.ACME.HTTPPort != cfg.HTTPPort {
		want = cfg.ACME.HTTPPort
	}
	m.lnMu.Lock()
	defer m.lnMu.Unlock()
	if m.ln != nil && (want == 0 || m.lnPort != want) {
		_ = m.ln.Close()
		m.ln = nil
		m.lnErr = ""
	}
	if want == 0 {
		if m.ln == nil && cfg.ACME.HTTPPort == cfg.HTTPPort {
			m.lnErr = "" // 主监听即验证端口
		}
		return
	}
	if m.ln != nil {
		return
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.BindHTTP, want))
	if err != nil {
		m.lnErr = fmt.Sprintf("HTTP-01 监听 %d 绑定失败: %v（若主监听端口已对公网开放 80 转发则不影响）", want, err)
		log.Printf("[web-manager] %s", m.lnErr)
		return
	}
	m.ln = ln
	m.lnPort = want
	m.lnErr = ""
	log.Printf("[web-manager] ACME HTTP-01 验证监听已启动 %s:%d", cfg.BindHTTP, want)
	go func() {
		srv := &http.Server{Handler: m.auxHandler(), ReadHeaderTimeout: 10 * time.Second}
		_ = srv.Serve(ln)
	}()
}

// auxHandler 独立端口：ACME 验证优先，其余请求转主 Web 服务（端口 80 行为与主端口一致）。
func (m *ACMEManager) auxHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isACMEChallengePath(r.URL.Path) {
			m.ServeChallenge(w, r)
			return
		}
		if m.app.web != nil {
			m.app.web.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

func isACMEChallengePath(p string) bool {
	return strings.HasPrefix(p, "/.well-known/acme-challenge/")
}

// ApplyConfig 设置变更后重建监听。
func (m *ACMEManager) ApplyConfig() { m.applyListener() }

// ---------- HTTP-01 应答 ----------

func (m *ACMEManager) setChallenge(token, keyAuth string) {
	m.chMu.Lock()
	m.challenges[token] = keyAuth
	m.chMu.Unlock()
}

func (m *ACMEManager) delChallenges(tokens []string) {
	m.chMu.Lock()
	for _, t := range tokens {
		delete(m.challenges, t)
	}
	m.chMu.Unlock()
}

// ServeChallenge 应答 /.well-known/acme-challenge/<token>。
func (m *ACMEManager) ServeChallenge(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	if token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}
	m.chMu.RLock()
	ka, ok := m.challenges[token]
	m.chMu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(ka))
}

// ---------- 账号 ----------

func (m *ACMEManager) acctDir() string  { return filepath.Join(m.app.etcDir, "acme") }
func (m *ACMEManager) acctKeyPath() string { return filepath.Join(m.acctDir(), "account.key") }
func (m *ACMEManager) acctsPath() string { return filepath.Join(m.acctDir(), "accounts.json") }

// loadAccountKey 全局一把账户私钥（各 CA 通用）。
func (m *ACMEManager) loadAccountKey() (*ecdsa.PrivateKey, error) {
	if err := os.MkdirAll(m.acctDir(), 0o700); err != nil {
		return nil, err
	}
	if data, err := os.ReadFile(m.acctKeyPath()); err == nil {
		blk, _ := pem.Decode(data)
		if blk != nil {
			if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
				return k, nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(m.acctKeyPath(), pemData, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func (m *ACMEManager) loadAccounts() map[string]acmeAccount {
	out := map[string]acmeAccount{}
	data, err := os.ReadFile(m.acctsPath())
	if err == nil {
		_ = json.Unmarshal(data, &out)
	}
	return out
}

func (m *ACMEManager) saveAccounts(accts map[string]acmeAccount) error {
	data, err := json.MarshalIndent(accts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.acctsPath(), data, 0o600)
}

// clientFor 为指定 CA 取已注册客户端（无账号则现场注册）。
func (m *ACMEManager) clientFor(ca acmeCA) (*acmeClient, error) {
	key, err := m.loadAccountKey()
	if err != nil {
		return nil, fmt.Errorf("账户密钥加载失败: %v", err)
	}
	cfg := m.app.store.Config().ACME
	accts := m.loadAccounts()
	c := newACMEClient(ca.DirURL, key, accts[ca.ID].KID)
	if err := c.fetchDirectory(); err != nil {
		return nil, err
	}
	if c.kid == "" {
		eabKid, eabHmac := cfg.EABKid, cfg.EABHmacKey
		if ca.ID == "zerossl" && cfg.ZeroSSLAPIKey != "" { // ZeroSSL：API Key 自动换 EAB
			k, h, err := zerosslFetchEAB(cfg.ZeroSSLAPIKey)
			if err != nil {
				return nil, fmt.Errorf("ZeroSSL EAB 获取失败: %v", err)
			}
			eabKid, eabHmac = k, h
		}
		if ca.NeedEAB && eabKid == "" {
			return nil, fmt.Errorf("%s 需要 EAB 凭据（ZeroSSL 填 API Key 自动获取，Google 填控制台生成的 EAB）", ca.Name)
		}
		if err := c.register(cfg.Email, eabKid, eabHmac); err != nil {
			return nil, err
		}
		accts[ca.ID] = acmeAccount{KID: c.kid, CreatedAt: time.Now()}
		_ = m.saveAccounts(accts)
		log.Printf("[web-manager] ACME 账号注册成功 ca=%s", ca.ID)
	}
	return c, nil
}

// zerosslFetchEAB 用 API Key 自动获取 EAB 凭据。
func zerosslFetchEAB(apiKey string) (kid, hmacKey string, err error) {
	hc := &http.Client{Timeout: 20 * time.Second}
	resp, err := hc.Get("https://api.zerossl.com/acme/eab-credentials?access_key=" + apiKey)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r struct {
		Success bool   `json:"success"`
		KID     string `json:"eab_kid"`
		HMAC    string `json:"eab_hmac_key"`
		Error   struct {
			Code int    `json:"code"`
			Info string `json:"info"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", "", fmt.Errorf("响应解析失败")
	}
	if !r.Success {
		return "", "", fmt.Errorf("API Key 无效或请求被拒（%s）", r.Error.Info)
	}
	return r.KID, r.HMAC, nil
}

// ---------- 签发 ----------

// Issue 为站点签发/续期证书（同步，串行）。
func (m *ACMEManager) Issue(siteID string) (*Site, error) {
	if m.busy.CompareAndSwap(false, true) {
		defer m.busy.Store(false)
	} else {
		return nil, fmt.Errorf("已有证书流程进行中，请稍后再试")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	st := m.app.store.Get(siteID)
	if st == nil {
		return nil, fmt.Errorf("站点不存在")
	}
	cfg := m.app.store.Config()
	ca, ok := acmeCAByID(cfg.ACME.Provider)
	if !ok {
		return nil, fmt.Errorf("未选择有效的证书 CA")
	}
	if cfg.ACME.Email == "" || !strings.Contains(cfg.ACME.Email, "@") {
		return nil, fmt.Errorf("请先在「SSL 证书」设置中填写邮箱")
	}
	// 标识符：IP 直连用 ip 类型，域名用 dns；通配符需 DNS-01，不支持
	var idents []acmeIdentifier
	var wilds []string
	hasIP := false
	for _, d := range st.Domains {
		if strings.HasPrefix(d, "*.") {
			wilds = append(wilds, d)
			continue
		}
		if addr, err := netip.ParseAddr(d); err == nil {
			idents = append(idents, acmeIdentifier{Type: "ip", Value: addr.String()})
			hasIP = true
		} else {
			idents = append(idents, acmeIdentifier{Type: "dns", Value: d})
		}
	}
	if len(idents) == 0 {
		return nil, fmt.Errorf("通配符域名 %s 需要 DNS 验证，暂不支持自动申请（请手动上传证书）", strings.Join(wilds, "、"))
	}
	if hasIP {
		log.Printf("[web-manager] 含 IP 标识符，尝试 shortlived profile（LE 专属，证书有效期约 6 天）")
	}

	// 0. 预检：HTTP-01 要求 CA 能从公网访问各域名的 80 端口（NAT 未映射是最常见故障）
	var checkHosts []string
	for _, id := range idents {
		checkHosts = append(checkHosts, id.Value)
	}
	if results := checkDomainsPort(checkHosts); len(results) > 0 {
		var bad []string
		for _, r := range results {
			if !r.Reachable && !strings.Contains(r.Detail, "已跳过") {
				bad = append(bad, fmt.Sprintf("%s（%s）", r.Host, r.Detail))
			}
		}
		if len(bad) > 0 {
			return nil, fmt.Errorf("公网 80 端口不可达：%s —— CA 无法完成 HTTP-01 验证。请先在服务器/云服务商处放行并转发 80 端口（NAT 环境需映射外部 80 → 本机 80）", strings.Join(bad, "、"))
		}
	}

	client, err := m.clientFor(ca)
	if err != nil {
		return nil, err
	}

	// 1. 下单
	orderURL, order, err := client.newOrder(idents, hasIP)
	if err != nil {
		return nil, err
	}

	// 2. 应答全部 HTTP-01 challenge
	var tokens []string
	defer func() { m.delChallenges(tokens) }() // 闭包：捕获循环追加后的最终切片
	for _, au := range order.Authorizations {
		authz, err := client.getAuthz(au)
		if err != nil {
			return nil, err
		}
		if authz.Status == "valid" {
			continue // 续期时已验证过的域名
		}
		var chURL, token string
		for _, ch := range authz.Challenges {
			if ch.Type == "http-01" && ch.Token != "" {
				chURL, token = ch.URL, ch.Token
				break
			}
		}
		if chURL == "" {
			return nil, fmt.Errorf("CA 未提供 HTTP-01 验证（域名 %s）", authz.Identifier.Value)
		}
		m.setChallenge(token, token+"."+jwkThumbprint(&client.key.PublicKey))
		tokens = append(tokens, token)
		if err := client.answerChallenge(chURL); err != nil {
			return nil, err
		}
	}

	// 3. 等待校验通过
	if _, err = client.pollOrder(orderURL, []string{"ready", "valid"}, 45*time.Second); err != nil {
		return nil, err
	}

	// 4. 生成私钥 + CSR（ECDSA P-256）
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr := &x509.CertificateRequest{Subject: pkix.Name{CommonName: idents[0].Value}}
	for _, id := range idents {
		if id.Type == "dns" {
			csr.DNSNames = append(csr.DNSNames, id.Value)
		} else {
			if a, err := netip.ParseAddr(id.Value); err == nil {
				csr.IPAddresses = append(csr.IPAddresses, net.IP(a.AsSlice()))
			}
		}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csr, certKey)
	if err != nil {
		return nil, fmt.Errorf("生成 CSR 失败: %v", err)
	}
	if err := client.finalize(order.Finalize, csrDER); err != nil {
		return nil, err
	}

	// 5. 等签发 + 取证书
	order, err = client.pollOrder(orderURL, []string{"valid"}, 45*time.Second)
	if err != nil {
		return nil, err
	}
	certURL := order.Certificate
	if certURL == "" {
		return nil, fmt.Errorf("订单已通过但未返回证书地址")
	}
	certPEM, err := client.downloadCert(certURL)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// 6. 校验并落盘
	leaf, err := validatePair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("CA 返回证书无效: %v", err)
	}
	dir := filepath.Join(m.app.certDir, st.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(dir, "cert.pem"), certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(dir, "key.pem"), keyPEM, 0o600); err != nil {
		return nil, err
	}

	// 7. 更新站点记录 + 热加载
	next := *st
	next.HasSSL = true
	sslDomains := append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		sslDomains = append(sslDomains, ip.String())
	}
	next.SSLDomains = sslDomains
	next.SSLNotBefore = leaf.NotBefore
	next.SSLNotAfter = leaf.NotAfter
	next.SSLAuto = true
	next.SSLProvider = ca.ID
	m.app.store.Update(st.ID, &next)
	if err := m.app.store.SaveSites(); err != nil {
		return nil, err
	}
	m.app.web.Reload(m.app.store.Sites())
	m.app.audit("自动签发证书 site=%s ca=%s domains=%v 到期=%s", st.ID, ca.ID, sslDomains, leaf.NotAfter.Format("2006-01-02"))
	log.Printf("[web-manager] 证书签发成功 site=%s ca=%s 到期=%s", st.ID, ca.ID, leaf.NotAfter.Format("2006-01-02"))
	return &next, nil
}

// ---------- 工具 ----------

// validatePair 解析并校验证书/私钥配对，返回叶证书。
func validatePair(certPEM, keyPEM []byte) (*x509.Certificate, error) {
	leaf, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, errors.New("私钥 PEM 无效")
	}
	var key *ecdsa.PrivateKey
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		key = k
	} else if k, err2 := x509.ParsePKCS8PrivateKey(blk.Bytes); err2 == nil {
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("仅支持 ECDSA 私钥")
		}
		key = ek
	} else {
		return nil, errors.New("私钥解析失败")
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.X.Cmp(key.PublicKey.X) != 0 || pub.Y.Cmp(key.PublicKey.Y) != 0 {
		return nil, errors.New("证书与私钥不配对")
	}
	return leaf, nil
}

// parseCertPEM 取 PEM 链中的第一张证书。
func parseCertPEM(pemData []byte) (*x509.Certificate, error) {
	rest := pemData
	for {
		blk, remain := pem.Decode(rest)
		if blk == nil {
			break
		}
		rest = remain
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	return nil, errors.New("PEM 中未找到证书")
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Register 仅注册/校验当前 CA 账号（设置界面「验证账号」按钮）。
func (m *ACMEManager) Register() (map[string]any, error) {
	if !m.busy.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("已有证书流程进行中")
	}
	defer m.busy.Store(false)
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg := m.app.store.Config()
	ca, ok := acmeCAByID(cfg.ACME.Provider)
	if !ok {
		return nil, fmt.Errorf("未选择有效的证书 CA")
	}
	if cfg.ACME.Email == "" || !strings.Contains(cfg.ACME.Email, "@") {
		return nil, fmt.Errorf("请先填写邮箱")
	}
	if ca.NeedEAB && ca.ID == "zerossl" && cfg.ACME.ZeroSSLAPIKey == "" && cfg.ACME.EABKid == "" {
		return nil, fmt.Errorf("ZeroSSL 需要填写 API Key（自动获取 EAB）或手动 EAB")
	}
	if ca.NeedEAB && ca.ID == "google" && cfg.ACME.EABKid == "" {
		return nil, fmt.Errorf("Google Trust Services 需要在 GCP 控制台生成 EAB 后填入")
	}
	c, err := m.clientFor(ca)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ca": ca.ID, "kid": c.kid}, nil
}

// ---------- 自动续期 ----------

func (m *ACMEManager) renewLoop() {
	select {
	case <-time.After(3 * time.Minute): // 启动后 3 分钟先巡检一轮
	case <-m.stopCh:
		return
	}
	m.RenewDue()
	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			m.RenewDue()
		case <-m.stopCh:
			return
		}
	}
}

// renewThreshold 计算续期阈值：常规证书用配置天数；
// 短周期证书（如 LE shortlived 约 6 天）按有效期 60% 截断，避免“永远到期”死循环。
func renewThreshold(cfgRenewDays int, lifetime time.Duration) time.Duration {
	th := time.Duration(cfgRenewDays) * 24 * time.Hour
	if th <= 0 {
		th = 30 * 24 * time.Hour
	}
	if lifetime > 0 {
		if adaptive := lifetime * 6 / 10; adaptive < th {
			th = adaptive
		}
	}
	return th
}

// RenewDue 巡检：SSLAuto 且剩余天数 < 阈值（或证书文件缺失）的站点自动续期。
func (m *ACMEManager) RenewDue() map[string]string {
	cfg := m.app.store.Config()
	if !cfg.ACME.AutoRenew {
		return map[string]string{}
	}
	out := map[string]string{}
	for _, st := range m.app.store.Sites() {
		if !st.SSLAuto || !st.HasSSL {
			continue
		}
		lifetime := st.SSLNotAfter.Sub(st.SSLNotBefore)
		threshold := renewThreshold(cfg.ACME.RenewDays, lifetime)
		due := time.Until(st.SSLNotAfter) < threshold
		if !due {
			if _, err := os.Stat(filepath.Join(m.app.certDir, st.ID, "cert.pem")); os.IsNotExist(err) {
				due = true // 证书文件丢了也要补
			}
		}
		if !due {
			continue
		}
		log.Printf("[web-manager] 证书续期开始 site=%s 剩余 %.1f 天（有效期 %.1f 天，阈值 %.1f 天）",
			st.ID, time.Until(st.SSLNotAfter).Hours()/24, lifetime.Hours()/24, threshold.Hours()/24)
		if _, err := m.Issue(st.ID); err != nil {
			log.Printf("[web-manager] 证书续期失败 site=%s: %v", st.ID, err)
			out[st.ID] = "失败: " + err.Error()
		} else {
			out[st.ID] = "已续期 " + time.Now().Format("01-02 15:04")
		}
	}
	m.lrMu.Lock()
	m.lastRenew = out
	m.lrMu.Unlock()
	return out
}

// ---------- 状态 ----------

func (m *ACMEManager) Status() map[string]any {
	cfg := m.app.store.Config().ACME
	accts := m.loadAccounts()
	accView := map[string]any{}
	for id, a := range accts {
		accView[id] = map[string]any{"createdAt": a.CreatedAt.Format("2006-01-02 15:04")}
	}
	m.lnMu.Lock()
	listening := m.ln != nil
	lnErr := m.lnErr
	port := m.lnPort
	m.lnMu.Unlock()
	if port == 0 {
		port = cfg.HTTPPort
	}
	if !listening && cfg.HTTPPort == m.app.store.Config().HTTPPort {
		lnErr = "" // 主监听端口本身就是验证端口
	}
	m.lrMu.Lock()
	lrCopy := map[string]string{}
	for k, v := range m.lastRenew {
		lrCopy[k] = v
	}
	m.lrMu.Unlock()
	return map[string]any{
		"providers": acmeCAs,
		"config": map[string]any{
			"provider": cfg.Provider, "email": cfg.Email,
			"zeroSslApiKey": cfg.ZeroSSLAPIKey, "eabKid": cfg.EABKid,
			"httpPort": cfg.HTTPPort, "autoRenew": cfg.AutoRenew, "renewDays": cfg.RenewDays,
		},
		"accounts":  accView,
		"http01":    map[string]any{"port": port, "listening": listening, "err": lnErr},
		"busy":      m.busy.Load(),
		"lastRenew": lrCopy,
	}
}

// Stop 优雅退出。
func (m *ACMEManager) Stop() {
	close(m.stopCh)
	m.lnMu.Lock()
	if m.ln != nil {
		_ = m.ln.Close()
	}
	m.lnMu.Unlock()
}

