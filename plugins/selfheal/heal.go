package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config 自愈守护配置
type Config struct {
	Enabled bool `json:"enabled"` // 总开关

	// 攻击判定
	AttackQPS       int     `json:"attack_qps"`        // 攻击速度阈值：WAF qps >= 此值视为被攻击
	AttackPerMinute int     `json:"attack_per_minute"` // 攻击量阈值：每分钟新增拦截/请求数 >= 此值视为被攻击
	AttackMode      bool    `json:"attack_on_guard"`   // 是否把 WAF 处于 guard/mode 视为攻击
	SustainSecs     int     `json:"sustain_secs"`      // 持续被攻击多少秒才触发熔断

	// 熔断
	CircuitBreakOn bool     `json:"circuit_break_on"` // 熔断开关
	TargetPlugins  []string `json:"target_plugins"`   // 被熔断关闭的插件(默认 cf-tunnel / web-manager)
	DownSecs       int      `json:"down_secs"`        // 熔断关闭持续秒数, 之后自动拉起

	// WAF 自愈
	MemRestartOn bool    `json:"mem_restart_on"` // 内存自愈开关
	MaxRSSMB     float64 `json:"max_rss_mb"`     // WAF 内存阈值(>此值且无攻击→重启 WAF)

	// 运行时
	WAFAPIBase string `json:"waf_api_base"` // WAF 管理接口, 如 http://127.0.0.1:19002
	PanelBase  string `json:"panel_base"`   // 面板 API, 如 http://127.0.0.1:8848
	AuthUser   string `json:"auth_user"`    // 面板登录账号
	AuthPass   string `json:"auth_pass"`    // 面板登录密码
}

func DefaultConfig() *Config {
	return &Config{
		Enabled:         false,
		AttackQPS:       200,
		AttackPerMinute: 2000,
		AttackMode:      true,
		SustainSecs:     15,
		CircuitBreakOn:  true,
		TargetPlugins:   []string{"cf-tunnel", "web-manager"},
		DownSecs:        90,
		MemRestartOn:    true,
		MaxRSSMB:        20,
		WAFAPIBase:      "http://127.0.0.1:19002",
		PanelBase:       "http://127.0.0.1:8848",
		AuthUser:        "root",
		AuthPass:        "",
	}
}

func (c *Config) Sanitize() {
	if c.SustainSecs < 3 {
		c.SustainSecs = 3
	}
	if c.DownSecs < 10 {
		c.DownSecs = 10
	}
	if c.AttackQPS <= 0 {
		c.AttackQPS = 200
	}
	if c.MaxRSSMB <= 0 {
		c.MaxRSSMB = 20
	}
	if len(c.TargetPlugins) == 0 {
		c.TargetPlugins = []string{"cf-tunnel", "web-manager"}
	}
	if c.AuthUser == "" {
		c.AuthUser = "root"
	}
}

// State 运行状态(供设置页展示)
type State struct {
	LastCheck  string `json:"last_check"`
	EnablingOn bool   `json:"enabling_on"`
	// WAF 视角
	WAFQPS      int     `json:"waf_qps"`
	WAFTotal    int     `json:"waf_total"`
	WAFBlocked  int     `json:"waf_blocked"`
	WAFMode     string  `json:"waf_mode"`
	WAFRSS      float64 `json:"waf_rss_mb"`
	AttackNow   bool    `json:"attack_now"`
	SustainSeen int     `json:"sustain_seen"`
	// 熔断状态
	CircuitOpen   bool   `json:"circuit_open"`
	CircuitTarget string `json:"circuit_target"`
	DownUntil     string `json:"down_until"`
	DownLeftSecs  int    `json:"down_left_secs"`
	// 自愈
	LastRestart string `json:"last_restart"`
	LastBreak   string `json:"last_break"`
	LastRecover string `json:"last_recover"`
	LastError   string `json:"last_error"`
}

// Healer 核心守护
type Healer struct {
	mu            sync.Mutex
	srv           *Server
	checkInterval time.Duration

	// 累计计数器
	lastTotal int
	lastBlock int
	lastAt    time.Time

	sustainHit   int
	circuitOpen  bool
	circuitUntil time.Time
	restartedAt  time.Time
}

func (h *Healer) TriggerRecheck() { /* 配置更新即时生效, 下一轮即应用 */ }

// loop 周期巡检
func (h *Healer) loop(stop <-chan struct{}) {
	tick := time.NewTicker(h.checkInterval)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			h.Check()
		case <-stop:
			return
		}
	}
}

// Check 单轮巡检
func (h *Healer) Check() {
	h.mu.Lock()
	cfg := *h.srv.cfg
	h.mu.Unlock()

	h.setState(func(s *State) { s.EnablingOn = cfg.Enabled })

	// 面板凭据未配置则跳过
	if !cfg.Enabled {
		return
	}
	if !cfg.CircuitBreakOn && !cfg.MemRestartOn {
		return
	}

	// 读取 WAF 攻击统计
	waf := h.fetchWAF(cfg.WAFAPIBase)
	attack := h.evaluateAttack(cfg, waf)

	// 1) 熔断逻辑
	if cfg.CircuitBreakOn {
		h.runCircuit(cfg, attack)
	}
	// 2) WAF 内存自愈
	if cfg.MemRestartOn {
		h.runMemRestart(cfg, attack, waf)
	}
}

// fetchWAF 拉取 waf 攻击统计
func (h *Healer) fetchWAF(base string) wafStatus {
	var s wafStatus
	resp, err := http.Get(strings.TrimRight(base, "/") + "/api/status")
	if err != nil {
		h.setErrf("读取WAF失败: %v", err)
		return s
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	json.Unmarshal(b, &s)
	return s
}

type wafStatus struct {
	Mode        string        `json:"mode"`
	GuardRemain int           `json:"guard_remain"`
	Stats       wafStats      `json:"stats"`
	ThreatIntel threatIntel   `json:"threat_intel"`
	Time        string        `json:"time"`
	Extra       interface{}   `json:"-"`
}

type wafStats struct {
	Blocked     int      `json:"blocked"`
	Challenged  int      `json:"challenged"`
	Escalations int      `json:"escalations"`
	Monitored   int      `json:"monitored"`
	QPS         int      `json:"qps"`
	RSSMB       float64  `json:"rss_mb"`
	TopIPs      []string `json:"top_ips"`
	TopRules    []string `json:"top_rules"`
	Total       int      `json:"total"`
	Uptime      int      `json:"uptime"`
}

type threatIntel struct {
	Count   int    `json:"count"`
	Err     string `json:"err"`
	Updated string `json:"updated"`
}

// evaluateAttack 判定是否被攻击
func (h *Healer) evaluateAttack(cfg Config, w wafStatus) bool {
	qps := w.Stats.QPS
	now := time.Now()
	// 攻击量增量/分钟
	addedPerMin := 0
	if !h.lastAt.IsZero() {
		dt := now.Sub(h.lastAt).Seconds()
		if dt > 0 {
			addedPerMin = int(float64(w.Stats.Blocked-h.lastBlock) / dt * 60)
		}
	}
	h.lastAt = now
	h.lastTotal = w.Stats.Total
	h.lastBlock = w.Stats.Blocked

	h.setState(func(s *State) {
		s.WAFQPS = qps
		s.WAFTotal = w.Stats.Total
		s.WAFBlocked = w.Stats.Blocked
		s.WAFMode = w.Mode
		s.WAFRSS = w.Stats.RSSMB
	})

	attacked := false
	if cfg.AttackQPS > 0 && qps >= cfg.AttackQPS {
		attacked = true
	}
	if cfg.AttackPerMinute > 0 && addedPerMin >= cfg.AttackPerMinute {
		attacked = true
	}
	if cfg.AttackMode && (w.Mode == "guard" || w.Mode == "block" || w.Mode == "hard") {
		attacked = true
	}

	// 连续攻击计数
	if attacked {
		h.sustainHit++
	} else {
		h.sustainHit = 0
	}
	hit := h.sustainHit >= maxI(1, cfg.SustainSecs/int(h.checkInterval.Seconds()))
	h.setState(func(s *State) { s.AttackNow = attacked; s.SustainSeen = h.sustainHit })
	return hit
}

// runCircuit 熔断：攻击持续达标 → 关闭目标插件; down_secs 后自动拉起
func (h *Healer) runCircuit(cfg Config, attack bool) {
	// 若熔断已打开：检查是否到拉起时间
	if h.circuitOpen {
		left := time.Until(h.circuitUntil)
		h.setState(func(s *State) {
			s.CircuitOpen = true
			s.DownUntil = h.circuitUntil.Format("15:04:05")
			s.DownLeftSecs = int(left.Seconds())
		})
		if time.Now().Before(h.circuitUntil) {
			return // 还在熔断期
		}
		// 到期自动拉起
		h.recoverTargets(cfg)
		h.circuitOpen = false
		h.setState(func(s *State) { s.CircuitOpen = false; s.DownLeftSecs = 0 })
		return
	}

	// 触发熔断
	if attack {
		h.tripTargets(cfg)
		h.circuitOpen = true
		h.circuitUntil = time.Now().Add(time.Duration(cfg.DownSecs) * time.Second)
		h.setState(func(s *State) {
			s.CircuitOpen = true
			s.LastBreak = time.Now().Format("15:04:05")
			s.DownUntil = h.circuitUntil.Format("15:04:05")
			s.DownLeftSecs = cfg.DownSecs
		})
		return
	}
	// 无攻击且未熔断: 确保目标在线(兜底拉起)
	h.setState(func(s *State) { s.CircuitOpen = false })
}

// tripTargets 关闭目标插件
func (h *Healer) tripTargets(cfg Config) {
	for _, name := range cfg.TargetPlugins {
		out, err := h.panelAction(cfg, name, "stop")
		h.setState(func(s *State) {
			s.CircuitTarget = name
			s.LastError = ""
		})
		if err != nil {
			h.setState(func(s *State) { s.LastError = "停" + name + ": " + err.Error() + " " + out })
		}
	}
}

// recoverTargets 拉起目标插件
func (h *Healer) recoverTargets(cfg Config) {
	for _, name := range cfg.TargetPlugins {
		out, err := h.panelAction(cfg, name, "start")
		if err != nil {
			h.setState(func(s *State) { s.LastError = "起" + name + ": " + err.Error() + " " + out })
		}
	}
	h.setState(func(s *State) { s.LastRecover = time.Now().Format("15:04:05"); s.CircuitTarget = "" })
}

// runMemRestart WAF 内存自愈: > max_rss_mb 且无攻击 → 重启 WAF
func (h *Healer) runMemRestart(cfg Config, attack bool, w wafStatus) {
	rss := w.Stats.RSSMB
	if rss <= cfg.MaxRSSMB {
		h.setState(func(s *State) { s.WAFRSS = rss })
		return
	}
	// 内存超限
	if attack {
		// 正在被攻击, 不重启(避免中断防护)
		h.setState(func(s *State) { s.WAFRSS = rss })
		return
	}
	// 内存超限且无攻击 → 重启 WAF
	cooldown := time.Since(h.restartedAt)
	if cooldown < 120*time.Second {
		return // 冷却期内不重复重启
	}
	out, err := h.panelAction(cfg, "waf", "restart")
	h.restartedAt = time.Now()
	if err != nil {
		h.setState(func(s *State) { s.LastError = "重启WAF: " + err.Error() + " " + out })
		return
	}
	h.setState(func(s *State) { s.LastRestart = time.Now().Format("15:04:05") })
}

// panelAction 调用面板 API 控制插件
func (h *Healer) panelAction(cfg Config, plugin, action string) (string, error) {
	base := strings.TrimRight(cfg.PanelBase, "/")
	client := &http.Client{Timeout: 10 * time.Second}
	jar := &cookieJar{cookies: map[string]string{}}

	// 登录
	loginBody, _ := json.Marshal(map[string]string{"username": cfg.AuthUser, "password": cfg.AuthPass})
	lreq, _ := http.NewRequest("POST", base+"/api/login", bytes.NewReader(loginBody))
	lreq.Header.Set("Content-Type", "application/json")
	lresp, err := client.Do(lreq)
	if err != nil {
		return "", err
	}
	jar.capture(lresp.Cookies())
	io.Copy(io.Discard, lresp.Body)
	lresp.Body.Close()

	// 执行动作
	areq, _ := http.NewRequest("POST", base+"/api/plugins/"+plugin+"/"+action, nil)
	jar.apply(areq)
	aresp, err := client.Do(areq)
	if err != nil {
		return "", err
	}
	defer aresp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(aresp.Body, 1<<20))
	if aresp.StatusCode >= 400 {
		return string(b), &httpStatusErr{code: aresp.StatusCode}
	}
	return string(b), nil
}

type httpStatusErr struct{ code int }

func (e *httpStatusErr) Error() string {
	return "HTTP " + strconv.Itoa(e.code)
}

// FullCycle 手动触发一轮完整巡检
func (h *Healer) FullCycle() { h.Check() }

// ---- 小工具 ----
func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (h *Healer) setState(fn func(*State)) {
	h.srv.mu.Lock()
	defer h.srv.mu.Unlock()
	fn(h.srv.state)
}

func (h *Healer) setErrf(format string, a ...interface{}) {
	msg := format
	if len(a) > 0 {
		msg = sprintf(format, a...)
	}
	h.setState(func(s *State) { s.LastError = msg })
}

func sprintf(format string, a ...interface{}) string {
	return fmt.Sprintf(format, a...)
}

// cookieJar 存储登录 cookie
type cookieJar struct {
	cookies map[string]string
}

func (c *cookieJar) capture(cs []*http.Cookie) {
	for _, ck := range cs {
		c.cookies[ck.Name] = ck.Value
	}
}
func (c *cookieJar) apply(r *http.Request) {
	for k, v := range c.cookies {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
}

// 避免 strconv 未使用
var _ = strconv.Itoa