// SPDX-License-Identifier: Apache-2.0
// 管理 REST API（面板经 /p/waf/api/* 反代进来；由面板统一做登录鉴权）。
//
//	GET  /api/health            存活探测（面板端口就绪检查）
//	GET  /api/status            引擎状态：当前模式、防护剩余秒数、统计快照
//	GET  /api/config            读取完整配置
//	POST /api/config            保存配置（校验 → 落盘 → 热更新，无需重启）
//	GET  /api/rules             内置规则组清单（含每条规则说明）
//	GET  /api/events            事件流（?n=&kind=&q= 过滤）
//	POST /api/mode              手动切换模式 {"mode":"guard"|"probe"}
//	POST /api/stats/reset       清零统计
//	POST /api/ip                快捷增删 IP 名单 {"list":"black"|"white","action":"add"|"remove","cidr":"","reason":""}

package main

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// API 管理接口
type API struct {
	engine *Engine
	store  *Store
}

func NewAPI(e *Engine, s *Store) *API { return &API{engine: e, store: s} }

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 兼容面板子路径反代：剥掉 /p/waf 前缀
	path := r.URL.Path
	if i := strings.Index(path, "/p/waf"); i >= 0 {
		path = path[i+len("/p/waf"):]
	}
	switch {
	case path == "/api/health":
		writeJSON(w, 200, map[string]any{"ok": true, "plugin": "waf", "version": "0.2.0"})

	case path == "/api/status":
		st := a.engine.stats.Snapshot()
		tc, upd, terr := a.engine.threats.snapshot()
		writeJSON(w, 200, map[string]any{
			"mode":           a.engine.State(),
			"guard_remain":   a.engine.GuardRemain(),
			"events_dropped": a.engine.events.Dropped(),
			"threat_intel":   map[string]any{"count": tc, "updated": upd.Format("2006-01-02 15:04:05"), "err": terr},
			"stats":          st,
			"time":           time.Now().Format("2006-01-02 15:04:05"),
		})

	case path == "/api/config" && r.Method == http.MethodGet:
		writeJSON(w, 200, a.engine.cfg.Load())

	case path == "/api/config" && r.Method == http.MethodPost:
		a.saveConfig(w, r)

	case path == "/api/rules":
		a.ruleList(w)

	case path == "/api/events":
		n, kind, q := queryInt(r, "n", 100), r.URL.Query().Get("kind"), r.URL.Query().Get("q")
		writeJSON(w, 200, map[string]any{"events": a.engine.events.Recent(n, kind, q)})

	case path == "/api/mode" && r.Method == http.MethodPost:
		var body struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]any{"error": "请求体必须是 JSON"})
			return
		}
		switch body.Mode {
		case "guard":
			a.engine.Escalate("管理页手动切换")
			writeJSON(w, 200, map[string]any{"mode": a.engine.State()})
		case "probe":
			a.engine.Deescalate()
			writeJSON(w, 200, map[string]any{"mode": a.engine.State()})
		default:
			writeJSON(w, 400, map[string]any{"error": "mode 必须是 guard 或 probe"})
		}

	case path == "/api/stats/reset" && r.Method == http.MethodPost:
		a.engine.stats.Reset()
		writeJSON(w, 200, map[string]any{"ok": true})

	case path == "/api/ip" && r.Method == http.MethodPost:
		a.ipMutate(w, r)

	default:
		writeJSON(w, 404, map[string]any{"error": "接口不存在: " + path})
	}
}

// saveConfig 保存配置：normalize → 落盘 → 热更新
func (a *API) saveConfig(w http.ResponseWriter, r *http.Request) {
	cfg := DefaultConfig()
	if err := json.NewDecoder(r.Body).Decode(cfg); err != nil {
		writeJSON(w, 400, map[string]any{"error": "配置 JSON 解析失败: " + err.Error()})
		return
	}
	cfg.normalize()
	if msg := validateConfig(cfg); msg != "" {
		writeJSON(w, 400, map[string]any{"error": msg})
		return
	}
	if err := a.store.SaveConfig(cfg); err != nil {
		writeJSON(w, 500, map[string]any{"error": "配置写入失败: " + err.Error()})
		return
	}
	a.engine.Apply(cfg)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// validateConfig 保存前的业务校验（返回空串表示通过）
func validateConfig(c *Config) string {
	seen := map[string]bool{}
	for i := range c.Sites {
		s := &c.Sites[i]
		s.ID = strings.TrimSpace(s.ID)
		s.Name = strings.TrimSpace(s.Name)
		if s.ID == "" {
			return "站点 " + s.Name + " 缺少 ID"
		}
		if seen[s.ID] {
			return "站点 ID 重复: " + s.ID
		}
		seen[s.ID] = true
		if len(s.Domains) == 0 {
			return "站点 " + s.Name + " 至少需要一个域名（可用 * 兜底）"
		}
		if len(s.Backends) == 0 {
			return "站点 " + s.Name + " 至少需要一个上游地址"
		}
		switch s.Mode {
		case "off", "monitor", "block":
		default:
			return "站点 " + s.Name + " 的防护模式必须是 off/monitor/block"
		}
	}
	for i := range c.CustomRules {
		cr := &c.CustomRules[i]
		cr.ID = strings.TrimSpace(cr.ID)
		cr.Name = strings.TrimSpace(cr.Name)
		if cr.ID == "" {
			cr.ID = "cr-" + randHex(4)
		}
		if cr.Name == "" {
			return "自定义规则缺少名称"
		}
		if cr.Action == "" {
			cr.Action = "block"
		}
	}
	if c.HTTPEntry != "" && c.HTTPEntry == c.HTTPSEntry {
		return "HTTP 与 HTTPS 入口不能是同一个端口"
	}
	return ""
}

// ruleList 输出内置规则组清单（给管理页展示）
func (a *API) ruleList(w http.ResponseWriter) {
	rs := a.engine.rules.Load()
	cfg := a.engine.cfg.Load()
	type ruleView struct {
		ID       string `json:"id"`
		Desc     string `json:"desc"`
		Severity string `json:"severity"`
	}
	type groupView struct {
		Key     string     `json:"key"`
		Name    string     `json:"name"`
		Desc    string     `json:"desc"`
		Enabled bool       `json:"enabled"`
		Count   int        `json:"count"`
		Rules   []ruleView `json:"rules"`
	}
	out := make([]groupView, 0, len(rs.Groups))
	for _, g := range rs.Groups {
		gv := groupView{
			Key: g.Key, Name: g.Name, Desc: g.Desc,
			Enabled: cfg.RuleGroups[g.Key], Count: len(g.Rules),
			Rules: make([]ruleView, 0, len(g.Rules)),
		}
		for _, r := range g.Rules {
			gv.Rules = append(gv.Rules, ruleView{ID: r.ID, Desc: r.Desc, Severity: r.Severity})
		}
		out = append(out, gv)
	}
	writeJSON(w, 200, map[string]any{"groups": out})
}

// ipMutate 快捷增删 IP 名单（不重载整份配置）
func (a *API) ipMutate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		List   string `json:"list"`   // black | white
		Action string `json:"action"` // add | remove
		CIDR   string `json:"cidr"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求体必须是 JSON"})
		return
	}
	if body.List != "black" && body.List != "white" {
		writeJSON(w, 400, map[string]any{"error": "list 必须是 black 或 white"})
		return
	}
	body.CIDR = strings.TrimSpace(body.CIDR)
	if body.CIDR == "" {
		writeJSON(w, 400, map[string]any{"error": "cidr 不能为空"})
		return
	}
	cfg := a.engine.cfg.Load().Clone()
	var target *[]IPEntry
	if body.List == "black" {
		target = &cfg.IPBlacklist
	} else {
		target = &cfg.IPWhitelist
	}
	if body.Action == "remove" {
		kept := (*target)[:0]
		for _, e := range *target {
			if e.CIDR != body.CIDR {
				kept = append(kept, e)
			}
		}
		*target = kept
	} else {
		if _, err := parseIPOrPrefix(body.CIDR); err != nil {
			writeJSON(w, 400, map[string]any{"error": "cidr 格式无效（需 IP 或 CIDR）: " + body.CIDR})
			return
		}
		// 去重追加
		exists := false
		for _, e := range *target {
			if e.CIDR == body.CIDR {
				exists = true
				break
			}
		}
		if !exists {
			*target = append(*target, IPEntry{CIDR: body.CIDR, Reason: body.Reason})
		}
	}
	if err := a.store.SaveConfig(cfg); err != nil {
		writeJSON(w, 500, map[string]any{"error": "配置写入失败: " + err.Error()})
		return
	}
	a.engine.Apply(cfg)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------- 工具 ----------

// parseIPOrPrefix 校验字符串是合法 IP 或 CIDR
func parseIPOrPrefix(s string) (string, error) {
	if _, err := netip.ParseAddr(s); err == nil {
		return s, nil
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String(), nil
	}
	_, err := netip.ParseAddr(s)
	return "", err
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func queryInt(r *http.Request, key string, def int) int {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return def
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	return n
}
