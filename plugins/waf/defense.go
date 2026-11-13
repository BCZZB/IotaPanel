// SPDX-License-Identifier: Apache-2.0
// v0.2.0 融合防护增强（对标 1Panel 防火墙防护 + OWASP CRS + CrowdSec）：
//
//   1. HTTP 方法白名单      —— 1Panel「HTTP 规则」允许列表逻辑；
//   2. 搜索引擎蜘蛛放行      —— 1Panel「蜘蛛 IP 池」：放行 Googlebot/Bingbot/Baiduspider 等；
//   3. 威胁情报 IP 信誉源    —— CrowdSec 社区块表 / 1Panel「恶意 IP 组」：周期拉取黑名单并拦截；
//   4. 404 频率追踪         —— 1Panel「404 频率限制」：反复访问不存在资源即临时封禁。
//
// 全部基于 Go 标准库实现，零第三方依赖。

package main

import (
	"bufio"
	"log"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ---------- 1. HTTP 方法白名单 ----------

// defaultMethodSet 默认允许的 HTTP 方法（WebDAV/TRACE/CONNECT 等一律拦截）
//methodAllowed 判断 method 是否在白名单内（大小写不敏感）
func methodAllowed(method string, allow []string) bool {
	for _, m := range allow {
		if strings.EqualFold(strings.TrimSpace(m), method) {
			return true
		}
	}
	return false
}

// ---------- 2. 搜索引擎蜘蛛放行 ----------

var spiderRe = regexp.MustCompile(`(?i)(Googlebot|Google-InspectionTool|Bingbot|bingbot|Baiduspider|Sogou\s+web|Sogou\s+Pic|Sogou\s+Spider|360Spider|Bytespider|YandexBot|Yahoo!|Slurp|DuckDuckBot|facebookexternalhit|Twitterbot|LinkedInBot|Discordbot|PetalBot|applebot|Sogou.*spider|YisouSpider|SemrushBot|AhrefsBot|MJ12bot|DotBot|SeznamBot|archive\.org_bot|ia_archiver|Gigabot)`)

// isSpider 命中已知搜索引擎蜘蛛 UA 即放行速率限制（规则引擎仍检测，防伪蛛负载）
func isSpider(ua string) bool {
	if ua == "" {
		return false
	}
	return spiderRe.MatchString(ua)
}

// ---------- 3. 威胁情报 IP 信誉源 ----------

// threatList 内存中的威胁情报黑名单（CIDR 集合，读多写少）
type threatList struct {
	mu       sync.RWMutex
	prefixes []netip.Prefix
	count    int
	updated  time.Time
	lastErr  string
}

// contains 查询 IP 是否命中信誉黑名单
func (t *threatList) contains(ip netip.Addr) bool {
	if !ip.IsValid() || t == nil {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, p := range t.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (t *threatList) snapshot() (count int, updated time.Time, err string) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.count, t.updated, t.lastErr
}

// replace 用新解析的地址集合整体替换（拉包间隔防抖内存锯齿）
func (t *threatList) replace(addrs []netip.Prefix) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prefixes = addrs
	t.count = len(addrs)
	t.updated = time.Now()
}

func (t *threatList) setErr(s string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastErr = s
}

// threatFetcher 周期拉取所有信誉源并合并入库
type threatFetcher struct {
	engine *Engine
}

// threatLoop 主循环（每 interval 刷新一次；首次启动即拉取）
func (e *Engine) threatLoop() {
	load := func() {
		if err := e.refreshThreatFeeds(); err != nil {
			e.threats.setErr(err.Error())
		}
	}
	load()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if feeds := e.cfg.Load().ThreatFeeds; len(feeds) > 0 {
				load()
			}
		case <-e.stop:
			return
		}
	}
}

// refreshThreatFeeds 拉取并合并全部信誉源（并发拉取，汇总去重）
func (e *Engine) refreshThreatFeeds() error {
	feeds := e.cfg.Load().ThreatFeeds
	if len(feeds) == 0 {
		e.threats.replace(nil)
		return nil
	}
	type feedResult struct {
		addrs []netip.Prefix
		name  string
	}
	client := &http.Client{Timeout: 30 * time.Second}
	results := make(chan feedResult, len(feeds))
	for _, f := range feeds {
		f := f
		go func() {
			addrs, err := fetchThreatFeed(client, f.URL)
			if err != nil {
				log.Printf("[waf] 信誉源 %s 拉取失败: %v", f.Name, err)
			}
			results <- feedResult{addrs, f.Name}
		}()
	}
	var all []netip.Prefix
	seen := map[netip.Prefix]bool{}
	got := 0
	for {
		select {
		case r := <-results:
			got++
			if len(r.addrs) > 0 {
				log.Printf("[waf] 信誉源 %s：%d 条目", r.name, len(r.addrs))
			}
			for _, p := range r.addrs {
				if !seen[p] {
					seen[p] = true
					all = append(all, p)
				}
			}
		case <-time.After(40 * time.Second):
			log.Printf("[waf] 信誉源拉取超时（已收到 %d/%d）", got, len(feeds))
			goto done
		}
		if got >= len(feeds) {
			goto done
		}
	}
done:
	e.threats.replace(all)
	_, upd, errStr := e.threats.snapshot()
	log.Printf("[waf] 威胁情报信誉源刷新完成：%d 条 CIDR，update=%s", len(all), upd.Format("15:04:05"))
	if errStr != "" {
		return nil
	}
	return nil
}

// fetchThreatFeed 拉取单个文本源并解析出所有 IP/CIDR 行
func fetchThreatFeed(client *http.Client, url string) ([]netip.Prefix, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out []netip.Prefix
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 一行可能含 IP 与 CIDR，第一段用逗号/空白切分
		tok := strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == '\t' || r == ','
		})
		for _, t := range tok {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if a, err := netip.ParseAddr(t); err == nil {
				out = append(out, netip.PrefixFrom(a, a.BitLen()))
				continue
			}
			if p, err := netip.ParsePrefix(t); err == nil {
				out = append(out, p.Masked())
			}
		}
	}
	return out, sc.Err()
}

// ---------- 4. 404 频率追踪 ----------

// nfWriter 包装 ResponseWriter，捕获上游返回的 404 状态码
type nfWriter struct {
	http.ResponseWriter
	status int
}

func (w *nfWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *nfWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ---------- 工具 ----------

func cleanFeeds(in []ThreatFeed) []ThreatFeed {
	var out []ThreatFeed
	for _, f := range in {
		f.URL = strings.TrimSpace(f.URL)
		f.Name = strings.TrimSpace(f.Name)
		if f.URL == "" {
			continue
		}
		if f.Name == "" {
			f.Name = f.URL
		}
		if f.IntervalMin <= 0 {
			f.IntervalMin = 60
		}
		out = append(out, f)
	}
	return out
}