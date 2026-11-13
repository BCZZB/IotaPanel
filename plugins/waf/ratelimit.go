// SPDX-License-Identifier: Apache-2.0
// CC 防护（令牌桶滑动限速）+ IP 黑白名单（CIDR）+ 自动拉黑 + 人机验证（工作量证明挑战）。
//
// 人机验证机制（雷池「Anti-Bot Challenge」的轻量实现）：
//   1. 超频客户端收到挑战页，页面内嵌 JS 求解工作量证明——
//      找到 n 使 fnv1a(nonce + ":" + n) 的低 pow_bits 位全为 0；
//   2. 求解后写入 Cookie：nonce.n.expiredAt.HMAC(nonce|n|expiredAt|ip)；
//   3. 服务端无状态校验：PoW 位 + HMAC 签名 + 有效期 + IP 绑定。
//   纯 JS 循环即可在浏览器内毫秒级完成，但不执行 JS 的爬虫/洪水工具会被卡住，
//   且每次求解都有真实 CPU 成本，令高频攻击变得昂贵。

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- 令牌桶限速器 ----------

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter 每客户端 IP 令牌桶；CC 防护与探针升级判定共用同一把尺子
type Limiter struct {
	mu   sync.Mutex
	m    map[string]*bucket
	cap  float64
	rate float64 // token/秒
}

func NewLimiter(capacity, windowSecs int) *Limiter {
	if capacity <= 0 {
		capacity = 120
	}
	if windowSecs <= 0 {
		windowSecs = 60
	}
	l := &Limiter{
		m:    map[string]*bucket{},
		cap:  float64(capacity),
		rate: float64(capacity) / float64(windowSecs),
	}
	go l.janitor()
	return l
}

// Update 调整参数（配置热更新）
func (l *Limiter) Update(capacity, windowSecs int) {
	if capacity <= 0 || windowSecs <= 0 {
		return
	}
	l.mu.Lock()
	l.cap = float64(capacity)
	l.rate = float64(capacity) / float64(windowSecs)
	l.mu.Unlock()
}

// Allow 消耗 1 个令牌；返回是否仍在限额内
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.m[key]
	if !ok {
		b = &bucket{tokens: l.cap, last: now}
		l.m[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.cap {
			b.tokens = l.cap
		}
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// janitor 每 2 分钟清理闲置桶（防内存增长）
func (l *Limiter) janitor() {
	for range time.Tick(2 * time.Minute) {
		cutoff := time.Now().Add(-10 * time.Minute)
		l.mu.Lock()
		for k, b := range l.m {
			if b.last.Before(cutoff) {
				delete(l.m, k)
			}
		}
		l.mu.Unlock()
	}
}

// ---------- IP 名单（单 IP + CIDR） ----------

type IPList struct {
	mu       sync.RWMutex
	exact    map[string]IPEntry // 精确 IP
	prefixes []prefixEntry      // CIDR 段
}

type prefixEntry struct {
	prefix netip.Prefix
	entry  IPEntry
}

func ParseIPList(entries []IPEntry) *IPList {
	l := &IPList{exact: map[string]IPEntry{}}
	for _, e := range entries {
		e.CIDR = strings.TrimSpace(e.CIDR)
		if e.CIDR == "" {
			continue
		}
		if addr, err := netip.ParseAddr(e.CIDR); err == nil {
			l.exact[addr.String()] = e
			continue
		}
		if p, err := netip.ParsePrefix(e.CIDR); err == nil {
			p = p.Masked()
			l.prefixes = append(l.prefixes, prefixEntry{prefix: p, entry: e})
		}
	}
	return l
}

// Contains 查询 IP 是否在名单中（跳过已过期条目）
func (l *IPList) Contains(ip netip.Addr) (IPEntry, bool) {
	now := time.Now().Unix()
	l.mu.RLock()
	defer l.mu.RUnlock()
	if e, ok := l.exact[ip.String()]; ok {
		if e.Expires == 0 || e.Expires > now {
			return e, true
		}
		return IPEntry{}, false
	}
	for _, pe := range l.prefixes {
		if pe.prefix.Contains(ip) {
			if pe.entry.Expires == 0 || pe.entry.Expires > now {
				return pe.entry, true
			}
		}
	}
	return IPEntry{}, false
}

// ---------- 自动拉黑 ----------

// AutoBanner 统计每 IP 在窗口内的拦截次数，达到阈值即建议拉黑
type AutoBanner struct {
	mu        sync.Mutex
	m         map[string][]int64 // ip -> 拦截时间戳
	threshold int
	window    int
}

func NewAutoBanner(threshold, window int) *AutoBanner {
	return &AutoBanner{m: map[string][]int64{}, threshold: threshold, window: window}
}

// RecordBlock 记录一次拦截；返回是否达到拉黑阈值
func (a *AutoBanner) RecordBlock(ip string) bool {
	now := time.Now().Unix()
	cutoff := now - int64(a.window)
	a.mu.Lock()
	defer a.mu.Unlock()
	var kept []int64
	for _, t := range a.m[ip] {
		if t > cutoff {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	a.m[ip] = kept
	if len(a.m) > 4096 { // 防膨胀：清理全部过期
		for k, ts := range a.m {
			var kk []int64
			for _, t := range ts {
				if t > cutoff {
					kk = append(kk, t)
				}
			}
			if len(kk) == 0 {
				delete(a.m, k)
			} else {
				a.m[k] = kk
			}
		}
	}
	return len(kept) >= a.threshold
}

// ---------- 工作量证明挑战 ----------

const challengeCookie = "waf_cv"

// fnv1a 32 位 FNV-1a 哈希（Go 与页面内 JS 逐位一致）
func fnv1a(s string) uint32 {
	var h uint32 = 0x811c9dc5
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 0x01000193
	}
	return h
}

// powOK 校验工作量证明：fnv1a(nonce:n) 的低 bits 位是否全 0
func powOK(nonce, n string, bits int) bool {
	if bits < 8 || bits > 24 {
		bits = 16
	}
	mask := uint32(1)<<uint(bits) - 1
	return fnv1a(nonce+":"+n)&mask == 0
}

// signChallenge 生成挑战签名（绑定 nonce/有效期/IP；n 由客户端求解 PoW 后自行填入）
func (e *Engine) signChallenge(nonce string, exp int64, ip string) string {
	mac := hmac.New(sha256.New, e.secret)
	mac.Write([]byte(nonce))
	mac.Write([]byte{'|'})
	mac.Write([]byte(strconv.FormatInt(exp, 10)))
	mac.Write([]byte{'|'})
	mac.Write([]byte(ip))
	return hex.EncodeToString(mac.Sum(nil))
}

// verifyChallenge 校验客户端提交的挑战 Cookie：有效期 + 工作量证明 + HMAC 签名
func (e *Engine) verifyChallenge(cookieVal, ip string, bits int) bool {
	parts := strings.Split(cookieVal, ".")
	if len(parts) != 4 {
		return false
	}
	nonce, nStr, expStr, sig := parts[0], parts[1], parts[2], parts[3]
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || exp < time.Now().Unix() {
		return false
	}
	if _, err := strconv.ParseUint(nStr, 10, 64); err != nil {
		return false
	}
	if !powOK(nonce, nStr, bits) {
		return false
	}
	expect := e.signChallenge(nonce, exp, ip)
	return hmac.Equal([]byte(expect), []byte(sig))
}
