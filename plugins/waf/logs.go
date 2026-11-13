// SPDX-License-Identifier: Apache-2.0
// 攻击事件与全局统计：内存环形缓冲（面板实时查看）+ 异步 JSONL 落盘（绝不阻塞请求路径）。

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Event 一条安全事件
type Event struct {
	ID     string `json:"id"`
	Time   int64  `json:"time"`
	Kind   string `json:"kind"` // block | monitor | challenge | ban | escalate | deescalate
	IP     string `json:"ip"`
	Method string `json:"method,omitempty"`
	Host   string `json:"host,omitempty"`
	Path   string `json:"path,omitempty"`
	Rule   string `json:"rule,omitempty"`   // 规则 ID
	Desc   string `json:"desc,omitempty"`   // 规则描述
	Detail string `json:"detail,omitempty"` // 命中片段 / 升级原因
	Site   string `json:"site,omitempty"`
}

// EventLog 环形缓冲 + 异步文件写入
type EventLog struct {
	mu   sync.Mutex
	ring []Event
	max  int

	ch      chan Event
	dropped atomic.Int64
	closed  chan struct{}
}

const (
	eventRingSize   = 2000
	eventChanSize   = 1024
	eventRotateSize = 5 << 20 // 5MB 轮转
)

func NewEventLog(path string) *EventLog {
	l := &EventLog{
		ring:   make([]Event, 0, 256),
		max:    eventRingSize,
		ch:     make(chan Event, eventChanSize),
		closed: make(chan struct{}),
	}
	go l.writer(path)
	return l
}

// Add 记录事件：入环 + 投递异步写盘（通道满则丢弃，绝不阻塞请求）
func (l *EventLog) Add(ev Event) {
	if ev.ID == "" {
		ev.ID = "evt-" + randHex(6)
	}
	if ev.Time == 0 {
		ev.Time = time.Now().Unix()
	}
	l.mu.Lock()
	l.ring = append(l.ring, ev)
	if len(l.ring) > l.max {
		l.ring = l.ring[len(l.ring)-l.max:]
	}
	l.mu.Unlock()

	select {
	case l.ch <- ev:
	default:
		l.dropped.Add(1)
	}
}

// Recent 返回最近 n 条（倒序），支持 kind / 关键字过滤
func (l *EventLog) Recent(n int, kind, q string) []Event {
	if n <= 0 || n > l.max {
		n = 100
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Event
	q = lower(q)
	for i := len(l.ring) - 1; i >= 0 && len(out) < n; i-- {
		ev := l.ring[i]
		if kind != "" && ev.Kind != kind {
			continue
		}
		if q != "" && !containsLower(ev.IP, q) && !containsLower(ev.Path, q) &&
			!containsLower(ev.Rule, q) && !containsLower(ev.Desc, q) && !containsLower(ev.Host, q) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

func (l *EventLog) Dropped() int64 { return l.dropped.Load() }

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func containsLower(s, q string) bool {
	return strings.Contains(lower(s), q)
}

// writer 单 goroutine 顺序写 JSONL，超 5MB 轮转保留 .1
func (l *EventLog) writer(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	bw := bufio.NewWriterSize(f, 64<<10)
	var size int64
	if st, err := f.Stat(); err == nil {
		size = st.Size()
	}
	flush := func() { bw.Flush(); f.Sync() }
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		select {
		case ev := <-l.ch:
			b, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			bw.Write(b)
			bw.WriteByte('\n')
			size += int64(len(b) + 1)
			if size > eventRotateSize {
				flush()
				f.Close()
				os.Rename(path, path+".1")
				f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
				if err != nil {
					return
				}
				bw = bufio.NewWriterSize(f, 64<<10)
				size = 0
			}
		case <-tick.C:
			flush()
		case <-l.closed:
			flush()
			f.Close()
			return
		}
	}
}

func (l *EventLog) Close() { close(l.closed) }

// ---------- 全局统计 ----------

// Stats 原子计数器集合（读写均无锁，高性能）
type Stats struct {
	start       time.Time
	total       atomic.Int64 // 总请求
	blocked     atomic.Int64 // 拦截
	monitored   atomic.Int64 // 观察（记录不拦截）
	challenged  atomic.Int64 // 触发人机验证
	escalations atomic.Int64 // 探针→防护 升级次数
	secCount    atomic.Int64 // 本秒请求数
	qps         atomic.Int64 // 上一秒快照

	ruleMu  sync.Mutex
	ruleMap map[string]int64 // 规则命中计数
	topMu   sync.Mutex
	topMap  map[string]int64 // 拦截 IP 计数
}

func NewStats() *Stats {
	return &Stats{start: time.Now(), ruleMap: map[string]int64{}, topMap: map[string]int64{}}
}

func (s *Stats) ruleHit(id string) {
	s.ruleMu.Lock()
	s.ruleMap[id]++
	s.ruleMu.Unlock()
}

func (s *Stats) ipBlock(ip string) {
	s.topMu.Lock()
	s.topMap[ip]++
	s.topMu.Unlock()
}

// Tick 每秒调用：刷新 QPS 快照
func (s *Stats) Tick() {
	s.qps.Store(s.secCount.Swap(0))
}

func (s *Stats) Snapshot() map[string]any {
	s.ruleMu.Lock()
	rules := map[string]int64{}
	for k, v := range s.ruleMap {
		rules[k] = v
	}
	s.ruleMu.Unlock()
	s.topMu.Lock()
	ips := map[string]int64{}
	for k, v := range s.topMap {
		ips[k] = v
	}
	s.topMu.Unlock()

	topRules := topN(rules, 10)
	topIPs := topN(ips, 10)
	return map[string]any{
		"uptime":      int64(time.Since(s.start).Seconds()),
		"total":       s.total.Load(),
		"blocked":     s.blocked.Load(),
		"monitored":   s.monitored.Load(),
		"challenged":  s.challenged.Load(),
		"escalations": s.escalations.Load(),
		"qps":         s.qps.Load(),
		"rss_mb":      rssMB(),
		"goroutines":  runtime.NumGoroutine(),
		"top_rules":   topRules,
		"top_ips":     topIPs,
	}
}

func (s *Stats) Reset() {
	s.total.Store(0)
	s.blocked.Store(0)
	s.monitored.Store(0)
	s.challenged.Store(0)
	s.escalations.Store(0)
	s.ruleMu.Lock()
	s.ruleMap = map[string]int64{}
	s.ruleMu.Unlock()
	s.topMu.Lock()
	s.topMap = map[string]int64{}
	s.topMu.Unlock()
}

func topN(m map[string]int64, n int) []map[string]any {
	type kv struct {
		k string
		v int64
	}
	var arr []kv
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].v > arr[j].v })
	if len(arr) > n {
		arr = arr[:n]
	}
	out := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		out = append(out, map[string]any{"key": e.k, "count": e.v})
	}
	return out
}

// rssMB 读取本进程 RSS（Linux）；其他平台返回 0
func rssMB() float64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	var size, resident int
	if _, err := fmt.Sscanf(string(data), "%d %d", &size, &resident); err != nil {
		return 0
	}
	return float64(resident) * float64(os.Getpagesize()) / (1 << 20)
}
