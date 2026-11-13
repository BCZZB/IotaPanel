// SPDX-License-Identifier: Apache-2.0
// 配置与数据文件管理：纯标准库，所有数据落在 <PANEL_HOME>/data/ai-guardian/
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ---------------- 配置 ----------------

type AIConfig struct {
	BaseURL    string `json:"base_url"`    // OpenAI 兼容地址，如 https://api.deepseek.com/v1
	APIKey     string `json:"api_key"`     // 密钥
	Model      string `json:"model"`       // 模型名
	MaxTokens  int    `json:"max_tokens"`  // 回复上限
	TimeoutSec int    `json:"timeout_sec"` // 请求超时
}

type Config struct {
	SampleInterval int      `json:"sample_interval"` // 采样间隔(秒)
	AIInterval     int      `json:"ai_interval"`     // AI 分析周期(秒)
	AutoAct        bool     `json:"auto_act"`        // 是否自动执行 AI 建议动作
	Watch          []string `json:"watch"`           // 动作允许作用的插件列表，"*" 表示全部(不含自身)
	PanelAddr      string   `json:"panel_addr"`      // 面板地址(用于懒启动插件)
	AI             AIConfig `json:"ai"`
	HistorySamples int      `json:"history_samples"` // 指标保留条数
	HistoryReports int      `json:"history_reports"` // 报告保留条数
}

func defaultConfig() Config {
	return Config{
		SampleInterval: 30,
		AIInterval:     900,
		AutoAct:        false,
		Watch:          []string{"*"},
		PanelAddr:      "http://127.0.0.1:8787",
		AI: AIConfig{
			BaseURL:    "",
			APIKey:     "",
			Model:      "",
			MaxTokens:  800,
			TimeoutSec: 60,
		},
		HistorySamples: 2880, // 30s × 2880 = 24h
		HistoryReports: 50,
	}
}

// ---------------- 路径 ----------------

func dataDirOf(home string) string {
	if home == "" {
		home = "."
	}
	return filepath.Join(home, "data", "ai-guardian")
}

func ensureDataDir(home string) string {
	dd := dataDirOf(home)
	os.MkdirAll(dd, 0755)
	return dd
}

func cfgPath(dd string) string      { return filepath.Join(dd, "config.json") }
func metricsPath(dd string) string  { return filepath.Join(dd, "metrics.jsonl") }
func reportsPath(dd string) string  { return filepath.Join(dd, "reports.jsonl") }
func pidPath(dd string) string      { return filepath.Join(dd, "probe.pid") }
func statePath(dd string) string    { return filepath.Join(dd, "probe-state.json") }
func probeLogPath(dd string) string { return filepath.Join(dd, "probe.log") }

// ---------------- 配置读写 ----------------

func loadConfig(dd string) Config {
	cfg := defaultConfig()
	b, err := os.ReadFile(cfgPath(dd))
	if err != nil {
		return cfg
	}
	var c Config
	if json.Unmarshal(b, &c) != nil {
		return cfg
	}
	// 合并：零值回落默认
	if c.SampleInterval < 5 {
		c.SampleInterval = cfg.SampleInterval
	}
	if c.AIInterval < 60 {
		c.AIInterval = cfg.AIInterval
	}
	if c.PanelAddr == "" {
		c.PanelAddr = cfg.PanelAddr
	}
	if c.AI.MaxTokens <= 0 {
		c.AI.MaxTokens = cfg.AI.MaxTokens
	}
	if c.AI.TimeoutSec <= 0 {
		c.AI.TimeoutSec = cfg.AI.TimeoutSec
	}
	if c.HistorySamples <= 0 {
		c.HistorySamples = cfg.HistorySamples
	}
	if c.HistoryReports <= 0 {
		c.HistoryReports = cfg.HistoryReports
	}
	if len(c.Watch) == 0 {
		c.Watch = cfg.Watch
	}
	return c
}

func saveConfig(dd string, c Config) error {
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(cfgPath(dd), b, 0600)
}

func aiConfigured(cfg Config) bool {
	return cfg.AI.BaseURL != "" && cfg.AI.APIKey != "" && cfg.AI.Model != ""
}

// ---------------- 指标 jsonl ----------------

func appendLine(path string, v any, cap int) error {
	b, _ := json.Marshal(v)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	capJSONL(path, cap)
	return nil
}

// capJSONL 超过 cap 行时保留后半段(轻量轮转)
func capJSONL(path string, cap int) {
	st, err := os.Stat(path)
	if err != nil || st.Size() < int64(cap*400) { // 粗略预估，避免频繁读取
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) <= cap {
		return
	}
	keep := lines[len(lines)-cap*3/4:]
	os.WriteFile(path, []byte(strings.Join(keep, "\n")+"\n"), 0644)
}

func readJSONL[T any](path string, last int) []T {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if last > 0 && len(lines) > last {
		lines = lines[len(lines)-last:]
	}
	out := make([]T, 0, len(lines))
	for _, ln := range lines {
		if ln == "" {
			continue
		}
		var v T
		if json.Unmarshal([]byte(ln), &v) == nil {
			out = append(out, v)
		}
	}
	return out
}

func appendSample(dd string, s Sample, cap int) error   { return appendLine(metricsPath(dd), s, cap) }
func readSamples(dd string, last int) []Sample          { return readJSONL[Sample](metricsPath(dd), last) }
func appendReport(dd string, r Report, cap int) error   { return appendLine(reportsPath(dd), r, cap) }
func readReports(dd string, last int) []Report          { return readJSONL[Report](reportsPath(dd), last) }

func latestReport(dd string) *Report {
	rs := readReports(dd, 1)
	if len(rs) == 0 {
		return nil
	}
	return &rs[0]
}

// ---------------- 探针 pid ----------------

func writePid(dd string, pid int) {
	os.WriteFile(pidPath(dd), []byte(strconv.Itoa(pid)), 0644)
}

func readPid(dd string) int {
	b, err := os.ReadFile(pidPath(dd))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func procAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return false
	}
	// 确认是我们的探针进程
	return strings.Contains(string(b), "ai-guardian")
}

func procRSSKB(pid int) int {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "VmRSS:") {
			f := strings.Fields(ln)
			if len(f) >= 2 {
				n, _ := strconv.Atoi(f[1])
				return n
			}
		}
	}
	return 0
}

func procStartTime(pid int) time.Time {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return time.Time{}
	}
	// 第22个字段是 starttime(时钟滴答)
	fields := strings.Fields(string(b))
	if len(fields) < 22 {
		return time.Time{}
	}
	ticks, _ := strconv.ParseInt(fields[21], 10, 64)
	boot := bootTime()
	return boot.Add(time.Duration(ticks) * time.Second / 100)
}

func bootTime() time.Time {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Now()
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "btime ") {
			f := strings.Fields(ln)
			if len(f) >= 2 {
				n, _ := strconv.ParseInt(f[1], 10, 64)
				return time.Unix(n, 0)
			}
		}
	}
	return time.Now()
}
