// SPDX-License-Identifier: Apache-2.0
// AI 分析：OpenAI 兼容 Chat API，输出结构化健康报告，可选自动执行处置动作
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Action AI 建议的动作
type Action struct {
	Type   string `json:"type"`   // stop_plugin | start_plugin
	Target string `json:"target"` // 插件名
	Reason string `json:"reason"` // 原因
}

// Executed 已执行动作的记录
type Executed struct {
	Action Action `json:"action"`
	Result string `json:"result"`
}

// Report 一次 AI 分析报告
type Report struct {
	ID             string     `json:"id"`
	Time           time.Time  `json:"time"`
	Verdict        string     `json:"verdict"`        // ok | warn | critical | error
	Summary        string     `json:"summary"`
	Issues         []string   `json:"issues"`
	Recommendations []string  `json:"recommendations"`
	Actions        []Action   `json:"actions"`
	Executed       []Executed `json:"executed"`
	Model          string     `json:"model"`
	Err            string     `json:"err,omitempty"`
	RawLen         int        `json:"rawLen"`
}

const systemPrompt = `你是一位资深 Linux 服务器运维专家，负责守护一台运行 IotaPanel 面板的小型服务器。
用户会提供服务器指标(CPU/内存/负载/磁盘/网络)与各面板插件的内存占用，以及最近趋势。
请判断健康状况并给出处置建议。

必须只输出一个 JSON 对象，不要输出 markdown 代码块、不要任何多余文字，格式如下：
{
  "verdict": "ok 或 warn 或 critical",
  "summary": "一句话总体结论(中文)",
  "issues": ["发现的问题1", "问题2"],
  "recommendations": ["建议1", "建议2"],
  "actions": [{"type": "stop_plugin 或 start_plugin", "target": "插件名", "reason": "原因"}]
}
要求：
- summary 简明扼要，不超过 60 字
- 无问题时 issues 与 recommendations 给空数组
- actions 非常谨慎：只在你确信该操作能明显改善状况时给出(如某插件内存泄漏异常、某插件异常退出需拉起)；通常给空数组
- verdict 判定参考：CPU 或内存持续 >90% 为 critical，>70% 为 warn，否则 ok`

// buildUserPrompt 构造指标上下文
func buildUserPrompt(samples []Sample, plugs []PluginInfo, prev *Report) string {
	var b strings.Builder
	if len(samples) == 0 {
		b.WriteString(`{"error": "暂无采样数据"}`)
		return b.String()
	}
	// 聚合最近样本：均值/峰值
	n := len(samples)
	window := n
	if window > 12 {
		window = 12 // 最近 6 分钟(30s 采样)
	}
	recent := samples[n-window:]
	var cpuSum, memSum float64
	var cpuMax, memMax float64
	for _, s := range recent {
		cpuSum += s.CPU
		memSum += s.Mem
		if s.CPU > cpuMax {
			cpuMax = s.CPU
		}
		if s.Mem > memMax {
			memMax = s.Mem
		}
	}
	last := samples[n-1]
	cur := map[string]any{
		"time":       time.Unix(last.T, 0).Format("15:04:05"),
		"cpu_pct":    round2(cpuSum / float64(window)),
		"cpu_peak":   round2(cpuMax),
		"mem_pct":    round2(memSum / float64(window)),
		"mem_peak":   round2(memMax),
		"mem_used_mb": last.MemUsed,
		"mem_total_mb": last.MemTotal,
		"load1":      last.Load1,
		"load5":      last.Load5,
		"disk_root_pct": last.DiskRoot,
		"net_rx_kbps":  last.RxKB,
		"net_tx_kbps":  last.TxKB,
	}
	if last.Load5 > 1 { // 附带负载参考
		cur["load_note"] = "5分钟负载偏高"
	}
	// 插件内存
	plugArr := []map[string]any{}
	for _, p := range plugs {
		plugArr = append(plugArr, map[string]any{
			"name":    p.Name,
			"running": p.Running,
			"rss_mb":  round2(float64(p.RSSKB) / 1024),
		})
	}
	cur["plugins"] = plugArr
	// 上次报告摘要，保持上下文连贯
	if prev != nil {
		cur["previous_report"] = map[string]any{
			"time":    prev.Time.Format("15:04"),
			"verdict": prev.Verdict,
			"summary": prev.Summary,
		}
	}
	enc, _ := json.Marshal(cur)
	b.Write(enc)
	return b.String()
}

// callAI 调用 OpenAI 兼容 chat/completions
func callAI(cfg Config, userPrompt string) (string, error) {
	url := strings.TrimRight(cfg.AI.BaseURL, "/") + "/chat/completions"
	payload := map[string]any{
		"model":       cfg.AI.Model,
		"messages":    []map[string]string{{"role": "system", "content": systemPrompt}, {"role": "user", "content": userPrompt}},
		"temperature": 0.2,
		"max_tokens":  cfg.AI.MaxTokens,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.AI.APIKey)
	client := &http.Client{Timeout: time.Duration(cfg.AI.TimeoutSec) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, trunc(string(rb), 200))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("AI 返回空结果")
	}
	return out.Choices[0].Message.Content, nil
}

// parseAIResult 解析 AI 输出(容错提取 JSON)
func parseAIResult(raw string) (verdict, summary string, issues, recs []string, actions []Action) {
	verdict, summary = "error", ""
	issues, recs, actions = []string{}, []string{}, []Action{}
	// 剥离可能的 markdown 代码块
	s := raw
	if i := strings.Index(s, "{"); i >= 0 {
		if j := strings.LastIndex(s, "}"); j > i {
			s = s[i : j+1]
		}
	}
	var r struct {
		Verdict         string   `json:"verdict"`
		Summary         string   `json:"summary"`
		Issues          []string `json:"issues"`
		Recommendations []string `json:"recommendations"`
		Actions         []Action `json:"actions"`
	}
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		return "error", trunc(raw, 120), issues, recs, actions
	}
	if r.Verdict == "ok" || r.Verdict == "warn" || r.Verdict == "critical" {
		verdict = r.Verdict
	} else {
		verdict = "warn"
	}
	return verdict, r.Summary, r.Issues, r.Recommendations, r.Actions
}

// runAnalysis 执行一次完整分析流程
func runAnalysis(dd, home string, cfg Config) Report {
	now := time.Now()
	rep := Report{ID: now.Format("20060102-150405"), Time: now, Model: cfg.AI.Model}
	if !aiConfigured(cfg) {
		rep.Verdict = "error"
		rep.Err = "AI 未配置 (需 base_url / api_key / model)"
		return rep
	}
	samples := readSamples(dd, 60)
	if len(samples) == 0 {
		rep.Verdict = "error"
		rep.Err = "暂无采样数据"
		return rep
	}
	plugs := listPlugins(home, cfg)
	prompt := buildUserPrompt(samples, plugs, latestReport(dd))
	raw, err := callAI(cfg, prompt)
	rep.RawLen = len(raw)
	if err != nil {
		rep.Verdict = "error"
		rep.Err = err.Error()
		return rep
	}
	rep.Verdict, rep.Summary, rep.Issues, rep.Recommendations, rep.Actions = parseAIResult(raw)

	// 自动执行动作(需开启 auto_act 且目标在 watch 白名单内)
	if cfg.AutoAct && len(rep.Actions) > 0 {
		for _, act := range rep.Actions {
			if act.Type != "stop_plugin" && act.Type != "start_plugin" {
				continue
			}
			if !watchAllowed(cfg, act.Target) {
				rep.Executed = append(rep.Executed, Executed{Action: act, Result: "跳过：目标不在 watch 白名单"})
				continue
			}
			var res string
			var err error
			if act.Type == "stop_plugin" {
				res, err = stopPlugin(home, act.Target)
			} else {
				res, err = startPlugin(home, act.Target, cfg.PanelAddr)
			}
			if err != nil {
				res = "失败: " + err.Error()
			}
			rep.Executed = append(rep.Executed, Executed{Action: act, Result: res})
		}
	}
	return rep
}

func trunc(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "…"
}
