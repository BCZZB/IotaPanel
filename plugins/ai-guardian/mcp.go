// SPDX-License-Identifier: Apache-2.0
// MCP 服务：Streamable HTTP (POST /mcp)，JSON-RPC 2.0
// 工具：指标查询 / AI 报告 / 立即分析 / 插件列表与启停 / 配置读写
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"syscall"
	"time"
)

var mcpTools = []map[string]any{
	{
		"name":        "get_metrics",
		"description": "获取服务器指标采样(CPU/内存/负载/磁盘/网络/各插件内存)。range: 最近采样条数，默认 20，最大 2880(约24小时)",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"count": map[string]any{"type": "integer", "description": "返回最近 N 条采样，默认 20"}}, "required": []string{}},
	},
	{
		"name":        "get_status",
		"description": "获取守护整体状态：探针是否存活、内存占用、采样/分析配置、AI 是否已配置",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "required": []string{}},
	},
	{
		"name":        "get_report",
		"description": "获取 AI 分析报告。不传 id 返回最新一份；history=true 返回最近报告列表",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "string"}, "history": map[string]any{"type": "boolean"}}, "required": []string{}},
	},
	{
		"name":        "analyze_now",
		"description": "触发探针立即执行一次 AI 分析(异步，稍后用 get_report 查看结果)",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "required": []string{}},
	},
	{
		"name":        "list_plugins",
		"description": "列出面板已安装插件及运行状态、内存占用",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "required": []string{}},
	},
	{
		"name":        "stop_plugin",
		"description": "优雅停止指定插件(SIGTERM)",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string", "description": "插件名"}}, "required": []string{"name"}},
	},
	{
		"name":        "start_plugin",
		"description": "启动指定插件(优先面板懒启动，失败则直接托管拉起)",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string", "description": "插件名"}}, "required": []string{"name"}},
	},
	{
		"name":        "get_config",
		"description": "读取守护配置(密钥已脱敏)",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "required": []string{}},
	},
	{
		"name":        "set_config",
		"description": "更新守护配置(部分字段)。可更新: sample_interval, ai_interval, auto_act, watch, panel_addr, ai.base_url, ai.api_key, ai.model",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
			"sample_interval": map[string]any{"type": "integer"},
			"ai_interval":     map[string]any{"type": "integer"},
			"auto_act":        map[string]any{"type": "boolean"},
			"watch":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"panel_addr":      map[string]any{"type": "string"},
			"ai_base_url":     map[string]any{"type": "string"},
			"ai_api_key":      map[string]any{"type": "string"},
			"ai_model":        map[string]any{"type": "string"},
		}, "required": []string{}},
	},
}

// handleMCP 处理 MCP JSON-RPC 请求
func handleMCP(home, dd string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			jsonErr(w, 405, "MCP 仅支持 POST")
			return
		}
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err := json.Unmarshal(body, &req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"解析错误"}}`))
			return
		}
		// 通知(无 id) → 202
		if len(req.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var result any
		var rpcErr *rpcError
		switch req.Method {
		case "initialize":
			proto := "2025-03-26"
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			if json.Unmarshal(req.Params, &p) == nil && p.ProtocolVersion != "" {
				proto = p.ProtocolVersion
			}
			result = map[string]any{
				"protocolVersion": proto,
				"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
				"serverInfo":      map[string]any{"name": "ai-guardian", "version": "0.1.0"},
			}
		case "ping":
			result = map[string]any{}
		case "tools/list":
			result = map[string]any{"tools": mcpTools}
		case "tools/call":
			var p struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			json.Unmarshal(req.Params, &p)
			txt, isErr := callMCPTool(home, dd, p.Name, p.Arguments)
			result = map[string]any{"content": []map[string]any{{"type": "text", "text": txt}}, "isError": isErr}
		default:
			rpcErr = &rpcError{Code: -32601, Message: "未知方法: " + req.Method}
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(req.ID)}
		if rpcErr != nil {
			resp["error"] = rpcErr
		} else {
			resp["result"] = result
		}
		b, _ := json.Marshal(resp)
		w.Write(b)
	}
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// callMCPTool 执行 MCP 工具调用
func callMCPTool(home, dd, name string, args json.RawMessage) (string, bool) {
	cfg := loadConfig(dd)
	var a map[string]any
	json.Unmarshal(args, &a)
	if a == nil {
		a = map[string]any{}
	}

	switch name {
	case "get_metrics":
		n := 20
		if v, ok := a["count"].(float64); ok && v > 0 {
			n = int(v)
			if n > 2880 {
				n = 2880
			}
		}
		ss := readSamples(dd, n)
		b, _ := json.Marshal(ss)
		return string(b), false

	case "get_status":
		pid := readPid(dd)
		alive := procAlive(pid)
		st := map[string]any{
			"probe_running": alive,
			"probe_pid":     pid,
			"probe_rss_kb":  procRSSKB(pid),
			"probe_uptime":  "",
			"ai_configured": aiConfigured(cfg),
			"sample_interval": cfg.SampleInterval,
			"ai_interval":     cfg.AIInterval,
			"auto_act":        cfg.AutoAct,
		}
		if alive {
			st["probe_uptime"] = timeSinceCN(procStartTime(pid))
		}
		if r := latestReport(dd); r != nil {
			st["last_report"] = map[string]any{"time": r.Time, "verdict": r.Verdict, "summary": r.Summary}
		}
		b, _ := json.Marshal(st)
		return string(b), false

	case "get_report":
		if v, ok := a["history"].(bool); ok && v {
			b, _ := json.Marshal(readReports(dd, 10))
			return string(b), false
		}
		if id, ok := a["id"].(string); ok && id != "" {
			for _, r := range readReports(dd, 50) {
				if r.ID == id {
					b, _ := json.Marshal(r)
					return string(b), false
				}
			}
			return "未找到报告 " + id, true
		}
		if r := latestReport(dd); r != nil {
			b, _ := json.Marshal(r)
			return string(b), false
		}
		return "暂无报告", false

	case "analyze_now":
		if err := signalProbe(dd, "SIGUSR1"); err != nil {
			return "触发失败: " + err.Error(), true
		}
		return "已触发立即分析，请稍后用 get_report 获取结果", false

	case "list_plugins":
		b, _ := json.Marshal(listPlugins(home, cfg))
		return string(b), false

	case "stop_plugin":
		nm, _ := a["name"].(string)
		if nm == "" {
			return "缺少 name", true
		}
		res, err := stopPlugin(home, nm)
		if err != nil {
			return err.Error(), true
		}
		return res, false

	case "start_plugin":
		nm, _ := a["name"].(string)
		if nm == "" {
			return "缺少 name", true
		}
		res, err := startPlugin(home, nm, cfg.PanelAddr)
		if err != nil {
			return err.Error(), true
		}
		return res, false

	case "get_config":
		c := cfg
		if c.AI.APIKey != "" {
			c.AI.APIKey = "****" + c.AI.APIKey[max(0, len(c.AI.APIKey)-4):]
		}
		b, _ := json.Marshal(c)
		return string(b), false

	case "set_config":
		res, err := applyConfigUpdate(dd, a)
		if err != nil {
			return err.Error(), true
		}
		_ = signalProbe(dd, "SIGHUP")
		return res, false
	}
	return "未知工具: " + name, true
}

// applyConfigUpdate 部分更新配置
func applyConfigUpdate(dd string, a map[string]any) (string, error) {
	cfg := loadConfig(dd)
	changed := []string{}
	if v, ok := a["sample_interval"].(float64); ok && v >= 5 {
		cfg.SampleInterval = int(v)
		changed = append(changed, "sample_interval")
	}
	if v, ok := a["ai_interval"].(float64); ok && v >= 60 {
		cfg.AIInterval = int(v)
		changed = append(changed, "ai_interval")
	}
	if v, ok := a["auto_act"].(bool); ok {
		cfg.AutoAct = v
		changed = append(changed, "auto_act")
	}
	if v, ok := a["panel_addr"].(string); ok && v != "" {
		cfg.PanelAddr = v
		changed = append(changed, "panel_addr")
	}
	if v, ok := a["watch"].([]any); ok {
		ws := []string{}
		for _, it := range v {
			if s, ok := it.(string); ok {
				ws = append(ws, s)
			}
		}
		if len(ws) > 0 {
			cfg.Watch = ws
			changed = append(changed, "watch")
		}
	}
	if v, ok := a["ai_base_url"].(string); ok {
		cfg.AI.BaseURL = v
		changed = append(changed, "ai.base_url")
	}
	if v, ok := a["ai_model"].(string); ok {
		cfg.AI.Model = v
		changed = append(changed, "ai.model")
	}
	// 密钥：只有显式传入且非脱敏值才更新
	if v, ok := a["ai_api_key"].(string); ok && v != "" && !strings.HasPrefix(v, "****") {
		cfg.AI.APIKey = v
		changed = append(changed, "ai.api_key")
	}
	if len(changed) == 0 {
		return "无有效变更", nil
	}
	if err := saveConfig(dd, cfg); err != nil {
		return "", err
	}
	return "已更新: " + strings.Join(changed, ", ") + "，已通知探针重载", nil
}

// signalProbe 向探针进程发信号
func signalProbe(dd, sigName string) error {
	pid := readPid(dd)
	if !procAlive(pid) {
		return fmt.Errorf("探针未运行")
	}
	var sig syscall.Signal
	switch sigName {
	case "SIGHUP":
		sig = syscall.SIGHUP
	case "SIGUSR1":
		sig = syscall.SIGUSR1
	default:
		return fmt.Errorf("不支持的信号")
	}
	return syscall.Kill(pid, sig)
}

// timeSinceCN 人性化运行时长
func timeSinceCN(t time.Time) string {
	if t.IsZero() {
		return "未知"
	}
	d := time.Since(t)
	if d < time.Minute {
		return fmt.Sprintf("%d秒", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d分钟", int(d.Minutes()))
	}
	return fmt.Sprintf("%d小时%d分", int(d.Hours()), int(d.Minutes())%60)
}
