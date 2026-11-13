// SPDX-License-Identifier: Apache-2.0
// AI 守护 —— IotaPanel 插件主入口
// 双进程模型:
//   ai-guardian probe  → 常驻探针(setsid 独立会话, ~2MB)
//   ai-guardian        → 主进程(面板按需拉起, 空闲自动退出; Web UI + MCP)
package main

import (
	"embed"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed web/index.html
var webFS embed.FS

//go:embed manifest.yaml
var manifestRaw []byte

var (
	homeDir string
	dataDD  string
	version = "0.1.0"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "probe":
			runProbe()
			return
		case "version":
			println("ai-guardian " + version)
			return
		}
	}
	runServe()
}

// ---------------- 探针生命周期 ----------------

// ensureProbe 领养或拉起探针进程
func ensureProbe() (int, error) {
	pid := readPid(dataDD)
	if procAlive(pid) {
		return pid, nil // 已在运行(上次主进程退出后存活下来的)
	}
	os.Remove(pidPath(dataDD))
	// 探针日志：超过 256KB 截断
	logPath := probeLogPath(dataDD)
	if st, err := os.Stat(logPath); err == nil && st.Size() > 256*1024 {
		os.Remove(logPath)
	}
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return 0, err
	}
	defer lf.Close()
	self, err := os.Executable()
	if err != nil {
		return 0, err
	}
	cmd := exec.Command(self, "probe")
	cmd.Env = append(os.Environ(), "PANEL_HOME="+homeDir)
	cmd.Stdout = lf
	cmd.Stderr = lf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // 独立会话:主进程退出不影响探针
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	return cmd.Process.Pid, nil
}

// ---------------- HTTP 辅助 ----------------

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"error": msg})
}

// ---------------- 主进程 HTTP 服务 ----------------

func runServe() {
	homeDir = os.Getenv("PANEL_HOME")
	if homeDir == "" {
		homeDir = "/data/panel"
	}
	port := os.Getenv("PLUGIN_PORT")
	if port == "" {
		port = "19100"
	}
	dataDD = ensureDataDir(homeDir)

	// 领养/拉起探针
	if pid, err := ensureProbe(); err != nil {
		log.Printf("[serve] 探针启动失败: %v", err)
	} else {
		log.Printf("[serve] 探针就绪 pid=%d", pid)
	}

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		<-ch
		log.Printf("[serve] 主进程退出(探针继续常驻)")
		os.Exit(0)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", handleIndex)
	mux.HandleFunc("GET /api/status", handleStatus)
	mux.HandleFunc("GET /api/metrics", handleMetrics)
	mux.HandleFunc("GET /api/report", handleReport)
	mux.HandleFunc("GET /api/plugins", handlePlugins)
	mux.HandleFunc("POST /api/plugin/action", handlePluginAction)
	mux.HandleFunc("POST /api/analyze", handleAnalyze)
	mux.HandleFunc("GET /api/config", handleGetConfig)
	mux.HandleFunc("POST /api/config", handleSetConfig)
	mux.HandleFunc("GET /api/probe/log", handleProbeLog)
	mux.HandleFunc("POST /mcp", handleMCP(homeDir, dataDD))

	addr := "127.0.0.1:" + port
	srv := &http.Server{Addr: addr, Handler: mux}
	log.Printf("[serve] AI 守护 v%s 监听 %s (空闲由面板回收, 探针独立常驻)", version, addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[serve] HTTP 异常退出: %v", err)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "ui missing", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

// handleStatus 总览状态
func handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := loadConfig(dataDD)
	pid := readPid(dataDD)
	alive := procAlive(pid)
	st := map[string]any{
		"pluginVersion":   version,
		"probeRunning":    alive,
		"probePID":        pid,
		"probeRSSKB":      procRSSKB(pid),
		"probeUptime":     timeSinceCN(procStartTime(pid)),
		"aiConfigured":    aiConfigured(cfg),
		"aiInterval":      cfg.AIInterval,
		"sampleInterval":  cfg.SampleInterval,
		"autoAct":         cfg.AutoAct,
		"sampleCount":     len(readSamples(dataDD, 0)),
		"reportCount":     len(readReports(dataDD, 0)),
	}
	if ss := readSamples(dataDD, 1); len(ss) > 0 {
		st["lastSampleTime"] = time.Unix(ss[0].T, 0).Format("15:04:05")
	}
	if rep := latestReport(dataDD); rep != nil {
		st["lastReport"] = rep
	}
	jsonOK(w, st)
}

// handleMetrics ?count=N 指标序列(自动降采样给图表)
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("count"))
	if n <= 0 {
		n = 480 // 默认 4 小时
	}
	if n > 2880 {
		n = 2880
	}
	ss := readSamples(dataDD, n)
	jsonOK(w, map[string]any{"samples": ss})
}

// handleReport 报告: ?id=xxx 或最新 + 列表
func handleReport(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	reports := readReports(dataDD, 50)
	if id != "" {
		for i := range reports {
			if reports[i].ID == id {
				jsonOK(w, reports[i])
				return
			}
		}
		jsonErr(w, 404, "报告不存在")
		return
	}
	latest := latestReport(dataDD)
	jsonOK(w, map[string]any{"latest": latest, "list": reports})
}

// handlePlugins 插件列表
func handlePlugins(w http.ResponseWriter, r *http.Request) {
	cfg := loadConfig(dataDD)
	jsonOK(w, map[string]any{"plugins": listPlugins(homeDir, cfg)})
}

// handlePluginAction 优雅启停插件
func handlePluginAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Action string `json:"action"` // start | stop
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "参数解析失败")
		return
	}
	if req.Name == "" || (req.Action != "start" && req.Action != "stop") {
		jsonErr(w, 400, "参数: {name, action: start|stop}")
		return
	}
	cfg := loadConfig(dataDD)
	var res string
	var err error
	if req.Action == "stop" {
		res, err = stopPlugin(homeDir, req.Name)
	} else {
		res, err = startPlugin(homeDir, req.Name, cfg.PanelAddr)
	}
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonOK(w, map[string]any{"result": res})
}

// handleAnalyze 触发立即分析
func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if err := signalProbe(dataDD, "SIGUSR1"); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonOK(w, map[string]any{"result": "已触发探针立即分析, 几秒后刷新报告"})
}

// handleGetConfig 配置(脱敏)
func handleGetConfig(w http.ResponseWriter, r *http.Request) {
	c := loadConfig(dataDD)
	if c.AI.APIKey != "" {
		c.AI.APIKey = "****" + c.AI.APIKey[max(0, len(c.AI.APIKey)-4):]
	}
	jsonOK(w, c)
}

// handleSetConfig 更新配置并通知探针
func handleSetConfig(w http.ResponseWriter, r *http.Request) {
	var a map[string]any
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		jsonErr(w, 400, "参数解析失败")
		return
	}
	res, err := applyConfigUpdate(dataDD, a)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonOK(w, map[string]any{"result": res})
}

// handleProbeLog 探针日志尾部
func handleProbeLog(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(probeLogPath(dataDD))
	if err != nil {
		jsonOK(w, map[string]any{"log": ""})
		return
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > 60 {
		lines = lines[len(lines)-60:]
	}
	jsonOK(w, map[string]any{"log": strings.Join(lines, "\n")})
}

// 防止未用 import 报错(filepath 在部分构建标签下可能未直接使用)
var _ = filepath.Join
