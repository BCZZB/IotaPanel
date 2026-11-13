// 自愈守护插件 (IotaPanel)
// 功能：
//   1. 熔断：被攻击速度/攻击量达到阈值 → 自动关闭内网穿透(cf-tunnel)与网站(web-manager)
//   2. 自动拉起：熔断持续 down_secs 秒后自动恢复被关闭的插件
//   3. 自愈：监控 WAF 自身内存，> max_rss_mb 且当前无攻击 → 自动重启 WAF
package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

//go:embed web/*
var webFS embed.FS

type Server struct {
	mu       sync.Mutex
	cfg      *Config
	state    *State
	healer   *Healer
	configPt string
}

func main() {
	port := os.Getenv("PLUGIN_PORT")
	if port == "" {
		port = "19210"
	}
	bind := os.Getenv("PLUGIN_BIND")
	if bind == "" {
		bind = "127.0.0.1"
	}
	home := os.Getenv("PANEL_HOME")
	if home == "" {
		home = "/data/panel"
	}

	h := &Healer{checkInterval: 5 * time.Second}
	srv := &Server{
		cfg:      DefaultConfig(),
		state:    &State{},
		healer:   h,
		configPt: home + "/data/selfheal/config.json",
	}
	if err := srv.loadConfig(); err != nil {
		log.Printf("[selfheal] 配置加载失败(使用默认): %v", err)
	}
	h.srv = srv

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", srv.handleIndex)
	mux.HandleFunc("GET /api/status", srv.handleStatus)
	mux.HandleFunc("GET /api/config", srv.handleGetConfig)
	mux.HandleFunc("POST /api/config", srv.handleSetConfig)
	mux.HandleFunc("POST /api/heal/run", srv.handleManualRun)
	sub, _ := fsSub(webFS, "web")
	mux.Handle("/assets/", http.StripPrefix("", http.FileServer(http.FS(sub))))

	log.Printf("[selfheal] 自愈守护启动: %s:%s (WAF巡检每 %ds)", bind, port, int(h.checkInterval.Seconds()))
	go h.loop(nil)

	httpSrv := &http.Server{
		Addr:              bind + ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("[selfheal] 服务退出: %v", err)
	}
}

// 持久化配置
func (s *Server) saveConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.configPt[:len(s.configPt)-len("/config.json")]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.configPt, b, 0o600)
}

func (s *Server) loadConfig() error {
	b, err := os.ReadFile(s.configPt)
	if err != nil {
		return err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	s.cfg = &c
	return nil
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	b, _ := webFS.ReadFile("web/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := *s.state
	st.LastCheck = time.Now().Format("15:04:05")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": st})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": s.cfg})
}

func (s *Server) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	var nc Config
	if err := json.NewDecoder(r.Body).Decode(&nc); err != nil {
		writeErr(w, err.Error())
		return
	}
	nc.Sanitize()
	s.mu.Lock()
	s.cfg = &nc
	s.mu.Unlock()
	if err := s.saveConfig(); err != nil {
		writeErr(w, err.Error())
		return
	}
	s.healer.TriggerRecheck()
	writeOK(w)
}

func (s *Server) handleManualRun(w http.ResponseWriter, r *http.Request) {
	go s.healer.FullCycle()
	writeOK(w)
}

func writeOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func writeErr(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
}

func fsSub(fsys fs.FS, dir string) (fs.FS, error) {
	return fs.Sub(fsys, dir)
}