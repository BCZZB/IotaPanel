// SPDX-License-Identifier: Apache-2.0
//
// 微盾 WAF 插件入口。
//
// 进程模型（与 IotaPanel 微内核插件协议对齐）：
//   · 流量入口（HTTPEntry/HTTPSEntry，如 :80/:443）——双态引擎，接管站点流量；
//   · 管理服务（PLUGIN_BIND:PLUGIN_PORT，面板注入）——挂载管理 UI 与 REST API，
//     面板经 /p/waf/* 反代进来；keepalive 常驻，因为入口端口必须一直在。
//
// 环境变量（面板启动插件时注入）：
//   PANEL_HOME    面板数据目录（配置存放 $PANEL_HOME/etc/waf/）
//   PLUGIN_PORT   面板分配的管理端口
//   PLUGIN_BIND   管理服务绑定地址（默认 127.0.0.1）

package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	log.SetFlags(log.LstdFlags)

	// ---- 目录与配置 ----
	home := os.Getenv("PANEL_HOME")
	if home == "" {
		home = "/data/panel"
	}
	dir := filepath.Join(home, "etc", "waf")
	store := NewStore(dir)
	cfg := store.LoadConfig()
	cfg.normalize()

	// ---- 双态引擎（流量入口） ----
	engine := NewEngine(store, cfg)
	engine.Start()
	defer engine.Stop()

	// ---- 管理服务（面板反代 /p/waf/* 到这里） ----
	api := NewAPI(engine, store)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 面板以子路径反代（/p/waf/...），静态资源按相对路径取，去掉前缀即可命中
		p := r.URL.Path
		if p != "/" {
			// 兼容带插件前缀访问（/p/waf/index.html → /index.html）
			if i := indexOf(p, "/p/waf"); i >= 0 {
				p = p[i+len("/p/waf"):]
				if p == "" {
					p = "/"
				}
			}
		}
		if p == "/" {
			p = "/index.html"
		}
		data, err := webFS.ReadFile("web" + p)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		switch {
		case hasSuffix(p, ".html"):
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case hasSuffix(p, ".js"):
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		case hasSuffix(p, ".css"):
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		case hasSuffix(p, ".svg"):
			w.Header().Set("Content-Type", "image/svg+xml")
		}
		_, _ = w.Write(data)
	})
	mux.Handle("/api/", api)

	port := envOr("PLUGIN_PORT", "19006")
	bind := envOr("PLUGIN_BIND", "127.0.0.1")
	srv := &http.Server{
		Addr:              bind + ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("[waf] 管理服务就绪: %s（面板侧边栏「微盾 WAF」可管理）", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[waf] 管理服务异常: %v", err)
		}
	}()

	// ---- 优雅退出 ----
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("[waf] 收到退出信号，正在关闭…")
	_ = srv.Close()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func indexOf(s, sub string) int {
	return strings.Index(s, sub)
}

func hasSuffix(s, suf string) bool {
	return strings.HasSuffix(s, suf)
}
