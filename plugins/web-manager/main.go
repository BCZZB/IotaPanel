// SPDX-License-Identifier: Apache-2.0
// web-manager：IotaPanel 网站管理插件（宝塔风格，纯 Go 零依赖）。
//
// 架构：单进程双角色 ——
//   1. 管理接口：监听 $PLUGIN_BIND:$PLUGIN_PORT（默认 127.0.0.1），经面板网关 /p/web-manager/ 访问
//   2. 站点服务：按配置监听 0.0.0.0:80 / :443（可改端口），虚拟主机路由
//
// 契约（IotaPanel 插件三铁律）：监听 $PLUGIN_PORT；处理 SIGTERM 优雅退出；manifest bind 保持 127.0.0.1。
package main

import (
	"embed"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"
)

//go:embed web
var webFS embed.FS

func main() {
	// 一贯作风：软内存上限 64MiB（GC 在逼近时积极回收，正常负载常驻 ~15MB）
	debug.SetMemoryLimit(64 << 20)

	port := os.Getenv("PLUGIN_PORT")
	if port == "" {
		port = "19100" // 手动运行兜底
	}
	bind := os.Getenv("PLUGIN_BIND")
	if bind == "" {
		bind = "127.0.0.1"
	}
	pluginName := os.Getenv("PLUGIN_NAME")
	if pluginName == "" {
		pluginName = "web-manager"
	}
	home := os.Getenv("PANEL_HOME")
	if home == "" {
		home = filepath.Join(os.TempDir(), "web-manager-dev")
	}

	app, err := NewApp(home, pluginName, port)
	if err != nil {
		log.Fatalf("[web-manager] 初始化失败: %v", err)
	}

	admin := &http.Server{
		Addr:              bind + ":" + port,
		Handler:           app.adminMux(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		log.Printf("[web-manager] 收到退出信号，优雅关闭…")
		// 先落盘统计，再关 fpm / mysqld 与站点监听、管理接口
		app.store.FlushStats(app.web.StatsSnapshot())
		if app.php != nil {
			app.php.Stop()
		}
		if app.mysql != nil {
			app.mysql.Stop()
		}
		if app.acme != nil {
			app.acme.Stop()
		}
		_ = admin.Close()
		app.web.Close()
		time.Sleep(200 * time.Millisecond) // 等待在途请求收尾
		log.Printf("[web-manager] 已退出")
		os.Exit(0)
	}()

	go func() {
		if err := admin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[web-manager] 管理接口启动失败: %v", err)
		}
	}()

	cfg := app.store.Config()
	log.Printf("[web-manager] 管理接口 %s:%s | 站点服务 %s:%d + HTTPS :%d | 数据目录 %s",
		bind, port, cfg.BindHTTP, cfg.HTTPPort, cfg.HTTPSPort, app.etcDir)

	select {} // 常驻（keepalive 插件）
}

// NewApp 组装应用：目录布局遵循面板约定 <PANEL_HOME>/etc/web-manager 与 /data/web-manager。
func NewApp(home, pluginName, adminPort string) (*App, error) {
	etcDir := filepath.Join(home, "etc", "web-manager")
	dataDir := filepath.Join(home, "data", "web-manager")
	sitesDir := filepath.Join(dataDir, "sites")
	certDir := filepath.Join(etcDir, "certs")
	for _, d := range []string{etcDir, dataDir, sitesDir, certDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	store, err := LoadStore(etcDir)
	if err != nil {
		return nil, err
	}
	a := &App{
		pluginName: pluginName,
		home:       home,
		etcDir:     etcDir,
		dataDir:    dataDir,
		sitesDir:   sitesDir,
		certDir:    certDir,
		store:      store,
		limiter:    newIPLimiter(),
		adminPort:  adminPort,
		startedAt:  time.Now(),
	}
	ws, err := NewWebServer(a)
	if err != nil {
		return nil, err
	}
	a.web = ws
	// PHP 运行时管理器（懒启动：真正用到才拉起 fpm）
	a.php = NewPHPManager(a)
	a.php.RebuildPools(a.phpSites())
	// MySQL 运行时管理器（零占用待命：连接到达才拉起 mysqld，空闲自动停止）
	a.mysql = NewMySQLManager(a)
	// ACME 证书管理器（HTTP-01 验证监听 + 到期自动续期巡检）
	a.acme = NewACMEManager(a)
	return a, nil
}
