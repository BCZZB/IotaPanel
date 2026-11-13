// SPDX-License-Identifier: Apache-2.0
// php-fpm 按需运行时：首个 PHP 请求才拉起 fpm，空闲自动停止 —— 不用时零开销。
// 单实例多 pool：每个 PHP 站点一个 pool（ondemand + open_basedir 隔离），worker 空闲 10s 自退。
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// PHPRuntimeConfig PHP 运行时配置（存储于 config.json）。
type PHPRuntimeConfig struct {
	Enabled      bool `json:"enabled"`
	MaxChildren  int  `json:"maxChildren"`  // 每站点 worker 上限
	IdleStopSecs int  `json:"idleStopSecs"` // 插件层空闲多久停掉整个 fpm
}

func defaultPHPConfig() PHPRuntimeConfig {
	return PHPRuntimeConfig{Enabled: false, MaxChildren: 2, IdleStopSecs: 300}
}

// phpFPMCandidates 常见发行版的 php-fpm 二进制位置（Debian/Alpine/编译安装）。
var phpFPMCandidates = []string{
	"/usr/sbin/php-fpm8.4", "/usr/sbin/php-fpm8.3", "/usr/sbin/php-fpm8.2",
	"/usr/sbin/php-fpm8.1", "/usr/sbin/php-fpm8.0", "/usr/sbin/php-fpm7.4",
	"/usr/sbin/php-fpm", "/usr/local/sbin/php-fpm",
	"/usr/bin/php-fpm", "/usr/local/bin/php-fpm",
	// Alpine（apk add php83-fpm 等）
	"/usr/sbin/php-fpm84", "/usr/sbin/php-fpm83", "/usr/sbin/php-fpm82",
	"/usr/sbin/php-fpm81", "/usr/sbin/php-fpm80",
}

// runUserCandidates 降权运行用户（fpm 拒绝 root）。
var runUserCandidates = []string{"www-data", "php", "nobody", "daemon", "www"}

// PHPManager fpm 生命周期管理。
type PHPManager struct {
	app      *App
	mu       sync.Mutex
	binPath  string // 探测到的 php-fpm
	runUser  string // 降权用户（已验证存在于 /etc/passwd）
	runGroup string // 该用户的主组（从 /etc/group 按 gid 反查，兼容 Alpine/Debian）
	fpmCmd   *exec.Cmd
	pid      int
	sockDir  string
	lastUse  time.Time
	pools    map[string]string // 站点ID -> socket 路径
	stopCh   chan struct{}
	// 每个站点一个连接池
	poolMu     sync.Mutex
	poolsConns map[string]*connPool
}

func NewPHPManager(app *App) *PHPManager {
	m := &PHPManager{
		app:        app,
		sockDir:    filepath.Join(app.etcDir, "php"),
		pools:      map[string]string{},
		poolsConns: map[string]*connPool{},
		stopCh:     make(chan struct{}),
	}
	m.detect()
	go m.idleLoop()
	return m
}

// detect 探测 php-fpm 二进制与运行用户。
func (m *PHPManager) detect() {
	for _, p := range phpFPMCandidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			m.binPath = p
			break
		}
	}
	for _, u := range runUserCandidates {
		if gid, ok := primaryGroupOf(u); ok {
			m.runUser = u
			m.runGroup = gid
			break
		}
	}
}

// primaryGroupOf 校验用户存在并反查其主组名（Debian: www-data/www-data；Alpine: nobody/nobody）。
// 返回空串表示用户不存在。严格按 /etc/passwd 与 /etc/group 解析，不依赖发行版假设。
func primaryGroupOf(name string) (string, bool) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", false
	}
	var gid = -1
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 4 && f[0] == name {
			g, err := strconv.Atoi(f[3])
			if err != nil {
				return "", false
			}
			gid = g
			break
		}
	}
	if gid < 0 {
		return "", false
	}
	if gdata, err := os.ReadFile("/etc/group"); err == nil {
		for _, line := range strings.Split(string(gdata), "\n") {
			f := strings.Split(line, ":")
			if len(f) >= 3 && f[0] != "" {
				if g, err := strconv.Atoi(f[2]); err == nil && g == gid {
					return f[0], true
				}
			}
		}
	}
	// 找不到组名：用 gid 数字也能被 fpm 接受
	return strconv.Itoa(gid), true
}

// Status 运行时状态（供管理 API）。
func (m *PHPManager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	alive := m.pid != 0 && syscall.Kill(m.pid, 0) == nil
	cfg := m.app.store.Config()
	return map[string]any{
		"enabled":      cfg.PHP.Enabled,
		"available":    m.binPath != "",
		"binPath":      m.binPath,
		"running":      alive,
		"pid":          m.pid,
		"poolCount":    len(m.pools),
		"lastUse":      m.lastUse.Unix(),
		"maxChildren":  cfg.PHP.MaxChildren,
		"idleStopSecs": cfg.PHP.IdleStopSecs,
	}
}

// RebuildPools 站点变更后重建 fpm 配置（运行中则平滑 reload）。
func (m *PHPManager) RebuildPools(phpSites []*Site) {
	m.mu.Lock()
	defer m.mu.Unlock()
	newPools := map[string]string{}
	for _, st := range phpSites {
		newPools[st.ID] = filepath.Join(m.sockDir, st.ID+".sock")
	}
	m.pools = newPools
	if m.pid == 0 || syscall.Kill(m.pid, 0) != nil {
		return // 未运行：配置下次启动时生效
	}
	// 运行中：重写配置 + USR2 平滑重载
	if err := m.writeConfLocked(); err != nil {
		log.Printf("[web-manager] 重写 php-fpm 配置失败: %v", err)
		return
	}
	if err := syscall.Kill(m.pid, syscall.SIGUSR2); err != nil {
		log.Printf("[web-manager] php-fpm reload 失败，尝试重启: %v", err)
		m.stopLocked()
	}
}

// Ensure 就绪检查：返回站点 socket 是否可用，必要时拉起 fpm。
func (m *PHPManager) Ensure(siteID string) (string, error) {
	cfg := m.app.store.Config()
	if !cfg.PHP.Enabled {
		return "", fmt.Errorf("PHP 运行时未启用（设置中开启）")
	}
	m.mu.Lock()
	sock, ok := m.pools[siteID]
	if !ok {
		m.mu.Unlock()
		return "", fmt.Errorf("站点不是 PHP 站点")
	}
	alive := m.pid != 0 && syscall.Kill(m.pid, 0) == nil
	if !alive {
		if err := m.startLocked(sock); err != nil {
			m.mu.Unlock()
			return "", err
		}
	}
	m.lastUse = time.Now()
	m.mu.Unlock()
	return sock, nil
}

// startLocked 拉起 php-fpm（调用方需持锁）。waitSock：本次需要就绪的站点 socket。
func (m *PHPManager) startLocked(waitSock string) error {
	if m.binPath == "" {
		return fmt.Errorf("未找到 php-fpm（请安装 php-fpm 后重启插件）")
	}
	if m.runUser == "" {
		return fmt.Errorf("未找到可用的降权用户（www-data/php/nobody/daemon），无法安全运行 php-fpm")
	}
	if err := os.MkdirAll(m.sockDir, 0o755); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(m.sockDir, "fpm-error.log")) // 清掉上次失败日志，便于定位本次错误
	if err := m.writeConfLocked(); err != nil {
		return err
	}
	confPath := filepath.Join(m.sockDir, "fpm.conf")
	cmd := exec.Command(m.binPath, "--fpm-config", confPath, "--nodaemonize")
	cmd.Stdout = os.Stderr // fpm 日志走 stderr（面板捕获）
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("php-fpm 启动失败: %v", err)
	}
	m.fpmCmd = cmd
	m.pid = cmd.Process.Pid

	// 无论成败都立即挂 Wait：1) 避免僵尸 2) 通过 exited 通道即时感知崩溃
	reap := cmd
	exited := make(chan struct{})
	go func() {
		if err := reap.Wait(); err != nil {
			log.Printf("[web-manager] php-fpm 退出: %v", err)
		}
		close(exited)
		m.mu.Lock()
		if m.fpmCmd == reap { // 仍是同一进程才清理（Stop/超时已重置则跳过）
			m.pid = 0
			m.fpmCmd = nil
		}
		m.mu.Unlock()
	}()

	// 等 socket 就绪（最多 5 秒）；期间进程退出则立刻带上 fpm 错误日志返回
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited: // 启动即崩溃（僵尸不触发 Kill 检测，必须靠 Wait）
			return fmt.Errorf("php-fpm 启动失败: %s", fpmErrTail(m.sockDir))
		case <-time.After(100 * time.Millisecond):
		}
		if waitSock != "" {
			if fi, err := os.Stat(waitSock); err == nil && fi.Mode()&os.ModeSocket != 0 {
				log.Printf("[web-manager] php-fpm 已按需启动 pid=%d user=%s pools=%d", m.pid, m.runUser, len(m.pools))
				return nil
			}
		} else if syscall.Kill(m.pid, 0) == nil { // 无 pool 站点：进程活着即算就绪
			return nil
		}
	}
	syscall.Kill(m.pid, syscall.SIGTERM)
	m.pid = 0
	m.fpmCmd = nil
	return fmt.Errorf("php-fpm socket 未就绪（5s 超时）: %s", fpmErrTail(m.sockDir))
}

// fpmErrTail 取 fpm-error.log 最后一条 ERROR（给用户定位问题，最多 200 字符）。
func fpmErrTail(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "fpm-error.log"))
	if err != nil {
		return "详见 " + filepath.Join(dir, "fpm-error.log")
	}
	last := ""
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "ERROR") {
			last = line
		}
	}
	if len(last) > 200 {
		last = last[len(last)-200:]
	}
	if last == "" {
		return "详见 " + filepath.Join(dir, "fpm-error.log")
	}
	return last
}

// writeConfLocked 生成 fpm 配置：全局一段 + 每 PHP 站点一个 pool。
func (m *PHPManager) writeConfLocked() error {
	cfg := m.app.store.Config()
	if cfg.PHP.MaxChildren < 1 {
		cfg.PHP.MaxChildren = 2
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[global]\n")
	fmt.Fprintf(&b, "error_log = %s\n", filepath.Join(m.sockDir, "fpm-error.log"))
	fmt.Fprintf(&b, "pid = %s\n", filepath.Join(m.sockDir, "fpm.pid"))
	fmt.Fprintf(&b, "log_level = warning\n")
	fmt.Fprintf(&b, "emergency_restart_threshold = 5\n")
	fmt.Fprintf(&b, "emergency_restart_interval = 1m\n\n")
	for _, st := range m.phpSitesLocked() {
		sock := filepath.Join(m.sockDir, st.ID+".sock")
		fmt.Fprintf(&b, "[%s]\n", st.ID)
		fmt.Fprintf(&b, "listen = %s\n", sock)
		fmt.Fprintf(&b, "listen.owner = %s\n", m.runUser)
		fmt.Fprintf(&b, "listen.group = %s\n", m.runGroup)
		fmt.Fprintf(&b, "listen.mode = 0660\n")
		if m.runUser != "" && m.runUser != "root" {
			fmt.Fprintf(&b, "user = %s\n", m.runUser)
			fmt.Fprintf(&b, "group = %s\n", m.runGroup)
		}
		fmt.Fprintf(&b, "pm = ondemand\n") // 空闲零 worker
		fmt.Fprintf(&b, "pm.max_children = %d\n", cfg.PHP.MaxChildren)
		fmt.Fprintf(&b, "pm.process_idle_timeout = 10s\n")
		fmt.Fprintf(&b, "pm.max_requests = 500\n")
		fmt.Fprintf(&b, "php_admin_value[open_basedir] = %s:/usr/share/php:/tmp\n", st.Root)
		fmt.Fprintf(&b, "php_admin_value[cgi.fix_pathinfo] = 1\n")
		fmt.Fprintf(&b, "php_admin_value[upload_tmp_dir] = /tmp\n")
		fmt.Fprintf(&b, "clear_env = no\n\n")
	}
	return os.WriteFile(filepath.Join(m.sockDir, "fpm.conf"), []byte(b.String()), 0o644)
}

// phpSitesLocked 从 store 取 PHP 站点。
// 锁顺序：PHPManager.mu → store.mu（反向不存在，无死锁）。
func (m *PHPManager) phpSitesLocked() []*Site {
	var out []*Site
	for _, st := range m.app.store.Sites() {
		if st.Type == "php" {
			out = append(out, st)
		}
	}
	return out
}

// Touch 记录最近使用时间（每请求调用）。
func (m *PHPManager) Touch() {
	m.mu.Lock()
	m.lastUse = time.Now()
	m.mu.Unlock()
}

// idleLoop 空闲回收：无 PHP 请求超过 idleStopSecs 停掉 fpm（保持低占用）。
func (m *PHPManager) idleLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			cfg := m.app.store.Config()
			idle := cfg.PHP.IdleStopSecs
			if idle < 30 {
				idle = 300
			}
			m.mu.Lock()
			alive := m.pid != 0 && syscall.Kill(m.pid, 0) == nil
			if alive && time.Since(m.lastUse) > time.Duration(idle)*time.Second {
				log.Printf("[web-manager] php-fpm 空闲 %ds，自动停止（零占用）", int(time.Since(m.lastUse).Seconds()))
				m.stopLocked()
			}
			m.mu.Unlock()
		case <-m.stopCh:
			return
		}
	}
}

// stopLocked 停止 fpm（调用方持锁）。
func (m *PHPManager) stopLocked() {
	if m.pid != 0 {
		syscall.Kill(m.pid, syscall.SIGTERM)
	}
	m.pid = 0
	m.fpmCmd = nil
	// 清理 socket 池
	m.poolMu.Lock()
	for _, p := range m.poolsConns {
		p.closeAll()
	}
	m.poolsConns = map[string]*connPool{}
	m.poolMu.Unlock()
	for id := range m.pools {
		_ = os.Remove(filepath.Join(m.sockDir, id+".sock"))
	}
}

// Stop 显式停止（禁用 PHP 或插件退出时）。
func (m *PHPManager) Stop() {
	m.mu.Lock()
	m.stopLocked()
	m.mu.Unlock()
}

// ConnPool 站点连接池（懒创建）。
func (m *PHPManager) ConnPool(siteID string) *connPool {
	m.poolMu.Lock()
	defer m.poolMu.Unlock()
	if p, ok := m.poolsConns[siteID]; ok {
		return p
	}
	sid := siteID
	p := newConnPool(func() (string, bool) {
		m.mu.Lock()
		sock, ok := m.pools[sid]
		alive := m.pid != 0 && syscall.Kill(m.pid, 0) == nil
		m.mu.Unlock()
		if !ok || !alive {
			return "", false
		}
		return sock, true
	})
	m.poolsConns[sid] = p
	return p
}

// FPMVersion php 版本信息（探测用）。
func (m *PHPManager) FPMVersion() string {
	if m.binPath == "" {
		return ""
	}
	if out, err := exec.Command(m.binPath, "-v").Output(); err == nil {
		first := strings.SplitN(string(out), "\n", 2)[0]
		return strings.TrimSpace(first)
	}
	return ""
}
