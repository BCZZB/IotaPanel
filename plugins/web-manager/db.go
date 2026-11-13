// SPDX-License-Identifier: Apache-2.0
// MySQL/MariaDB 按需运行时：平时完全不运行（零内存），首个连接才拉起 mysqld，空闲自动停止。
// 原理：插件在 127.0.0.1:3306 常驻一个极轻的 TCP 唤醒代理 → 连接到来时启动 mysqld 并桥接到
// 本地 unix socket；无活跃连接且空闲超时则停掉 mysqld 释放全部内存。代理本身仅两个 goroutine。
// mysqld 仅监听 socket（skip-networking），不对外暴露任何端口。
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// mysqldCandidates 常见发行版的服务端二进制位置。
var mysqldCandidates = []string{
	"/usr/sbin/mysqld", "/usr/bin/mysqld", // Alpine（mariadb 软链）
	"/usr/sbin/mariadbd", "/usr/bin/mariadbd",
	"/usr/local/mysql/bin/mysqld",
}

var mysqlClientCandidates = []string{
	"/usr/bin/mysql", "/usr/local/bin/mysql", "/usr/local/mysql/bin/mysql",
}

var installDBCandidates = []string{
	"/usr/bin/mysql_install_db", "/usr/bin/mariadb-install-db",
	"/usr/scripts/mysql_install_db", "/usr/local/mysql/scripts/mysql_install_db",
}

// dbRunUserCandidates mysqld 降权用户（拒绝 root 跑 mysqld）。
var dbRunUserCandidates = []string{"mysql", "mariadb"}

// MySQLManager 数据库生命周期管理。
type MySQLManager struct {
	app     *App
	mu      sync.Mutex
	binPath string // mysqld
	cliPath string // mysql 客户端
	instBin string // mysql_install_db
	runUser string
	runUID  int
	runGid  int

	sockPath string
	confPath string
	dataDir  string
	baseDir  string // <etcDir>/mysql

	cmd     *exec.Cmd
	pid     int
	exited  chan struct{}
	pendingRootPwd string // 首启待设置的 root 密码（就绪后落库）
	active  atomic.Int32 // 活跃代理连接数
	lastUse time.Time
	ln      net.Listener // 唤醒代理监听
	lnErr   string
	stopCh  chan struct{}
}

func NewMySQLManager(app *App) *MySQLManager {
	m := &MySQLManager{
		app:     app,
		baseDir: filepath.Join(app.etcDir, "mysql"),
		stopCh:  make(chan struct{}),
	}
	m.sockPath = filepath.Join(m.baseDir, "mysqld.sock")
	m.confPath = filepath.Join(m.baseDir, "my.cnf")
	m.dataDir = filepath.Join(m.baseDir, "data")
	m.detect()
	go m.idleLoop()
	m.applyProxy() // 配置开启时启动唤醒代理
	return m
}

// detect 探测二进制与降权用户。
func (m *MySQLManager) detect() {
	for _, p := range mysqldCandidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			m.binPath = p
			break
		}
	}
	for _, p := range mysqlClientCandidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			m.cliPath = p
			break
		}
	}
	for _, p := range installDBCandidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			m.instBin = p
			break
		}
	}
	for _, u := range dbRunUserCandidates {
		if uid, gid := unixUserIDs(u); uid >= 0 {
			m.runUser = u
			m.runUID = uid
			m.runGid = gid
			break
		}
	}
}

// unixUserIDs 查 /etc/passwd 取 uid/gid（找不到返回 -1,-1）。
func unixUserIDs(name string) (int, int) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return -1, -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 4 && f[0] == name {
			uid, gid := 0, 0
			fmt.Sscanf(f[2], "%d", &uid)
			fmt.Sscanf(f[3], "%d", &gid)
			return uid, gid
		}
	}
	return -1, -1
}

// ---------- 唤醒代理 ----------

// applyProxy 按配置启停 TCP 唤醒代理（端口变化时重建）。
func (m *MySQLManager) applyProxy() {
	cfg := m.app.store.Config()
	m.mu.Lock()
	wantPort := 0
	if cfg.MySQL.Enabled {
		wantPort = cfg.MySQL.Port
	}
	ln, lnErr := m.ln, m.lnErr
	m.mu.Unlock()

	if wantPort == 0 { // 关闭：撤下代理
		if ln != nil {
			_ = ln.Close()
			m.mu.Lock()
			m.ln = nil
			m.mu.Unlock()
			log.Printf("[web-manager] MySQL 唤醒代理已停止")
		}
		m.Stop()
		return
	}
	if ln != nil && lnErr == "" { // 已在监听：端口没变就复用
		if cur := ln.Addr().(*net.TCPAddr).Port; cur == wantPort {
			return
		}
		_ = ln.Close()
	}
	// （重）监听 127.0.0.1:port
	newLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", wantPort))
	m.mu.Lock()
	m.ln = newLn
	m.lnErr = ""
	if err != nil {
		m.ln = nil
		m.lnErr = err.Error()
	}
	m.mu.Unlock()
	if err != nil {
		log.Printf("[web-manager] MySQL 唤醒代理监听失败: %v", err)
		return
	}
	log.Printf("[web-manager] MySQL 唤醒代理 127.0.0.1:%d 就绪（mysqld 待命中，零占用）", wantPort)
	go m.proxyLoop(newLn)
}

func (m *MySQLManager) proxyLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return // listener 被关闭（配置变更）
		}
		go m.bridge(c)
	}
}

// bridge 单个连接：确保 mysqld 运行 → 双向桥接到 unix socket。
func (m *MySQLManager) bridge(c net.Conn) {
	cfg := m.app.store.Config()
	if !cfg.MySQL.Enabled {
		_ = c.Close()
		return
	}
	if err := m.EnsureRunning(); err != nil {
		log.Printf("[web-manager] MySQL 唤醒失败: %v", err)
		_ = c.Close()
		return
	}
	m.active.Add(1)
	defer m.active.Add(-1)
	m.Touch()
	up, err := net.DialTimeout("unix", m.sockPath, 5*time.Second)
	if err != nil {
		_ = c.Close()
		return
	}
	// 双向转发；任一方向结束即断开（MySQL 协议两端同步收发）
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
	_ = c.Close()
	_ = up.Close()
	<-done
}

// ---------- 生命周期 ----------

// EnsureRunning 保证 mysqld 运行中（连接/管理操作前调用）。
func (m *MySQLManager) EnsureRunning() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pid != 0 && syscall.Kill(m.pid, 0) == nil {
		return nil
	}
	return m.startLocked()
}

// startLocked 拉起 mysqld（调用方持锁）。
func (m *MySQLManager) startLocked() error {
	if m.binPath == "" {
		return fmt.Errorf("未找到 mysqld（安装 mariadb / mysql-server 后重启插件）")
	}
	if m.runUser == "" {
		return fmt.Errorf("未找到可用的降权用户（mysql），无法安全运行 mysqld")
	}
	if err := m.prepareLocked(); err != nil { // 初始化数据目录（首次）+ 配置
		return err
	}
	cmd := exec.Command(m.binPath, "--defaults-file="+m.confPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("mysqld 启动失败: %v", err)
	}
	m.cmd = cmd
	m.pid = cmd.Process.Pid
	m.lastUse = time.Now()

	reap := cmd
	exited := make(chan struct{})
	m.exited = exited
	go func() {
		if err := reap.Wait(); err != nil {
			log.Printf("[web-manager] mysqld 退出: %v", err)
		}
		close(exited)
		m.mu.Lock()
		if m.cmd == reap {
			m.pid = 0
			m.cmd = nil
		}
		m.mu.Unlock()
	}()

	// 等 socket 可用 + 能执行 SQL（首启含初始化，放宽到 45s）
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			return fmt.Errorf("mysqld 启动即退出: %s", m.errTail())
		case <-time.After(300 * time.Millisecond):
		}
		if m.pingLocked() == nil {
			log.Printf("[web-manager] mysqld 已按需启动 pid=%d user=%s（低内存配置）", m.pid, m.runUser)
			return nil
		}
	}
	syscall.Kill(m.pid, syscall.SIGTERM)
	m.pid = 0
	m.cmd = nil
	return fmt.Errorf("mysqld 就绪超时（45s）: %s", m.errTail())
}

// prepareLocked 首次初始化数据目录 + 生成 my.cnf + root 密码。
func (m *MySQLManager) prepareLocked() error {
	if err := os.MkdirAll(m.baseDir, 0o755); err != nil {
		return err
	}
	// baseDir 本身也要授权：mysqld（降权用户）需要在这里写 sock / pid / error log
	if err := os.Chown(m.baseDir, m.runUID, m.runGid); err != nil {
		return fmt.Errorf("运行目录授权失败: %v", err)
	}
	// 数据目录未初始化：跑 mysql_install_db
	if _, err := os.Stat(filepath.Join(m.dataDir, "mysql")); os.IsNotExist(err) {
		if m.instBin == "" {
			return fmt.Errorf("未找到 mysql_install_db，无法初始化数据目录")
		}
		if err := os.MkdirAll(m.dataDir, 0o700); err != nil {
			return err
		}
		if err := chownAll(m.dataDir, m.runUID, m.runGid); err != nil {
			return fmt.Errorf("数据目录授权失败: %v", err)
		}
		inst := exec.Command(m.instBin, "--datadir="+m.dataDir, "--auth-root-authentication-method=normal",
			"--skip-test-db", "--user="+m.runUser)
		out, err := inst.CombinedOutput()
		if err != nil {
			return fmt.Errorf("mysql_install_db 失败: %v: %s", err, lastLines(out, 3))
		}
		log.Printf("[web-manager] MySQL 数据目录初始化完成")
	}
	if err := m.writeConfLocked(); err != nil {
		return err
	}
	// root 密码：首次生成并落库（存储于 config.json，0600）
	cfg := m.app.store.Config()
	if cfg.MySQL.RootPassword == "" {
		pwd, err := genPassword(24)
		if err != nil {
			return err
		}
		// 首启 root 为空密码：改密必须在服务起来后做，这里先暂存，就绪后由 setRootPassword 完成
		m.pendingRootPwd = pwd
	} else {
		m.pendingRootPwd = ""
	}
	return nil
}

// writeConfLocked 低内存 my.cnf（socket-only，不监听 TCP）。
func (m *MySQLManager) writeConfLocked() error {
	var b strings.Builder
	fmt.Fprintf(&b, "[mysqld]\n")
	fmt.Fprintf(&b, "skip-networking\n") // 只走 unix socket，TCP 由插件代理唤醒
	fmt.Fprintf(&b, "socket = %s\n", m.sockPath)
	fmt.Fprintf(&b, "pid-file = %s\n", filepath.Join(m.baseDir, "mysqld.pid"))
	fmt.Fprintf(&b, "datadir = %s\n", m.dataDir)
	fmt.Fprintf(&b, "tmpdir = /tmp\n")
	fmt.Fprintf(&b, "user = %s\n", m.runUser)
	fmt.Fprintf(&b, "\n# ---- 低内存 ----\n")
	fmt.Fprintf(&b, "performance_schema = OFF\n")
	fmt.Fprintf(&b, "skip-name-resolve\n")
	fmt.Fprintf(&b, "max_connections = 30\n")
	fmt.Fprintf(&b, "key_buffer_size = 2M\n")
	fmt.Fprintf(&b, "max_allowed_packet = 16M\n")
	fmt.Fprintf(&b, "table_open_cache = 64\n")
	fmt.Fprintf(&b, "innodb_buffer_pool_size = 16M\n")
	fmt.Fprintf(&b, "innodb_log_buffer_size = 1M\n")
	fmt.Fprintf(&b, "innodb_flush_log_at_trx_commit = 2\n")
	fmt.Fprintf(&b, "log_error = %s\n", filepath.Join(m.baseDir, "mysqld-error.log"))
	return os.WriteFile(m.confPath, []byte(b.String()), 0o644)
}

// pingLocked 用 CLI 探活（socket + SELECT 1）。
func (m *MySQLManager) pingLocked() error {
	if _, err := os.Stat(m.sockPath); err != nil {
		return err
	}
	_, err := m.runSQLLocked("SELECT 1")
	return err
}

// runSQLLocked 通过 unix socket 执行 SQL（管理通道，不走 TCP 代理避免递归唤醒等待）。
func (m *MySQLManager) runSQLLocked(sql string) (string, error) {
	if m.cliPath == "" {
		return "", fmt.Errorf("未找到 mysql 客户端（安装 mariadb-client）")
	}
	cfg := m.app.store.Config()
	cmd := exec.Command(m.cliPath, "--socket="+m.sockPath, "-u", "root", "-N", "-B", "-e", sql)
	cmd.Env = append(os.Environ(), "MYSQL_PWD="+cfg.MySQL.RootPassword)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%v: %s", err, lastLines(out, 2))
	}
	return string(out), nil
}

// setRootPassword 首启后设置 root 密码并持久化。
func (m *MySQLManager) setRootPassword(pwd string) error {
	if m.cliPath == "" {
		return fmt.Errorf("未找到 mysql 客户端")
	}
	cmd := exec.Command(m.cliPath, "--socket="+m.sockPath, "-u", "root",
		"-e", "ALTER USER 'root'@'localhost' IDENTIFIED BY '"+pwd+"'")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("设置 root 密码失败: %v: %s", err, lastLines(out, 2))
	}
	cfg := m.app.store.Config()
	cfg.MySQL.RootPassword = pwd
	m.app.store.SetConfig(cfg)
	if err := m.app.store.SaveConfig(); err != nil {
		return err
	}
	log.Printf("[web-manager] MySQL root 密码已生成并安全存储")
	return nil
}

// Touch / idleLoop / Stop 同 php.go 哲学。
func (m *MySQLManager) Touch() {
	m.mu.Lock()
	m.lastUse = time.Now()
	m.mu.Unlock()
}

func (m *MySQLManager) idleLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			cfg := m.app.store.Config()
			idle := cfg.MySQL.IdleStopSecs
			if idle < 30 {
				idle = 300
			}
			m.mu.Lock()
			alive := m.pid != 0 && syscall.Kill(m.pid, 0) == nil
			if alive && m.active.Load() == 0 && time.Since(m.lastUse) > time.Duration(idle)*time.Second {
				log.Printf("[web-manager] mysqld 空闲 %ds，自动停止（零占用）", int(time.Since(m.lastUse).Seconds()))
				m.stopLocked()
			}
			m.mu.Unlock()
		case <-m.stopCh:
			return
		}
	}
}

func (m *MySQLManager) stopLocked() {
	if m.pid != 0 {
		syscall.Kill(m.pid, syscall.SIGTERM)
		// 优雅退出最多等 8 秒，超时强杀
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if syscall.Kill(m.pid, 0) != nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if syscall.Kill(m.pid, 0) == nil {
			syscall.Kill(m.pid, syscall.SIGKILL)
		}
	}
	m.pid = 0
	m.cmd = nil
	_ = os.Remove(m.sockPath)
	_ = os.Remove(filepath.Join(m.baseDir, "mysqld.pid"))
}

func (m *MySQLManager) Stop() {
	m.mu.Lock()
	m.stopLocked()
	m.mu.Unlock()
}

// ---------- 管理操作（对外） ----------

// Exec 执行管理 SQL：自动确保运行，可能触发首启 root 密码初始化。
func (m *MySQLManager) Exec(sql string) (string, error) {
	if err := m.EnsureRunning(); err != nil {
		return "", err
	}
	m.mu.Lock()
	if m.pendingRootPwd != "" {
		pwd := m.pendingRootPwd
		m.pendingRootPwd = ""
		m.mu.Unlock()
		if err := m.setRootPassword(pwd); err != nil {
			return "", err
		}
		m.mu.Lock()
	}
	defer m.mu.Unlock()
	m.lastUse = time.Now()
	return m.runSQLLocked(sql)
}

// Running mysqld 是否已在运行（纯读，绝不触发唤醒）。
func (m *MySQLManager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pid != 0 && syscall.Kill(m.pid, 0) == nil
}

// Status 运行状态。
func (m *MySQLManager) Status() map[string]any {
	cfg := m.app.store.Config()
	m.mu.Lock()
	defer m.mu.Unlock()
	alive := m.pid != 0 && syscall.Kill(m.pid, 0) == nil
	var rss int
	if alive {
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", m.pid)); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "VmRSS:") {
					fmt.Sscanf(strings.TrimPrefix(line, "VmRSS:"), "%d", &rss)
					break
				}
			}
		}
	}
	return map[string]any{
		"enabled":      cfg.MySQL.Enabled,
		"available":    m.binPath != "",
		"binPath":      m.binPath,
		"cliAvailable": m.cliPath != "",
		"running":      alive,
		"pid":          m.pid,
		"activeConns":  m.active.Load(),
		"rssKB":        rss,
		"port":         cfg.MySQL.Port,
		"proxyErr":     m.lnErr,
		"lastUse":      m.lastUse.Unix(),
		"idleStopSecs": cfg.MySQL.IdleStopSecs,
	}
}

// ApplyConfig 配置变更后调用（代理端口/开关）。
func (m *MySQLManager) ApplyConfig() {
	m.applyProxy()
}

// ---------- 工具 ----------

func genPassword(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b)[:n], nil
}

func chownAll(dir string, uid, gid int) error {
	return filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(p, uid, gid)
	})
}

func lastLines(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.TrimSpace(strings.Join(lines, " | "))
}

func (m *MySQLManager) errTail() string {
	data, err := os.ReadFile(filepath.Join(m.baseDir, "mysqld-error.log"))
	if err != nil {
		return "详见 " + filepath.Join(m.baseDir, "mysqld-error.log")
	}
	return lastLines(data, 2)
}
