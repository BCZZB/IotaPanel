// SPDX-License-Identifier: Apache-2.0
// 插件发现与优雅启停：
//   停止 = SIGTERM(插件规范约定收到 SIGTERM 优雅退出，面板自动清理登记)
//   启动 = 优先请求面板 /p/<name>/ 触发懒启动；失败则直接托管拉起二进制
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const SelfName = "ai-guardian"

// PluginInfo 面板已安装插件
type PluginInfo struct {
	Name    string `json:"name"`
	Title   string `json:"title"`
	Command string `json:"command"`
	Running bool   `json:"running"`
	PID     int    `json:"pid"`
	RSSKB   int    `json:"rssKB"`
	Watched bool   `json:"watched"`
}

// manifestLight 轻量解析 manifest.yaml(仅取需要的字段，避免引入 yaml 依赖)
func manifestLight(dir string) (title, command string) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
	if err != nil {
		return "", ""
	}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "title:") {
			title = strings.TrimSpace(strings.TrimPrefix(ln, "title:"))
		}
		if strings.HasPrefix(ln, "command:") {
			command = strings.TrimSpace(strings.TrimPrefix(ln, "command:"))
		}
	}
	return
}

// listPlugins 枚举已安装插件并合并运行状态
func listPlugins(home string, cfg Config) []PluginInfo {
	var out []PluginInfo
	if home == "" {
		home = "/data/panel"
	}
	procs := scanPluginProcs(home)
	entries, err := os.ReadDir(filepath.Join(home, "plugins"))
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == SelfName {
			continue
		}
		title, command := manifestLight(filepath.Join(home, "plugins", name))
		pi := PluginInfo{Name: name, Title: title, Command: command, Watched: watchAllowed(cfg, name)}
		if st, ok := procs[name]; ok {
			pi.Running = true
			pi.RSSKB = st.RSSKB
			// 取任一 pid 作为代表
			pi.PID = firstPID(home, name)
		}
		out = append(out, pi)
	}
	return out
}

func firstPID(home, name string) int {
	entries, _ := os.ReadDir("/proc")
	marker := "/plugins/" + name + "/"
	for _, e := range entries {
		if !e.IsDir() || e.Name()[0] < '0' || e.Name()[0] > '9' {
			continue
		}
		cb, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		if strings.Contains(string(cb), marker) {
			return atoiSafe(e.Name())
		}
	}
	return 0
}

func watchAllowed(cfg Config, name string) bool {
	if name == SelfName {
		return false
	}
	for _, w := range cfg.Watch {
		if w == "*" || w == name {
			return true
		}
	}
	return false
}

// stopPlugin 优雅停止：SIGTERM 后等待退出
func stopPlugin(home, name string) (string, error) {
	if name == SelfName {
		return "", fmt.Errorf("不能停止自身")
	}
	pids := allPIDs(home, name)
	if len(pids) == 0 {
		return "插件未在运行", nil
	}
	for _, pid := range pids {
		syscall.Kill(pid, syscall.SIGTERM)
	}
	// 最多等 6 秒确认退出
	for i := 0; i < 12; i++ {
		time.Sleep(500 * time.Millisecond)
		if len(allPIDs(home, name)) == 0 {
			return fmt.Sprintf("已优雅停止 (原 pid: %v)", pids), nil
		}
	}
	// 兜底强杀
	for _, pid := range allPIDs(home, name) {
		syscall.Kill(pid, syscall.SIGKILL)
	}
	return fmt.Sprintf("已强制停止 (原 pid: %v)", pids), nil
}

func allPIDs(home, name string) []int {
	var pids []int
	entries, _ := os.ReadDir("/proc")
	marker := "/plugins/" + name + "/"
	for _, e := range entries {
		if !e.IsDir() || e.Name()[0] < '0' || e.Name()[0] > '9' {
			continue
		}
		cb, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		if strings.Contains(string(cb), marker) {
			pids = append(pids, atoiSafe(e.Name()))
		}
	}
	return pids
}

// startPlugin 启动插件：
//  1. 已在运行 → 直接返回
//  2. 请求面板 /p/<name>/ 懒启动(面板核心会按规范拉起并登记)
//  3. 面板不可用时直接拉起二进制(面板重启后会自动 adopt)
func startPlugin(home, name, panelAddr string) (string, error) {
	if name == SelfName {
		return "", fmt.Errorf("自身无需此方式启动")
	}
	if len(allPIDs(home, name)) > 0 {
		return "插件已在运行", nil
	}
	// 读取插件信息
	if home == "" {
		home = "/data/panel"
	}
	pdir := filepath.Join(home, "plugins", name)
	if _, err := os.Stat(pdir); err != nil {
		return "", fmt.Errorf("插件未安装: %s", name)
	}
	_, command := manifestLight(pdir)
	if command == "" {
		command = "bin/" + name
	}
	bin := filepath.Join(pdir, command)

	// 方式1: 面板懒启动
	if panelAddr != "" {
		client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Get(strings.TrimRight(panelAddr, "/") + "/p/" + name + "/")
		if err == nil {
			resp.Body.Close()
			time.Sleep(1 * time.Second)
			if len(allPIDs(home, name)) > 0 {
				return "已通过面板启动", nil
			}
		}
	}

	// 方式2: 直接拉起(setsid 独立会话，面板重启时会 adopt)
	port := freePort(19000, 19999)
	if port == 0 {
		return "", fmt.Errorf("端口池 19000-19999 已耗尽")
	}
	cmd := exec.Command(bin)
	cmd.Dir = pdir
	cmd.Env = append(os.Environ(),
		"PLUGIN_PORT="+fmt.Sprint(port),
		"PLUGIN_BIND=127.0.0.1",
		"PANEL_HOME="+home,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	devnull, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if devnull != nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("直接启动失败: %v", err)
	}
	time.Sleep(800 * time.Millisecond)
	if len(allPIDs(home, name)) == 0 {
		return "", fmt.Errorf("进程启动后立即退出")
	}
	return fmt.Sprintf("已直接托管启动 (端口 %d, 面板重启后会自动接管)", port), nil
}

// freePort 在 [lo,hi] 中寻找一个可用端口
func freePort(lo, hi int) int {
	for p := lo + 10; p <= hi; p++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			ln.Close()
			return p
		}
	}
	return 0
}
