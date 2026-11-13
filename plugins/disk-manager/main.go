// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 plainfate <https://github.com/plainfate>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// 磁盘管理插件 —— 探针 / 主进程 双模式单二进制。
//
// 设计目标（省内存）：
//   - 探针模式（常驻，keepalive=true）：进程极小（空闲约 3-5MB），只负责
//     ① 服务前端页面；② 收到 /api/* 请求时按需拉起主进程并反向代理转发。
//     本身不扫描磁盘、不解析日志。
//   - 主进程模式（子进程，按需唤醒）：由探针以【同一二进制】exec 拉起，
//     设置环境变量 IS_WORKER=1 切换。磁盘扫描、大文件检测、访问日志解析
//     等重活全部在子进程完成；空闲约 90 秒自动退出，内存立即释放。
//
// 单二进制的做法同时兼容官方 build.sh 的一次性内嵌打包，无需单独管理子进程产物。
package main

import (
	"bufio"
	"embed"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed web
var webFS embed.FS

const (
	workerAddr = "127.0.0.1"
	wakeTimeout = 10 * time.Second // 等待主进程就绪的最长时间
)

// 主进程句柄（探针持有，全局唯一）
var (
	workerMu    sync.Mutex
	workerCmd   *exec.Cmd
	workerURL   *url.URL
	workerAlive bool
)

func main() {
	// 子进程模式（由探针 exec 拉起）：直接运行工作逻辑，不启动探针。
	if os.Getenv("IS_WORKER") == "1" {
		runWorker()
		return
	}
	runProbe()
}

// ---------- 探针模式 ----------

func runProbe() {
	port := os.Getenv("PLUGIN_PORT")
	bind := envOr("PLUGIN_BIND", "127.0.0.1")
	if port == "" {
		port = "19004"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			apiProxy.ServeHTTP(w, r)
			return
		}
		handleIndex(w, r)
	})

	addr := bind + ":" + port
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		log.Printf("[disk-manager] 探针收到退出信号，已唤醒的主进程将被关闭")
		stopWorker()
		server.Close()
	}()
	log.Printf("[disk-manager] 探针已就绪（极省内存模式），listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		if !strings.Contains(err.Error(), "use of closed network connection") {
			log.Fatal(err)
		}
	}
}

// handleIndex 服务内嵌前端页面（仅根路径）
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "页面资源缺失", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// apiProxy 确保主进程已就绪，然后把 /api/* 反向代理到主进程。
var apiProxy = &httputil.ReverseProxy{
	Director: func(req *http.Request) {
		target, err := ensureWorker()
		if err != nil {
			// 无法调度主进程时，指向不可达端口触发 502 由前端兜底。
			req.URL.Scheme = "http"
			req.URL.Host = "127.0.0.1:1"
			return
		}
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
	},
	ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "主进程不可用", http.StatusBadGateway)
	},
}

// ensureWorker 确保主进程已启动并就绪，返回其 URL。
func ensureWorker() (*url.URL, error) {
	workerMu.Lock()
	defer workerMu.Unlock()

	if workerURL != nil && workerAlive {
		return workerURL, nil
	}

	// 占用一个空闲端口传给主进程（探针与面板同机，端口不冲突即可）。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	freePort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(),
		"IS_WORKER=1",
		"WORKER_ADDR="+workerAddr,
		"WORKER_PORT="+strconv.Itoa(freePort),
	)
	// 主进程 stdout 走“就绪协议 + 日志”，stderr 一并汇入探针日志
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// 后台等待主进程退出，清空句柄以便下次重新拉起
	go func() {
		_ = cmd.Wait()
		workerMu.Lock()
		if workerCmd == cmd {
			workerCmd = nil
			workerURL = nil
			workerAlive = false
		}
		workerMu.Unlock()
		log.Printf("[disk-manager] 主进程已退出，内存已释放")
	}()

	// 就绪协议：主进程启动后在 stdout 首行打印 _READY_<port>
	ready := make(chan struct{})
	var closeOnce sync.Once
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "_READY_") {
				if p, err := strconv.Atoi(strings.TrimPrefix(line, "_READY_")); err == nil && p > 0 {
					u, _ := url.Parse("http://" + workerAddr + ":" + strconv.Itoa(p))
					workerURL = u
					workerCmd = cmd
					workerAlive = true
				}
				closeOnce.Do(func() { close(ready) })
				continue
			}
			if line != "" {
				log.Printf("[disk-manager][worker] %s", line)
			}
		}
		// stdout 关闭（主进程退出）时若还未就绪也放行
		closeOnce.Do(func() { close(ready) })
	}()

	select {
	case <-ready:
	case <-time.After(wakeTimeout):
		_ = cmd.Process.Kill()
		return nil, errors.New("主进程启动超时")
	}
	if workerURL == nil {
		return nil, errors.New("主进程就绪协议异常")
	}
	return workerURL, nil
}

// stopWorker 停止主进程（探针退出时调用）
func stopWorker() {
	workerMu.Lock()
	defer workerMu.Unlock()
	if workerCmd != nil && workerCmd.Process != nil {
		_ = workerCmd.Process.Signal(syscall.SIGTERM)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}