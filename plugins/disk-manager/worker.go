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

// 主进程模式（IS_WORKER=1 时由探针 exec 拉起）。
// 承载磁盘总览、空间分析、大文件检测、访问统计等重活；空闲自动退出释放内存。
//
// 空间分析引擎设计（借鉴开源项目）：
//   - ncdu ：单遍扫描构建完整目录树，之后任意层级钻取零重扫（缓存命中）
//   - gdu  ：有界并行遍历（goroutine 工作池），多核加速
//   - ncdu ：硬链接按 (dev,inode) 去重，不重复计入占用
//   - dust ：自底向上聚合目录体积/文件数，每层按大小截断 Top-K 控制内存
package main

import (
	"bufio"
	"bytes"
	"container/heap"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultIdleTimeout = 90 * time.Second // 空闲自动退出时间（可用 WORKER_IDLE 覆盖）
	workerAddrDef      = "127.0.0.1"
	workerPortDef      = "19200"
)

// 扫描引擎参数
const (
	maxScanEntries = 400000 // 全局条目上限（防失控，达到后停止深入）
	maxChildren    = 2000   // 每目录保留的子项数（按大小截断；聚合总量始终完整）
	topFilesCap    = 4000   // 大文件候选堆容量（内存有界）
)

// 空闲自动退出时间，支持环境变量 WORKER_IDLE 覆盖（如 "30s"/"5m"）
var idleTimeout = func() time.Duration {
	if v := os.Getenv("WORKER_IDLE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return defaultIdleTimeout
}()

// 并发扫描数（受 CPU 数与内存约束）
var maxWorkers = func() int {
	n := runtime.NumCPU()
	if n > 8 {
		n = 8
	}
	if n < 2 {
		n = 2
	}
	return n
}()

// 常用访问日志候选路径（含常见轮转）
var accessLogCandidates = []string{
	"/var/log/nginx/access.log",
	"/var/log/nginx/access.log.1",
	"/var/log/apache2/access.log",
	"/var/log/apache2/access.log.1",
	"/var/log/httpd/access_log",
	"/var/log/httpd/access_log.1",
}

// 空闲计时
var (
	touchMu sync.Mutex
	lastAt  time.Time
)

func runWorker() {
	addr := envOr("WORKER_ADDR", workerAddrDef)
	port := os.Getenv("WORKER_PORT")
	if port == "" {
		port = workerPortDef
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/disks", handleWorkerDisks)
	mux.HandleFunc("POST /api/scan", handleScanStart)     // 启动异步扫描（ncdu 式建树）
	mux.HandleFunc("GET /api/progress", handleScanProgress) // 扫描实时进度
	mux.HandleFunc("GET /api/tree", handleTreeNode)        // 树缓存钻取（瞬时）
	mux.HandleFunc("GET /api/bigfiles", handleBigFiles)    // 大文件 Top-N（来自扫描堆）
	mux.HandleFunc("GET /api/access", handleWorkerAccess)
	mux.HandleFunc("GET /api/logenv", handleWorkerLogEnv)

	addr = addr + ":" + port
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[disk-manager] 主进程监听失败 %s: %v", addr, err)
	}
	// 端口已实际监听成功后，才向探针报就绪（确保转发可用）
	fmt.Fprintf(os.Stdout, "_READY_%s\n", port)
	log.Printf("[disk-manager] 主进程已启动，listening on %s", addr)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	// 空闲自退：无请求超过 idleTimeout 则退出，释放内存
	lastAt = time.Now()
	checkEvery := idleTimeout / 3
	if checkEvery < time.Second {
		checkEvery = time.Second
	}
	if checkEvery > 10*time.Second {
		checkEvery = 10 * time.Second
	}
	go func() {
		for {
			time.Sleep(checkEvery)
			touchMu.Lock()
			idle := time.Since(lastAt)
			touchMu.Unlock()
			if idle > idleTimeout {
				log.Printf("[disk-manager] 主进程空闲 %v，自动退出", idle.Round(time.Second))
				_ = server.Close()
				os.Exit(0)
			}
		}
	}()

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		_ = server.Close()
	}()

	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// touch 记录最近活跃时间
func touch() {
	touchMu.Lock()
	lastAt = time.Now()
	touchMu.Unlock()
}

// ---------- 磁盘总览 ----------

type diskInfo struct {
	Mount   string  `json:"mount"`
	Fs      string  `json:"fs"`
	Total   uint64  `json:"total"`
	Used    uint64  `json:"used"`
	Free    uint64  `json:"free"`
	Percent float64 `json:"percent"`
}

func handleWorkerDisks(w http.ResponseWriter, r *http.Request) {
	touch()
	writeJSON(w, listDisks())
}

func listDisks() []diskInfo {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return []diskInfo{}
	}
	var disks []diskInfo
	// 按 stat 设备号去重（df 语义）：同一块盘的多个挂载点只展示一次，
	// 避免容器/bind-mount 场景下同一文件系统被重复列出（如 / 与 /data/user）。
	seen := make(map[uint64]bool)
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		mount, fs := f[1], f[2]
		// 排除伪/虚拟文件系统，只统计真实磁盘与常见存储
		if isVirtFS(fs) || isSysSpecial(mount) {
			continue
		}
		var st syscall.Statfs_t
		if err := syscall.Statfs(mount, &st); err != nil {
			continue
		}
		// 设备号去重：overlay/绑定挂载的多个挂载点共享同一设备
		var id syscall.Stat_t
		if err := syscall.Stat(mount, &id); err == nil {
			if seen[id.Dev] {
				continue
			}
			seen[id.Dev] = true
			// 单文件挂载（如容器注入的 /etc/hosts）不是磁盘，跳过
			if id.Mode&syscall.S_IFMT != syscall.S_IFDIR {
				continue
			}
		}
		total := st.Blocks * uint64(st.Bsize)
		free := st.Bavail * uint64(st.Bsize)
		used := total - free
		pct := 0.0
		if total > 0 {
			pct = float64(used) / float64(total) * 100
		}
		disks = append(disks, diskInfo{
			Mount: mount, Fs: fs,
			Total: total, Used: used, Free: free, Percent: pct,
		})
	}
	return disks
}

// isVirtFS 是否为伪/虚拟文件系统（应排除）
func isVirtFS(fs string) bool {
	switch fs {
	case "proc", "sysfs", "cgroup", "cgroup2", "devpts", "tmpfs", "devtmpfs",
		"securityfs", "pstore", "bpf", "autofs", "mqueue", "debugfs", "tracefs",
		"binfmt_misc", "configfs", "fuse.lxcfs", "ramfs":
		return true
	}
	return false
}

func isSysSpecial(mount string) bool {
	switch mount {
	case "/proc", "/sys", "/dev", "/run", "/boot/efi":
		return true
	}
	if strings.HasPrefix(mount, "/sys/") || strings.HasPrefix(mount, "/proc/") ||
		strings.HasPrefix(mount, "/dev/") || strings.HasPrefix(mount, "/run/") {
		return true
	}
	return false
}

// ============================================================
// 空间分析引擎：单遍建树 + 并行遍历 + 硬链接去重 + 树缓存钻取
// ============================================================

// treeNode 目录树节点。目录 Size 为递归聚合值。
type treeNode struct {
	Name     string      `json:"name"`
	Path     string      `json:"path"`
	Size     uint64      `json:"size"`
	Files    uint64      `json:"files"` // 子树内文件数
	Dirs     uint64      `json:"dirs"`  // 子树内目录数
	IsDir    bool        `json:"is_dir"`
	Children []*treeNode `json:"children,omitempty"`

	// 扫描期内部状态（不序列化）
	mu        sync.Mutex // 保护 fileKids/dirDone/pending/finalized
	parent    *treeNode
	fileKids  []*treeNode // 直接文件子项
	dirDone   []*treeNode // 已完成聚合的目录子项
	pending   int         // 未完成的目录子项数
	finalized bool        // 聚合完成标记（防重复 finalize）
}

// fileEntry 大文件候选
type fileEntry struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Size uint64 `json:"size"`
}

// topHeap 按 Size 的最小堆（容量有界，只保留最大的 topFilesCap 个）
type topHeap []fileEntry

func (h topHeap) Len() int           { return len(h) }
func (h topHeap) Less(i, j int) bool { return h[i].Size < h[j].Size }
func (h topHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *topHeap) Push(x any)        { *h = append(*h, x.(fileEntry)) }
func (h *topHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// dirQueue 无界目录队列（cond 实现，入队永不阻塞，彻底避免
// 「信号量递归死锁」：父任务持槽等待子任务、子任务又等槽）。
type dirQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  []*treeNode
	closed bool
}

func newDirQueue() *dirQueue {
	q := &dirQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *dirQueue) push(n *treeNode) {
	q.mu.Lock()
	q.items = append(q.items, n)
	q.mu.Unlock()
	q.cond.Signal()
}

// pop 阻塞取一个；队列关闭且为空时返回 nil
func (q *dirQueue) pop() *treeNode {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.items) == 0 {
		return nil
	}
	n := q.items[0]
	q.items = q.items[1:]
	return n
}

func (q *dirQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.cond.Broadcast()
}

// scanner 全局扫描器（单扫描任务；重复请求等待或复用结果）
type scanner struct {
	mu       sync.Mutex
	root     string
	tree     *treeNode
	scanning bool
	done     bool
	started  time.Time
	elapsed  time.Duration

	files atomic.Int64
	dirs  atomic.Int64
	bytes atomic.Int64
	tasks atomic.Int64 // 待 finalize 的目录节点数（归零即扫描结束）

	hardMu sync.Mutex
	hard   map[string]struct{} // "dev:ino" 硬链接去重

	topMu sync.Mutex
	top   topHeap

	q       *dirQueue
	aborted atomic.Bool
}

var sc = &scanner{
	hard: map[string]struct{}{},
}

// scanProgress 进度快照
type scanProgress struct {
	Scanning  bool   `json:"scanning"`
	Done      bool   `json:"done"`
	Root      string `json:"root"`
	Files     int64  `json:"files"`
	Dirs      int64  `json:"dirs"`
	Bytes     int64  `json:"bytes"`
	ElapsedMs int64  `json:"elapsed_ms"`
	Aborted   bool   `json:"aborted"`
}

func handleScanStart(w http.ResponseWriter, r *http.Request) {
	touch()
	root := strings.TrimSpace(r.URL.Query().Get("root"))
	started := sc.Start(root)
	writeJSON(w, map[string]any{"ok": true, "started": started})
}

func handleScanProgress(w http.ResponseWriter, r *http.Request) {
	touch()
	writeJSON(w, sc.Progress())
}

func handleTreeNode(w http.ResponseWriter, r *http.Request) {
	touch()
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	n, msg := sc.Node(path)
	if n == nil {
		writeJSON(w, map[string]any{"error": msg, "path": path})
		return
	}
	writeJSON(w, map[string]any{
		"path":     n.Path,
		"root":     sc.RootPath(),
		"total":    n.Size,
		"files":    n.Files,
		"dirs":     n.Dirs,
		"children": n.Children,
		"progress": sc.Progress(),
	})
}

func handleBigFiles(w http.ResponseWriter, r *http.Request) {
	touch()
	root := strings.TrimSpace(r.URL.Query().Get("root"))
	if root == "" {
		root = sc.RootPath()
	}
	n := atoiDefault(r.URL.Query().Get("n"), 15)
	if n > 200 {
		n = 200
	}
	files := sc.BigFiles(root, n)
	if files == nil {
		files = []fileEntry{}
	}
	writeJSON(w, map[string]any{"root": root, "files": files, "progress": sc.Progress()})
}

// Start 启动（或复用）一次扫描；返回是否由本次调用启动。
func (s *scanner) Start(root string) bool {
	root = strings.TrimSuffix(strings.TrimSpace(root), "/")
	if root == "" {
		root = "/"
	}
	if !filepath.IsAbs(root) {
		root = "/" + root
	}

	s.mu.Lock()
	if s.scanning {
		s.mu.Unlock()
		return false // 已在扫描：前端轮询进度即可
	}
	s.root = root
	s.tree = nil
	s.scanning = true
	s.done = false
	s.started = time.Now()
	s.elapsed = 0
	s.files.Store(0)
	s.dirs.Store(0)
	s.bytes.Store(0)
	s.aborted.Store(false)
	s.mu.Unlock()
	s.hardMu.Lock()
	s.hard = map[string]struct{}{}
	s.hardMu.Unlock()
	s.topMu.Lock()
	s.top = nil
	s.topMu.Unlock()

	go func() {
		tree := s.runScan(root)
		s.mu.Lock()
		s.tree = tree
		s.scanning = false
		s.done = true
		s.elapsed = time.Since(s.started)
		s.mu.Unlock()
		log.Printf("[disk-manager] 扫描完成 %s：%d 文件 / %d 目录 / %s，耗时 %s（并行 %d）",
			root, s.files.Load(), s.dirs.Load(), fmtSize(uint64(s.bytes.Load())),
			s.elapsed.Round(time.Millisecond), maxWorkers)
	}()
	return true
}

// Progress 读取进度快照。
func (s *scanner) Progress() scanProgress {
	s.mu.Lock()
	defer s.mu.Unlock()
	el := s.elapsed
	if s.scanning {
		el = time.Since(s.started)
	}
	return scanProgress{
		Scanning: s.scanning, Done: s.done, Root: s.root,
		Files: s.files.Load(), Dirs: s.dirs.Load(), Bytes: s.bytes.Load(),
		ElapsedMs: el.Milliseconds(), Aborted: s.aborted.Load(),
	}
}

// RootPath 当前扫描根。
func (s *scanner) RootPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.root
}

// Node 在树缓存中查找路径（O(深度×子项)，零 IO）。
func (s *scanner) Node(path string) (*treeNode, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tree == nil {
		if s.scanning {
			return nil, "扫描进行中，请稍候…"
		}
		return nil, "尚未扫描，请先点击「扫描」"
	}
	// 注意：filepath.Clean("") 会返回 "."，必须先判空再 Clean
	path = strings.TrimSpace(path)
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		path = "/"
	}
	path = filepath.Clean(path)
	root := filepath.Clean(s.root)
	if path == root {
		return s.tree, ""
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, "路径不在当前扫描范围内（" + root + "）"
	}
	cur := s.tree
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		if seg == "." || seg == "" {
			continue
		}
		var next *treeNode
		for _, c := range cur.Children {
			if c.IsDir && c.Name == seg {
				next = c
				break
			}
		}
		if next == nil {
			if _, err := os.Stat(path); err != nil {
				return nil, "目录不存在或不可访问"
			}
			return nil, "目录不在缓存中（超出 Top-" + strconv.Itoa(maxChildren) + " 截断范围），请直接扫描该目录"
		}
		cur = next
	}
	return cur, ""
}

// BigFiles 从候选堆中按前缀过滤 Top-N。
func (s *scanner) BigFiles(root string, n int) []fileEntry {
	s.topMu.Lock()
	all := make([]fileEntry, len(s.top))
	copy(all, s.top)
	s.topMu.Unlock()

	// 注意：filepath.Clean("") 会返回 "."，必须先判空再 Clean
	root = strings.TrimSpace(root)
	root = strings.TrimSuffix(root, "/")
	if root == "" {
		root = "/"
	}
	root = filepath.Clean(root)
	out := []fileEntry{}
	for _, f := range all {
		if root == "/" || f.Path == root || strings.HasPrefix(f.Path, root+"/") {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Size > out[j].Size })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// runScan 工作池并行扫描：maxWorkers 个 worker 从无界队列取目录处理，
// 每个目录节点 finalize 时向父级上报，tasks 计数归零即整树完成。
func (s *scanner) runScan(root string) *treeNode {
	rootNode := &treeNode{Name: filepath.Base(root), Path: root, IsDir: true}
	s.q = newDirQueue()
	s.tasks.Store(1)
	s.q.push(rootNode)

	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n := s.q.pop()
				if n == nil {
					return
				}
				s.process(n)
			}
		}()
	}
	wg.Wait()
	return rootNode
}

// process 处理一个目录：读取子项，文件直接入列，目录子项入队由其他 worker 处理。
func (s *scanner) process(n *treeNode) {
	if s.aborted.Load() {
		s.tryFinalize(n)
		return
	}
	if s.files.Load()+s.dirs.Load() > maxScanEntries {
		s.aborted.Store(true)
		log.Printf("[disk-manager] 条目数达到上限 %d，停止深入", maxScanEntries)
	}
	entries, err := os.ReadDir(n.Path)
	if err != nil {
		s.tryFinalize(n)
		return
	}
	var dirKids []*treeNode
	for _, e := range entries {
		if s.aborted.Load() {
			break
		}
		full := filepath.Join(n.Path, e.Name())
		if e.IsDir() {
			if skipDir(full) {
				continue
			}
			dirKids = append(dirKids, &treeNode{Name: e.Name(), Path: full, IsDir: true, parent: n})
			continue
		}
		fi, err := e.Info()
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		sz := s.accountFile(fi, full)
		n.mu.Lock()
		n.fileKids = append(n.fileKids, &treeNode{Name: e.Name(), Path: full, Size: sz})
		n.mu.Unlock()
	}

	// 先声明 pending（在入队前），子项完成时据此上报
	n.mu.Lock()
	n.pending = len(dirKids)
	n.mu.Unlock()
	for _, c := range dirKids {
		if s.aborted.Load() {
			// 中止后未入队的子项：撤销 pending 计数
			n.mu.Lock()
			n.pending--
			n.mu.Unlock()
			continue
		}
		s.tasks.Add(1)
		s.dirs.Add(1)
		s.q.push(c)
	}
	s.tryFinalize(n)
}

// tryFinalize 聚合节点（幂等，pending==0 才执行）：
// 合并文件子项+已完成目录子项 → 排序截断 → 自底向上累计 → 向父级上报。
func (s *scanner) tryFinalize(n *treeNode) {
	n.mu.Lock()
	if n.pending != 0 || n.finalized {
		n.mu.Unlock()
		return
	}
	n.finalized = true
	all := make([]*treeNode, 0, len(n.fileKids)+len(n.dirDone))
	all = append(all, n.fileKids...)
	all = append(all, n.dirDone...)
	n.fileKids, n.dirDone = nil, nil
	n.mu.Unlock()

	sort.Slice(all, func(i, j int) bool { return all[i].Size > all[j].Size })
	if len(all) > maxChildren {
		all = all[:maxChildren]
	}
	var size, files, dirs uint64
	for _, c := range all {
		size += c.Size
		files += c.Files
		dirs += c.Dirs
		if c.IsDir {
			dirs++
		} else {
			files++
		}
	}
	n.mu.Lock()
	n.Size, n.Files, n.Dirs, n.Children = size, files, dirs, all
	n.mu.Unlock()

	// 向父级上报并级联检查
	p := n.parent
	if p != nil {
		p.mu.Lock()
		p.dirDone = append(p.dirDone, n)
		p.pending--
		p.mu.Unlock()
		s.tryFinalize(p)
	}
	if s.tasks.Add(-1) == 0 {
		s.q.close() // 整树完成，唤醒所有 worker 退出
	}
}

// accountFile 文件计账：硬链接 (dev,ino) 去重；候选堆维护。
func (s *scanner) accountFile(fi os.FileInfo, path string) uint64 {
	sz := fileDiskSize(fi)
	s.files.Add(1)
	s.bytes.Add(int64(sz))
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 {
		key := strconv.FormatUint(uint64(st.Dev), 16) + ":" + strconv.FormatUint(st.Ino, 16)
		s.hardMu.Lock()
		if _, dup := s.hard[key]; dup {
			s.hardMu.Unlock()
			return 0 // 硬链接已计入，不重复统计占用（ncdu 同款策略）
		}
		s.hard[key] = struct{}{}
		s.hardMu.Unlock()
	}
	s.pushTop(path, sz)
	return sz
}

// fileDiskSize 取文件计入磁盘占用的尺寸（du 语义）：
// 常规文件用逻辑大小；稀疏文件（实际分配块远小于逻辑大小，
// 如 128TiB 的稀疏镜像）按实际分配块计，避免总量虚报。
func fileDiskSize(fi os.FileInfo) uint64 {
	logical := fi.Size()
	if logical <= 0 {
		return 0
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		alloc := int64(st.Blocks) * 512
		if alloc >= 0 && uint64(alloc) < uint64(logical)/2 {
			return uint64(alloc)
		}
	}
	return uint64(logical)
}

// pushTop 维护有界大文件候选堆（最小堆，容量 topFilesCap）。
func (s *scanner) pushTop(path string, sz uint64) {
	if sz == 0 {
		return
	}
	s.topMu.Lock()
	defer s.topMu.Unlock()
	if len(s.top) < topFilesCap {
		heap.Push(&s.top, fileEntry{Path: path, Name: filepath.Base(path), Size: sz})
		return
	}
	if sz > s.top[0].Size {
		s.top[0] = fileEntry{Path: path, Name: filepath.Base(path), Size: sz}
		heap.Fix(&s.top, 0)
	}
}

func skipDir(d string) bool {
	return strings.HasPrefix(d, "/proc/") || strings.HasPrefix(d, "/sys/") ||
		strings.HasPrefix(d, "/dev/") || strings.HasPrefix(d, "/run/")
}

// ---------- 访问统计 ----------

type accessEntry struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

type logEnv struct {
	Logs    []string `json:"logs"`
	Default string   `json:"default"`
	Analyzed bool    `json:"analyzed"`
}

func handleWorkerLogEnv(w http.ResponseWriter, r *http.Request) {
	touch()
	logs := probeLogs()
	e := logEnv{Logs: logs, Default: "", Analyzed: false}
	if len(logs) > 0 {
		e.Default = logs[0]
		e.Analyzed = true
	}
	writeJSON(w, e)
}

func handleWorkerAccess(w http.ResponseWriter, r *http.Request) {
	touch()
	logPath := strings.TrimSpace(r.URL.Query().Get("log"))
	if logPath == "" {
		logPath = firstLog()
	}
	n := atoiDefault(r.URL.Query().Get("n"), 20)
	if n > 200 {
		n = 200
	}
	filter := strings.TrimSpace(r.URL.Query().Get("filter"))
	if logPath == "" {
		writeJSON(w, map[string]any{"error": "未探测到访问日志，请填入日志路径", "paths": []accessEntry{}, "path": ""})
		return
	}
	if _, err := os.Stat(logPath); err != nil {
		writeJSON(w, map[string]any{"error": "日志不存在: " + logPath, "path": logPath, "paths": []accessEntry{}})
		return
	}
	paths := parseAccessLog(logPath, n, filter)
	writeJSON(w, map[string]any{"path": logPath, "total": len(paths), "paths": paths})
}

func probeLogs() []string {
	var out []string
	for _, p := range accessLogCandidates {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			out = append(out, p)
		}
	}
	home := os.Getenv("PANEL_HOME")
	if home != "" {
		for _, p := range []string{
			filepath.Join(home, "logs", "access.log"),
			filepath.Join(home, "logs", "panel.log"),
		} {
			if _, err := os.Stat(p); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

func firstLog() string {
	ls := probeLogs()
	if len(ls) > 0 {
		return ls[0]
	}
	return ""
}

var (
	reqRe       = regexp.MustCompile(`"([A-Z]+)\s+(\S+)\s+HTTP` + `/\d\.\d"`)
	plainReqRe  = regexp.MustCompile(`^\S+\s+-\s+\[[^\]]+\]\s+"[A-Z]+\s+(\S+)\s+HTTP`)
	panelLineRe = regexp.MustCompile(`\s(POST|GET|PUT|DELETE|PATCH|HEAD)\s+(\S+)\s+`)
	// slog 键值日志（IotaPanel 核心格式）：time=... level=INFO msg=http method=GET path=/api/x status=200
	slogPathRe = regexp.MustCompile(`method=(GET|POST|PUT|DELETE|PATCH|HEAD)\s+path=(\S+)`)
)

func parseAccessLog(logPath string, n int, filter string) []accessEntry {
	f, err := os.Open(logPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	counts := map[string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	lines := 0
	for sc.Scan() {
		line := sc.Text()
		lines++
		if lines > 2_000_000 {
			break
		}
		path := extractPath(line)
		if path == "" || path == "/" {
			continue
		}
		if filter != "" && !strings.Contains(path, filter) {
			continue
		}
		counts[path]++
	}
	if len(counts) == 0 {
		return nil
	}
	entries := make([]accessEntry, 0, len(counts))
	for p, c := range counts {
		entries = append(entries, accessEntry{Path: p, Count: c})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Count > entries[j].Count })
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

func extractPath(line string) string {
	if m := reqRe.FindStringSubmatch(line); m != nil {
		return cleanPath(m[2])
	}
	if m := panelLineRe.FindStringSubmatch(line); m != nil {
		return cleanPath(m[2])
	}
	if m := slogPathRe.FindStringSubmatch(line); m != nil {
		return cleanPath(m[2])
	}
	if m := plainReqRe.FindStringSubmatch(line); m != nil {
		return cleanPath(m[1])
	}
	return ""
}

func cleanPath(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if len(p) > 0 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	if p == "" {
		return "/"
	}
	return p
}

// ---------- 工具 ----------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	_, _ = w.Write(buf.Bytes())
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func fmtSize(n uint64) string {
	switch {
	case n < 1024:
		return strconv.FormatUint(n, 10) + " B"
	case n < 1<<20:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	case n < 1<<30:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n < 1<<40:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	default:
		return fmt.Sprintf("%.2f TB", float64(n)/(1<<40))
	}
}
