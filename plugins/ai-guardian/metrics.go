// SPDX-License-Identifier: Apache-2.0
// 指标采集：CPU/内存/负载/磁盘/网络/各插件 RSS —— 全部读 /proc 与 statfs，零依赖
package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// PluginStat 单个插件的内存占用
type PluginStat struct {
	Name  string `json:"name"`   // 插件名
	RSSKB int    `json:"rssKB"`  // 常驻内存 KB
	PIDs  int    `json:"pids"`   // 进程数
}

// Sample 一次采样
type Sample struct {
	T        int64         `json:"t"`                  // unix 秒
	CPU      float64       `json:"cpu"`                // CPU 使用率 %
	Mem      float64       `json:"mem"`                // 内存使用率 %
	MemUsed  float64       `json:"memUsedMB"`          // 已用内存 MB
	MemTotal float64       `json:"memTotalMB"`         // 总内存 MB
	Load1    float64       `json:"load1"`              // 1分钟负载
	Load5    float64       `json:"load5"`
	Load15   float64       `json:"load15"`
	DiskRoot float64       `json:"diskRoot"`           // / 使用率 %
	DiskData float64       `json:"diskData"`           // PANEL_HOME 所在盘使用率 %
	RxKB     float64       `json:"rxKBs"`              // 网络下行 KB/s
	TxKB     float64       `json:"txKBs"`              // 网络上行 KB/s
	Plug     []PluginStat  `json:"plug,omitempty"`     // 各插件 RSS
	ProbeRSS int           `json:"probeRSS"`           // 探针自身 RSS KB
}

// counters 增量计数器(跨采样求差)
type counters struct {
	CPUIdle float64 `json:"cpuIdle"`
	CPUTotal float64 `json:"cpuTotal"`
	Rx      float64 `json:"rx"`
	Tx      float64 `json:"tx"`
}

// readCounters 读取 CPU 累计时间与网络字节数
func readCounters() (counters, error) {
	var c counters
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return c, err
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "cpu ") {
			f := strings.Fields(ln)
			var total, idle float64
			for i := 1; i < len(f); i++ {
				v, _ := strconv.ParseFloat(f[i], 64)
				total += v
				if i == 4 || i == 5 { // idle + iowait
					idle += v
				}
			}
			c.CPUTotal, c.CPUIdle = total, idle
			break
		}
	}
	nb, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return c, err
	}
	for _, ln := range strings.Split(string(nb), "\n") {
		idx := strings.Index(ln, ":")
		if idx < 0 {
			continue
		}
		iface := strings.TrimSpace(ln[:idx])
		if iface == "lo" {
			continue
		}
		f := strings.Fields(ln[idx+1:])
		if len(f) >= 9 {
			rx, _ := strconv.ParseFloat(f[0], 64)
			tx, _ := strconv.ParseFloat(f[8], 64)
			c.Rx += rx
			c.Tx += tx
		}
	}
	return c, nil
}

// readMem 内存信息
func readMem() (usedMB, totalMB, pct float64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0
	}
	var total, avail float64
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseFloat(f[1], 64)
		switch f[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	if total <= 0 {
		return 0, 0, 0
	}
	used := total - avail
	return used / 1024, total / 1024, used * 100 / total
}

// readLoad 负载
func readLoad() (l1, l5, l15 float64) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	f := strings.Fields(string(b))
	if len(f) >= 3 {
		l1, _ = strconv.ParseFloat(f[0], 64)
		l5, _ = strconv.ParseFloat(f[1], 64)
		l15, _ = strconv.ParseFloat(f[2], 64)
	}
	return
}

// diskPct 目录所在文件系统使用率
func diskPct(dir string) float64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0
	}
	if st.Blocks == 0 {
		return 0
	}
	return float64(st.Blocks-st.Bfree) * 100 / float64(st.Blocks)
}

// scanPluginProcs 扫描所有 IotaPanel 插件进程的 RSS
// 匹配规则: cmdline 包含 /plugins/<name>/bin/
func scanPluginProcs(home string) map[string]*PluginStat {
	m := make(map[string]*PluginStat)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return m
	}
	marker := "/plugins/"
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		if pid == "" || pid[0] < '0' || pid[0] > '9' {
			continue
		}
		cb, err := os.ReadFile("/proc/" + pid + "/cmdline")
		if err != nil {
			continue
		}
		cl := strings.ReplaceAll(string(cb), "\x00", " ")
		i := strings.Index(cl, marker)
		if i < 0 {
			continue
		}
		rest := cl[i+len(marker):]
		name := rest
		if j := strings.Index(rest, "/"); j >= 0 {
			name = rest[:j]
		}
		if name == "" {
			continue
		}
		st := m[name]
		if st == nil {
			st = &PluginStat{Name: name}
			m[name] = st
		}
		st.PIDs++
		st.RSSKB += procRSSKB(atoiSafe(pid))
	}
	return m
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// collect 采集一次完整采样；prev 为上次计数器(可为空,首次采样 CPU/网络为 0)
func collect(home string, prev counters, dt float64) (Sample, counters) {
	var s Sample
	s.T = nowUnix()
	cur, _ := readCounters()
	// CPU 差值
	dTotal := cur.CPUTotal - prev.CPUTotal
	dIdle := cur.CPUIdle - prev.CPUIdle
	if dTotal > 0 && dt > 0 {
		s.CPU = round2((1 - dIdle/dTotal) * 100)
		if s.CPU < 0 {
			s.CPU = 0
		}
	}
	// 网络差值
	if dt > 0 {
		s.RxKB = round2((cur.Rx - prev.Rx) / 1024 / dt)
		s.TxKB = round2((cur.Tx - prev.Tx) / 1024 / dt)
		if s.RxKB < 0 || prev.Rx == 0 {
			s.RxKB = 0
		}
		if s.TxKB < 0 || prev.Tx == 0 {
			s.TxKB = 0
		}
	}
	s.MemUsed, s.MemTotal, s.Mem = readMem()
	s.MemUsed = round2(s.MemUsed)
	s.MemTotal = round2(s.MemTotal)
	s.Mem = round2(s.Mem)
	s.Load1, s.Load5, s.Load15 = readLoad()
	s.DiskRoot = round2(diskPct("/"))
	if home != "" {
		s.DiskData = round2(diskPct(home))
	} else {
		s.DiskData = s.DiskRoot
	}
	// 插件进程
	plugs := scanPluginProcs(home)
	for _, st := range plugs {
		if st.Name == "ai-guardian" {
			continue // 自身主进程不计入被守护列表
		}
		s.Plug = append(s.Plug, *st)
	}
	return s, cur
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}

func nowUnix() int64 {
	return time.Now().Unix()
}
