// SPDX-License-Identifier: Apache-2.0
// 探针进程：常驻独立会话(setsid)，极低占用
//   · 定时采样落盘
//   · 周期调用 AI 分析
//   · SIGHUP 重载配置 / SIGUSR1 立即分析 / SIGTERM 优雅退出
package main

import (
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"
)

func runProbe() {
	home := os.Getenv("PANEL_HOME")
	dd := ensureDataDir(home)
	cfg := loadConfig(dd)

	// 低占用调优：降低 GC 目标，让内存尽快归还系统
	debug.SetGCPercent(30)
	debug.SetMemoryLimit(12 << 20) // 软限制 12MB

	writePid(dd, os.Getpid())
	defer os.Remove(pidPath(dd))

	log.SetPrefix("[probe] ")
	log.SetFlags(log.LstdFlags)
	log.Printf("探针启动 pid=%d 采样间隔=%ds AI周期=%ds AI=%v", os.Getpid(),
		cfg.SampleInterval, cfg.AIInterval, aiConfigured(cfg))

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGUSR1)

	// 恢复上次计数器，避免探针重启后首个采样抖动
	prev := loadProbeState(dd)

	sampleTick := time.NewTicker(time.Duration(cfg.SampleInterval) * time.Second)
	aiTick := time.NewTicker(time.Duration(cfg.AIInterval) * time.Second)
	defer sampleTick.Stop()
	defer aiTick.Stop()

	sampleN := 0

	// 启动先采一次(计数器来自落盘状态，CPU 差值即刻可用)
	var s Sample
	s, prev = collect(home, prev, float64(cfg.SampleInterval))
	s.ProbeRSS = procRSSKB(os.Getpid())
	if err := appendSample(dd, s, cfg.HistorySamples); err != nil {
		log.Printf("采样落盘失败: %v", err)
	}
	saveProbeState(dd, prev)

	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				log.Printf("收到退出信号，探针退出")
				return
			case syscall.SIGHUP:
				cfg = loadConfig(dd)
				log.Printf("配置已重载: 采样=%ds AI=%ds autoAct=%v", cfg.SampleInterval, cfg.AIInterval, cfg.AutoAct)
				sampleTick.Reset(time.Duration(cfg.SampleInterval) * time.Second)
				aiTick.Reset(time.Duration(cfg.AIInterval) * time.Second)
			case syscall.SIGUSR1:
				log.Printf("收到立即分析信号")
				rep := runAnalysis(dd, home, cfg)
				appendReport(dd, rep, cfg.HistoryReports)
				if rep.Verdict == "error" {
					log.Printf("分析失败: %s", rep.Err)
				} else {
					log.Printf("分析完成 verdict=%s: %s", rep.Verdict, rep.Summary)
				}
			}

		case <-sampleTick.C:
			var s Sample
			s, prev = collect(home, prev, float64(cfg.SampleInterval))
			s.ProbeRSS = procRSSKB(os.Getpid())
			if err := appendSample(dd, s, cfg.HistorySamples); err != nil {
				log.Printf("采样落盘失败: %v", err)
			}
			saveProbeState(dd, prev)
			// 每采 10 次主动归还内存，压低常驻 RSS
			sampleN++
			if sampleN%10 == 0 {
				debug.FreeOSMemory()
			}

		case <-aiTick.C:
			if !aiConfigured(cfg) {
				continue // 未配置 AI 时静默跳过
			}
			rep := runAnalysis(dd, home, cfg)
			appendReport(dd, rep, cfg.HistoryReports)
			if rep.Verdict == "error" {
				log.Printf("分析失败: %s", rep.Err)
			} else {
				log.Printf("分析完成 verdict=%s: %s", rep.Verdict, rep.Summary)
				for _, ex := range rep.Executed {
					log.Printf("自动动作 %s %s → %s", ex.Action.Type, ex.Action.Target, ex.Result)
				}
			}
		}
	}
}

// ---------------- 探针状态持久化 ----------------

func saveProbeState(dd string, c counters) {
	b, _ := json.Marshal(c)
	os.WriteFile(statePath(dd), b, 0600)
}

func loadProbeState(dd string) counters {
	var c counters
	b, err := os.ReadFile(statePath(dd))
	if err == nil {
		json.Unmarshal(b, &c)
	}
	return c
}
