// SPDX-License-Identifier: Apache-2.0
// 站点数据模型与轻量 JSON 存储（原子写盘 + .bak 回退，与面板核心同款策略）。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Site 单个站点配置。注册后视为不可变快照：修改必须整体替换并触发 Reload。
type Site struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Type          string    `json:"type"` // "static" | "proxy"
	Domains       []string  `json:"domains"`
	Root          string    `json:"root"`               // 静态站点根目录
	Upstream      string    `json:"upstream,omitempty"` // proxy 上游 http(s)://host:port
	Enabled       bool      `json:"enabled"`
	Index         []string  `json:"index"`     // 默认文档
	AutoIndex     bool      `json:"autoIndex"` // 目录浏览
	RedirectHTTPS bool      `json:"redirectHttps"`
	BlockedIPs    []string  `json:"blockedIps,omitempty"` // IP / CIDR 黑名单
	HasSSL        bool      `json:"hasSsl"`
	SSLDomains    []string  `json:"sslDomains,omitempty"` // 证书覆盖的域名（展示用）
	SSLNotBefore  time.Time `json:"sslNotBefore,omitempty"`
	SSLNotAfter   time.Time `json:"sslNotAfter,omitempty"`
	SSLAuto       bool      `json:"sslAuto,omitempty"`   // 由 ACME 自动签发/续期
	SSLProvider   string    `json:"sslProvider,omitempty"` // 签发 CA（letsencrypt 等）
	Requests      uint64    `json:"requests"` // 累计请求（仅快照持久化，运行时用原子计数）
	BytesOut      uint64    `json:"bytesOut"`
	CreatedAt     time.Time `json:"createdAt"`
}

// Database 数据库账号（一库一账号，宝塔同款习惯）。
type Database struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"` // 库名（唯一）
	User      string    `json:"user"` // 专属账号
	Password  string    `json:"password"`
	Remark    string    `json:"remark,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// MySQLRuntimeConfig 数据库运行时配置（按需启停，不用时零占用）。
type MySQLRuntimeConfig struct {
	Enabled      bool   `json:"enabled"`
	IdleStopSecs int    `json:"idleStopSecs"` // 空闲多久停 mysqld
	Port         int    `json:"port"`         // TCP 唤醒代理端口（PHP 应用连 127.0.0.1:port）
	RootPassword string `json:"rootPassword,omitempty"`
}

// ACMEConfig SSL 证书自动申请配置（多家免费 CA）。
type ACMEConfig struct {
	Provider     string `json:"provider"`               // CA id：letsencrypt / le-staging / zerossl / buypass / google
	Email        string `json:"email"`                  // ACME 账号邮箱
	ZeroSSLAPIKey string `json:"zeroSslApiKey,omitempty"` // ZeroSSL：API Key 自动换 EAB
	EABKid       string `json:"eabKid,omitempty"`        // 手动 EAB（Google 等）
	EABHmacKey   string `json:"eabHmacKey,omitempty"`
	HTTPPort     int    `json:"httpPort"`                // 独立 HTTP-01 验证监听端口（默认 80；0=仅主端口）
	AutoRenew    bool   `json:"autoRenew"`               // 到期前自动续期
	RenewDays    int    `json:"renewDays"`               // 提前多少天续期
}

// GlobalConfig 全局监听配置。
type GlobalConfig struct {
	HTTPPort  int                `json:"httpPort"`
	HTTPSPort int                `json:"httpsPort"`
	BindHTTP  string             `json:"bindHttp"`
	PHP       PHPRuntimeConfig   `json:"php"`
	MySQL     MySQLRuntimeConfig `json:"mysql"`
	ACME      ACMEConfig         `json:"acme"`
}

func defaultConfig() GlobalConfig {
	return GlobalConfig{HTTPPort: 80, HTTPSPort: 443, BindHTTP: "0.0.0.0",
		PHP: defaultPHPConfig(), MySQL: defaultMySQLConfig(), ACME: defaultACMEConfig()}
}

func defaultACMEConfig() ACMEConfig {
	return ACMEConfig{Provider: "letsencrypt", HTTPPort: 80, AutoRenew: true, RenewDays: 30}
}

func defaultMySQLConfig() MySQLRuntimeConfig {
	return MySQLRuntimeConfig{Enabled: false, IdleStopSecs: 300, Port: 3306}
}

type sitesFile struct {
	Sites []*Site `json:"sites"`
}

type dbsFile struct {
	Databases []*Database `json:"databases"`
}

// Store 面板数据目录下的轻量 JSON 存储。
type Store struct {
	mu    sync.Mutex
	dir   string
	sites []*Site
	dbs   []*Database
	cfg   GlobalConfig
}

// LoadStore 读取 etc/web-manager/ 下的 sites.json 与 config.json，损坏时回退 .bak。
func LoadStore(etcDir string) (*Store, error) {
	s := &Store{dir: etcDir}

	var sf sitesFile
	if err := readJSONAtomic(filepath.Join(etcDir, "sites.json"), &sf); err != nil {
		return nil, fmt.Errorf("读取站点数据: %w", err)
	}
	s.sites = sf.Sites
	if s.sites == nil {
		s.sites = []*Site{}
	}
	// 兜底：历史数据缺省字段
	for _, st := range s.sites {
		if st.Index == nil {
			st.Index = []string{"index.html", "index.htm"}
		}
	}

	if err := readJSONAtomic(filepath.Join(etcDir, "config.json"), &s.cfg); err != nil {
		return nil, fmt.Errorf("读取配置: %w", err)
	}
	if s.cfg.HTTPPort == 0 || s.cfg.HTTPSPort == 0 {
		def := defaultConfig()
		if s.cfg.HTTPPort == 0 {
			s.cfg.HTTPPort = def.HTTPPort
		}
		if s.cfg.HTTPSPort == 0 {
			s.cfg.HTTPSPort = def.HTTPSPort
		}
	}
	if s.cfg.BindHTTP == "" {
		s.cfg.BindHTTP = "0.0.0.0"
	}
	if s.cfg.PHP.MaxChildren == 0 && !s.cfg.PHP.Enabled && s.cfg.PHP.IdleStopSecs == 0 {
		s.cfg.PHP = defaultPHPConfig() // 旧版配置文件缺 PHP 段
	}
	if s.cfg.PHP.IdleStopSecs < 30 {
		s.cfg.PHP.IdleStopSecs = 300
	}
	if s.cfg.MySQL.IdleStopSecs == 0 && !s.cfg.MySQL.Enabled && s.cfg.MySQL.Port == 0 {
		s.cfg.MySQL = defaultMySQLConfig() // 旧版配置文件缺 MySQL 段
	}
	if s.cfg.MySQL.Port == 0 {
		s.cfg.MySQL.Port = 3306
	}
	if s.cfg.MySQL.IdleStopSecs < 30 {
		s.cfg.MySQL.IdleStopSecs = 300
	}
	// 旧版配置无 acme 段：整体补默认（provider 有值则视为用户已保存过，逐项兜底）
	if s.cfg.ACME.Provider == "" {
		s.cfg.ACME = defaultACMEConfig()
	}
	if s.cfg.ACME.HTTPPort == 0 {
		s.cfg.ACME.HTTPPort = 80
	}
	if s.cfg.ACME.RenewDays == 0 {
		s.cfg.ACME.RenewDays = 30
	}

	var df dbsFile
	if err := readJSONAtomic(filepath.Join(etcDir, "databases.json"), &df); err != nil {
		return nil, fmt.Errorf("读取数据库数据: %w", err)
	}
	s.dbs = df.Databases
	if s.dbs == nil {
		s.dbs = []*Database{}
	}
	return s, nil
}

func readJSONAtomic(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) { // 全新安装，允许为空
			return nil
		}
		if data2, err2 := os.ReadFile(path + ".bak"); err2 == nil {
			data = data2
		} else {
			return err
		}
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, v); err != nil {
		if data2, err2 := os.ReadFile(path + ".bak"); err2 == nil && json.Unmarshal(data2, v) == nil {
			return nil
		}
		return err
	}
	return nil
}

// writeJSONAtomic 先写 .tmp 再 rename，旧文件转存 .bak，杜绝半截文件。
func writeJSONAtomic(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if old, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(path+".bak", old, 0o600)
	}
	return os.Rename(tmp, path)
}

// ---------- 站点操作（全部加锁） ----------

// Sites 返回站点切片副本（元素指针为当前快照）。
func (s *Store) Sites() []*Site {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Site, len(s.sites))
	copy(out, s.sites)
	return out
}

func (s *Store) Config() GlobalConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

func (s *Store) Get(id string) *Site {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.sites {
		if st.ID == id {
			return st
		}
	}
	return nil
}

func (s *Store) Add(st *Site) {
	s.mu.Lock()
	s.sites = append(s.sites, st)
	s.mu.Unlock()
}

// Update 以新快照整体替换（保证运行时读到的对象不被并发修改）。
func (s *Store) Update(id string, next *Site) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, st := range s.sites {
		if st.ID == id {
			s.sites[i] = next
			return true
		}
	}
	return false
}

// Remove 摘除并返回站点。
func (s *Store) Remove(id string) *Site {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, st := range s.sites {
		if st.ID == id {
			s.sites = append(s.sites[:i], s.sites[i+1:]...)
			return st
		}
	}
	return nil
}

// SaveSites 持久化站点表（写时复制 + 全程持锁，保证站点对象对外只读）。
func (s *Store) SaveSites() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	out := make([]*Site, len(s.sites))
	for i, st := range s.sites {
		cp := *st
		out[i] = &cp
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return writeJSONAtomic(filepath.Join(s.dir, "sites.json"), sitesFile{Sites: out})
}

func (s *Store) SaveConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSONAtomic(filepath.Join(s.dir, "config.json"), s.cfg)
}

func (s *Store) SetConfig(cfg GlobalConfig) {
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
}

// FlushStats 把运行时原子计数写回并落盘（替换为副本，不改动已发布对象）。
func (s *Store) FlushStats(snap map[string][2]uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, st := range s.sites {
		v, ok := snap[st.ID]
		if !ok {
			continue
		}
		cp := *st
		cp.Requests = v[0]
		cp.BytesOut = v[1]
		s.sites[i] = &cp
	}
	_ = s.saveLocked()
}

// ---------- 数据库操作 ----------

// Databases 返回数据库切片副本。
func (s *Store) Databases() []*Database {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Database, len(s.dbs))
	copy(out, s.dbs)
	return out
}

func (s *Store) GetDB(id string) *Database {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.dbs {
		if d.ID == id {
			return d
		}
	}
	return nil
}

// DBExistsName / DBExistsUser 库名与用户名唯一性检查。
func (s *Store) DBExistsName(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.dbs {
		if d.Name == name {
			return true
		}
	}
	return false
}

func (s *Store) DBExistsUser(user string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.dbs {
		if d.User == user {
			return true
		}
	}
	return false
}

func (s *Store) AddDB(d *Database) {
	s.mu.Lock()
	s.dbs = append(s.dbs, d)
	s.mu.Unlock()
}

func (s *Store) RemoveDB(id string) *Database {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, d := range s.dbs {
		if d.ID == id {
			s.dbs = append(s.dbs[:i], s.dbs[i+1:]...)
			return d
		}
	}
	return nil
}

// UpdateDB 整体替换数据库记录（如改密码）。
func (s *Store) UpdateDB(id string, next *Database) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, d := range s.dbs {
		if d.ID == id {
			s.dbs[i] = next
			return true
		}
	}
	return false
}

func (s *Store) SaveDBs() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Database, len(s.dbs))
	copy(out, s.dbs)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return writeJSONAtomic(filepath.Join(s.dir, "databases.json"), dbsFile{Databases: out})
}
