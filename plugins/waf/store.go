// SPDX-License-Identifier: Apache-2.0
//
// 微盾 WAF —— IotaPanel 的雷池式轻量 WAF 插件
//
// 设计哲学（与 IotaPanel 微内核一脉相承）：
//   平时只保留一个「低占用探针」——纯 TCP 直通 + 字面量特征扫描，不做 HTTP 解析；
//   检测到可疑请求（特征命中 / 频率超限 / 流量异常）时，自动升级「防护模式」——
//   完整 HTTP 解析 + 深度解码 + 规则引擎 + CC 防护 + 人机验证；
//   威胁平息一段时间后自动降级回探针，释放算力。
//
// 纯 Go 标准库实现，零第三方依赖，单二进制。

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ---------- 配置结构 ----------

// Site 防护站点（类似雷池的「保护站点」）
type Site struct {
	ID       string   `json:"id"`                  // 站点 ID
	Name     string   `json:"name"`                // 显示名
	Domains  []string `json:"domains"`             // Host 匹配（支持 *.example.com 与 * 兜底）
	Backends []string `json:"backends"`            // 上游地址列表 host:port
	Mode     string   `json:"mode"`                // off 关闭 | monitor 观察 | block 拦截
	CertFile string   `json:"cert_file,omitempty"` // HTTPS 入口时本站证书（可选）
	KeyFile  string   `json:"key_file,omitempty"`
}

// IPEntry IP 名单条目（支持单 IP 与 CIDR）
type IPEntry struct {
	CIDR    string `json:"cidr"`
	Reason  string `json:"reason,omitempty"`
	Expires int64  `json:"expires,omitempty"` // Unix 秒；0 = 永久
}

// CustomRule 用户自定义规则
type CustomRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Regex   string `json:"regex"`
	Target  string `json:"target"` // path|query|headers|ua|referer|cookie|body|all
	Action  string `json:"action"` // block | monitor
	Enabled bool   `json:"enabled"`
}

// CCConfig CC 防护配置
type CCConfig struct {
	Enabled    bool   `json:"enabled"`
	Capacity   int    `json:"capacity"`    // 窗口内最大请求数
	Window     int    `json:"window"`      // 窗口（秒）
	Action     string `json:"action"`      // challenge 人机验证 | block 直接拦截
	PowBits    int    `json:"pow_bits"`    // 工作量证明难度（位）
	VerifySecs int    `json:"verify_secs"` // 验证通过后的有效期（秒）
}

// AutoBanConfig 自动拉黑配置
type AutoBanConfig struct {
	Enabled   bool `json:"enabled"`
	Threshold int  `json:"threshold"` // 窗口内拦截次数阈值
	Window    int  `json:"window"`    // 统计窗口（秒）
	Minutes   int  `json:"minutes"`   // 拉黑时长（分钟）
}

// BlockPageConfig 自定义拦截页文案
type BlockPageConfig struct {
	Title string `json:"title"`
	Line1 string `json:"line1"`
	Line2 string `json:"line2"`
}

// URLRateConfig URL 频率限制（融合 1Panel「URL 模式」访问频率限制）
type URLRateConfig struct {
	Enabled  bool `json:"enabled"`
	Capacity int  `json:"capacity"`  // 每「IP+URL」单位时间最大请求数
	Window   int  `json:"window"`    // 统计窗口（秒）
	BanSecs  int  `json:"ban_secs"`  // 超限临时封禁秒数（0=仅 429 不封禁）
}

// NotFoundConfig 404 频率限制（融合 1Panel「404 频率限制」：反复访问不存在资源→封 IP）
type NotFoundConfig struct {
	Enabled  bool `json:"enabled"`
	Capacity int  `json:"capacity"` // 单位时间 404 次数阈值
	Window   int  `json:"window"`   // 统计窗口（秒）
	BanSecs  int  `json:"ban_secs"` // 达标封禁秒数
}

// ThreatFeed 威胁情报 IP 信誉源（融合 CrowdSec 社区块表 / 1Panel「恶意 IP 组」）
// URL 指向一个纯文本源：每行一个 IP 或 CIDR，`#` 开头为注释。
type ThreatFeed struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	IntervalMin int    `json:"interval_min"` // 拉取周期（分钟）
}

// Config 插件总配置（$PANEL_HOME/etc/waf/config.json）
type Config struct {
	HTTPEntry           string `json:"http_entry"`             // 对外 HTTP 入口，如 ":80" / ":8080"
	HTTPSEntry          string `json:"https_entry"`            // 对外 HTTPS 入口（空 = 不启用）
	TrustProxy          bool   `json:"trust_proxy"`            // 本插件部署在受信反代之后时，信任 X-Forwarded-For
	ThreatIntelBlock    bool   `json:"threat_intel_block"`     // 威胁情报 IP 信誉拦截总开关（默认关闭，部署在反代/隧道后务必关闭）
	CalmSecs            int    `json:"calm_secs"`              // 防护模式无威胁持续多久后降级回探针
	BodyMax             int64  `json:"body_max"`               // 请求体检测上限（字节）
	EscalateConnsPerMin int    `json:"escalate_conns_per_min"` // 全局连接速率升级阈值（个/分钟）

	Sites       []Site          `json:"sites"`
	IPBlacklist []IPEntry       `json:"ip_blacklist"`
	IPWhitelist []IPEntry       `json:"ip_whitelist"`
	RuleGroups  map[string]bool `json:"rule_groups"`
	CustomRules []CustomRule    `json:"custom_rules"`
	CC          CCConfig        `json:"cc"`
	AutoBan     AutoBanConfig   `json:"auto_ban"`
	BlockPage   BlockPageConfig `json:"block_page"`

	// ---- v0.2.0 融合防护（1Panel + OWASP CRS + CrowdSec）----
	HTTPMethods  []string        `json:"http_methods"`   // HTTP 方法白名单（1Panel HTTP 规则）
	AllowSpiders bool            `json:"allow_spiders"`  // 放行搜索引擎蜘蛛（1Panel 蜘蛛池）
	URLRate      URLRateConfig   `json:"url_rate"`       // URL 频率限制（1Panel URL 模式）
	NotFound     NotFoundConfig  `json:"notfound"`       // 404 频率限制（1Panel）
	ThreatFeeds  []ThreatFeed    `json:"threat_feeds"`   // 威胁情报 IP 信誉源（CrowdSec）
	UploadExtBan []string        `json:"upload_ext_ban"` // 上传危险扩展名（1Panel 限制上传）
}

// DefaultConfig 首次运行生成的默认配置
func DefaultConfig() *Config {
	return &Config{
		HTTPEntry:           ":8080",
		HTTPSEntry:          "",
		TrustProxy:          false,
		CalmSecs:            300,
		BodyMax:             1 << 20,
		EscalateConnsPerMin: 600,
		Sites: []Site{{
			ID:       "site_default",
			Name:     "默认站点（示例）",
			Domains:  []string{"*"},
			Backends: []string{"127.0.0.1:8081"},
			Mode:     "block",
		}},
		RuleGroups: map[string]bool{
			"sqli": true, "xss": true, "cmdi": true, "traversal": true,
			"fileinc": true, "webshell": true, "scanner": true, "sensitive": true,
			"xxe": true, "deser": true, "ssrf": true, "crlf": true,
			"protocol": true, "upload": true, "ldap": true,
		},
		CC: CCConfig{
			Enabled:    true,
			Capacity:   120,
			Window:     60,
			Action:     "challenge",
			PowBits:    16,
			VerifySecs: 1800,
		},
		AutoBan: AutoBanConfig{Enabled: false, Threshold: 5, Window: 120, Minutes: 10},
		BlockPage: BlockPageConfig{
			Title: "请求已被拦截",
			Line1: "您的请求触发了安全规则，已被微盾 WAF 拦截。",
			Line2: "如果您认为这是误报，请联系站点管理员并提供页面上的事件 ID。",
		},
		HTTPMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowSpiders: true,
		URLRate: URLRateConfig{Enabled: true, Capacity: 240, Window: 60, BanSecs: 0},
		NotFound: NotFoundConfig{Enabled: false, Capacity: 60, Window: 60, BanSecs: 600},
		UploadExtBan: []string{".php", ".php5", ".php7", ".phtml", ".asp", ".aspx",
			".ashx", ".jsp", ".jspx", ".cgi", ".pl", ".py", ".sh", ".exe", ".bat", ".cmd", ".com"},
	}
}

// normalize 补全空缺默认值
func (c *Config) normalize() {
	d := DefaultConfig()
	if c.HTTPEntry == "" {
		c.HTTPEntry = d.HTTPEntry
	}
	if c.CalmSecs <= 0 {
		c.CalmSecs = d.CalmSecs
	}
	if c.BodyMax <= 0 {
		c.BodyMax = d.BodyMax
	}
	if c.EscalateConnsPerMin <= 0 {
		c.EscalateConnsPerMin = d.EscalateConnsPerMin
	}
	if c.CC.Capacity <= 0 {
		c.CC = d.CC
	}
	if c.CC.Action != "block" && c.CC.Action != "challenge" {
		c.CC.Action = "challenge"
	}
	if c.CC.PowBits < 8 {
		c.CC.PowBits = 8
	}
	if c.CC.PowBits > 24 {
		c.CC.PowBits = 24
	}
	if c.CC.VerifySecs <= 0 {
		c.CC.VerifySecs = 1800
	}
	if c.AutoBan.Threshold <= 0 {
		c.AutoBan.Threshold = 5
	}
	if c.AutoBan.Window <= 0 {
		c.AutoBan.Window = 120
	}
	if c.AutoBan.Minutes <= 0 {
		c.AutoBan.Minutes = 10
	}
	if c.RuleGroups == nil {
		c.RuleGroups = d.RuleGroups
	}
	// 旧配置缺省 fs：默认启用 v0.2.0 新增规则组（protocol/upload/ldap）
	if c.RuleGroups != nil {
		if _, ok := c.RuleGroups["protocol"]; !ok {
			c.RuleGroups["protocol"] = true
		}
		if _, ok := c.RuleGroups["upload"]; !ok {
			c.RuleGroups["upload"] = true
		}
		if _, ok := c.RuleGroups["ldap"]; !ok {
			c.RuleGroups["ldap"] = true
		}
	}
	if len(c.HTTPMethods) == 0 {
		c.HTTPMethods = d.HTTPMethods
	}
	if len(c.UploadExtBan) == 0 {
		c.UploadExtBan = d.UploadExtBan
	}
	if c.URLRate.Capacity <= 0 {
		c.URLRate = d.URLRate
	}
	if c.NotFound.Capacity <= 0 {
		c.NotFound = d.NotFound
	}
	c.ThreatFeeds = cleanFeeds(c.ThreatFeeds)
	if c.BlockPage.Title == "" {
		c.BlockPage = d.BlockPage
	}
	for i := range c.Sites {
		if c.Sites[i].Mode == "" {
			c.Sites[i].Mode = "monitor"
		}
	}
}

// Clone 深拷贝（写时复制用）
func (c *Config) Clone() *Config {
	b, _ := json.Marshal(c)
	out := DefaultConfig()
	_ = json.Unmarshal(b, out)
	return out
}

// ---------- 存储层 ----------

// Store 配置与密钥的原子持久化（纯 JSON，零依赖）
type Store struct {
	dir string
	mu  sync.Mutex
}

func NewStore(dir string) *Store {
	_ = os.MkdirAll(dir, 0o755)
	return &Store{dir: dir}
}

func (s *Store) Dir() string        { return s.dir }
func (s *Store) ConfigPath() string { return filepath.Join(s.dir, "config.json") }
func (s *Store) EventsPath() string { return filepath.Join(s.dir, "events.jsonl") }

// LoadConfig 读取配置；不存在或损坏时生成默认配置
func (s *Store) LoadConfig() *Config {
	data, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		cfg := DefaultConfig()
		if err := s.SaveConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "[waf] 写入默认配置失败: %v\n", err)
		}
		return cfg
	}
	cfg := DefaultConfig() // 以默认值为底，覆盖已写字段
	if err := json.Unmarshal(data, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "[waf] 配置损坏，使用默认配置: %v\n", err)
		cfg = DefaultConfig()
	}
	cfg.normalize()
	return cfg
}

// SaveConfig 原子写盘（tmp + rename）
func (s *Store) SaveConfig(cfg *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.ConfigPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.ConfigPath())
}

// Secret 插件级 HMAC 密钥（人机验证 Cookie 签名用；首次生成后持久化）
func (s *Store) Secret() []byte {
	p := filepath.Join(s.dir, "secret.key")
	if b, err := os.ReadFile(p); err == nil && len(b) == 32 {
		return b
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	_ = os.WriteFile(p, b, 0o600)
	return b
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
