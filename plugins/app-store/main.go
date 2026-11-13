// SPDX-License-Identifier: Apache-2.0
// IotaPanel 软件商店插件 (app-store)
// 参考 XMP 星梦面板软件商店设计,适配 IotaPanel 插件规范:
//   - 监听 $PLUGIN_PORT,收到 SIGTERM 优雅退出
//   - 纯 Go 标准库,零第三方依赖,单二进制低占用
//   - Docker 操作全部通过 CLI (exec docker),不引入重型 SDK
package main

import (
	"archive/tar"
	"compress/gzip"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed web/index.html
var webFS embed.FS

//go:embed store.json
var builtinStore []byte

const labelKey = "io.iotapanel.appstore"
const containerPrefix = "xstore-"

// 商店默认源:依次尝试(国内环境 jsdelivr 优先)
var defaultSources = []string{
	"https://cdn.jsdelivr.net/gh/BCZZB/iotapanel-appstore@main/store.json",
	"https://fastly.jsdelivr.net/gh/BCZZB/iotapanel-appstore@main/store.json",
	"https://raw.githubusercontent.com/BCZZB/iotapanel-appstore/main/store.json",
}

// ---------------- 商店数据结构(兼容 XMP store.json 格式) ----------------

type PortMap struct {
	Host      string `json:"host"`
	Container string `json:"container"`
}

type VolumeMap struct {
	Host      string `json:"host"`
	Container string `json:"container"`
}

type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type AppVersion struct {
	Version string      `json:"version"`
	Image   string      `json:"image"`
	Network string      `json:"network"`
	Command string      `json:"command,omitempty"`
	Ports   []PortMap   `json:"ports"`
	Volumes []VolumeMap `json:"volumes"`
	Env     []EnvVar    `json:"env"`
}

type StoreApp struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Icon        string       `json:"icon"`
	Logo        string       `json:"logo,omitempty"`
	Color       string       `json:"color,omitempty"`
	Description string       `json:"description"`
	TypeID      string       `json:"typeId"`
	Versions    []AppVersion `json:"versions"`
}

type StoreType struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type StoreData struct {
	Version string      `json:"version"`
	Types   []StoreType `json:"types"`
	Apps    []StoreApp  `json:"apps"`
}

// ---------------- 部署记录 ----------------

type DeployedApp struct {
	Name      string      `json:"name"` // 容器实例名(不含前缀)
	AppID     string      `json:"appId"`
	Image     string      `json:"image"`
	Version   string      `json:"version"`
	Ports     []PortMap   `json:"ports"`
	CreatedAt time.Time   `json:"createdAt"`
}

type RuntimeState struct {
	mu       sync.Mutex
	deployed []DeployedApp
}

var (
	homeDir   string // PANEL_HOME
	stateFile string // <home>/data/appstore.json
	state     = &RuntimeState{}
)

// ---------------- 初始化 ----------------

func dataDir() string {
	if homeDir != "" {
		return filepath.Join(homeDir, "data")
	}
	return "."
}

func loadState() {
	state.mu.Lock()
	defer state.mu.Unlock()
	b, err := os.ReadFile(stateFile)
	if err != nil {
		state.deployed = []DeployedApp{}
		return
	}
	var d []DeployedApp
	if json.Unmarshal(b, &d) == nil {
		state.deployed = d
	}
}

func saveStateLocked() {
	b, _ := json.MarshalIndent(state.deployed, "", "  ")
	tmp := stateFile + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		os.Rename(tmp, stateFile)
	}
}

// ---------------- Docker CLI 封装 ----------------

func dockerCmd(timeout time.Duration, args ...string) (string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", fmt.Errorf("docker 未安装")
	}
	c := exec.Command("docker", args...)
	c.Env = os.Environ()
	done := make(chan struct{})
	var out []byte
	var err error
	go func() {
		out, err = c.CombinedOutput()
		close(done)
	}()
	select {
	case <-done:
		return string(out), err
	case <-time.After(timeout):
		if c.Process != nil {
			c.Process.Kill()
		}
		<-done
		return string(out), fmt.Errorf("命令超时")
	}
}

func dockerInstalled() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

func dockerAlive() bool {
	if !dockerInstalled() {
		return false
	}
	_, err := dockerCmd(5*time.Second, "version", "--format", "{{.Server.Version}}")
	return err == nil
}

// ---------------- 工具函数 ----------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func jsonOK(w http.ResponseWriter, v any) { writeJSON(w, 200, map[string]any{"ok": true, "data": v}) }
func jsonErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"ok": false, "error": msg})
}

func containerName(instance string) string {
	return containerPrefix + instance
}

// ---------------- 加载商店(远程缓存 + 爬取结果合并,内嵌兜底) ----------------

func loadStore() (StoreData, error) {
	var s StoreData
	usingRemote := false
	// 远程缓存优先
	if b, err := os.ReadFile(filepath.Join(dataDir(), "store-remote.json")); err == nil {
		if json.Unmarshal(b, &s) == nil && len(s.Apps) > 0 {
			usingRemote = true
		}
	}
	// 内嵌兜底
	if !usingRemote {
		if err := json.Unmarshal(builtinStore, &s); err != nil {
			return s, err
		}
	}
	// 合并爬取结果(不覆盖已有,按 ID/镜像去重)
	hasHot := false
	existing := map[string]bool{}
	for _, a := range s.Apps {
		existing[a.ID] = true
		for _, v := range a.Versions {
			base := v.Image
			if i := strings.LastIndex(base, ":"); i > 0 {
				base = base[:i]
			}
			existing[base] = true
		}
	}
	if b, err := os.ReadFile(filepath.Join(dataDir(), "store-crawled.json")); err == nil {
		var cf crawlStoreFile
		if json.Unmarshal(b, &cf) == nil {
			for _, a := range cf.Apps {
				if len(a.Versions) == 0 || existing[a.ID] {
					continue
				}
				base := a.Versions[0].Image
				if i := strings.LastIndex(base, ":"); i > 0 {
					base = base[:i]
				}
				if existing[base] {
					continue
				}
				existing[a.ID] = true
				existing[base] = true
				if a.TypeID == "hot" {
					hasHot = true
				}
				s.Apps = append(s.Apps, a)
			}
		}
	}
	if hasHot {
		hasType := false
		for _, t := range s.Types {
			if t.ID == "hot" {
				hasType = true
			}
		}
		if !hasType {
			s.Types = append(s.Types, StoreType{ID: "hot", Name: "🌐 热门镜像"})
		}
	}
	return s, nil
}

// ---------------- 多源爬取 Docker 镜像仓库 ----------------
// Docker Hub 主站 API 国内被阻断,改用四个可达源:
//   1. docker-library/official-images (GitHub, Docker 官方镜像库,含版本标签)
//   2. linuxserver GitHub org (自托管应用全家桶)
//   3. bitnami/containers GitHub org (Bitnami 打包)
//   4. quay.io 热门仓库 API

const crawlUA = "IotaPanel-AppStore/1.3 (+https://github.com/BCZZB/iotapanel-appstore)"

func fetchURL(url string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", crawlUA)
	req.Header.Set("Accept", "application/vnd.github+json")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}

func fetchInto(url string, v any, timeout time.Duration) error {
	b, err := fetchURL(url, timeout)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// ---- 智能分类 / 端口 / 图标猜测 ----

// tokenize: 镜像名拆成小写词元(供关键词精确匹配,避免 "ai" 误配 "mail")
func tokenize(s string) map[string]bool {
	out := map[string]bool{}
	for _, f := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		out[f] = true
	}
	return out
}

var classifyRules = []struct {
	TypeID string
	Words  []string
}{
	{"7", []string{"ai", "llm", "ollama", "stable", "diffusion", "model", "tensor", "pytorch", "torch", "machine", "inference", "chatgpt", "openai", "whisper", "tts", "speech", "localai", "libretranslate", "bento", "comfyui", "flowise", "text", "sglang", "vllm"}},
	{"1", []string{"wordpress", "ghost", "drupal", "joomla", "wiki", "cms", "blog", "grav", "typo3", "discourse", "flarum", "vanilla", "matomo", "umami", "plausible", "piwik", "shop", "woocommerce", "magento", "prestashop", "ghost", "hugo", "jekyll", "hexo", "docusaurus", "vuepress"}},
	{"3", []string{"file", "cloud", "storage", "sync", "nas", "torrent", "download", "sonarr", "radarr", "lidarr", "readarr", "prowlarr", "jackett", "flaresolverr", "sabnzbd", "nzbget", "aria", "transmission", "qbittorrent", "deluge", "nextcloud", "owncloud", "seafile", "webdav", "backup", "restic", "duplicati", "borg", "vaultwarden"}},
	{"4", []string{"monitor", "prometheus", "grafana", "zabbix", "nagios", "metric", "log", "dashboard", "alert", "statping", "uptime", "kuma", "netdata", "glances", "telegraf", "loki", "alerta", "observability", "cAdvisor", "portainer", "docker", "kubernetes", "k8s", "proxy", "vpn", "wireguard", "nginx", "traefik", "caddy", "network"}},
	{"5", []string{"jellyfin", "plex", "emby", "media", "video", "audio", "music", "photo", "movie", "tv", "subtitle", "book", "comic", "manga", "stream", "audiobook", "navidrome", "airsonic", "koel", "beets", "calibre", "kavita", "komga", "tdarr", "bazarr", "photoprism", "immich", "lychee"}},
	{"6", []string{"tool", "pdf", "note", "markdown", "office", "password", "vault", "translate", "rss", "feed", "git", "ci", "cd", "paste", "short", "url", "draw", "whiteboard", "mindmap", "calendar", "contact", "mail", "smtp", "imap", "imap", "adminer", "chat", "focalboard", "matrix", "zulip", "rocketchat", "gitea", "gogs", "jenkins", "drone"}},
	{"2", []string{"mysql", "postgres", "postgresql", "mongo", "mongodb", "redis", "mariadb", "sql", "database", "db", "cache", "memcached", "cassandra", "elastic", "search", "solr", "clickhouse", "couchdb", "influxdb", "neo4j", "arangodb", "rabbitmq", "kafka", "nats", "mqtt", "activemq", "python", "node", "golang", "java", "openjdk", "php", "ruby", "rust", "perl", "erlang", "alpine", "debian", "ubuntu", "centos", "fedora", "busybox", "httpd", "haproxy", "varnish", "registry", "zookeeper", "etcd", "consul"}},
}

var knownPorts = map[string][]PortMap{
	"nginx":     {{"80", "80"}},
	"httpd":     {{"80", "80"}},
	"caddy":     {{"8080", "80"}},
	"traefik":   {{"8080", "8080"}},
	"mysql":     {{"3306", "3306"}},
	"mariadb":   {{"3306", "3306"}},
	"postgres":  {{"5432", "5432"}},
	"mongodb":   {{"27017", "27017"}},
	"mongo":     {{"27017", "27017"}},
	"redis":     {{"6379", "6379"}},
	"memcached": {{"11211", "11211"}},
	"rabbitmq":  {{"5672", "5672"}, {"15672", "15672"}},
	"zookeeper": {{"2181", "2181"}},
	"clickhouse": {{"8123", "8123"}},
	"elasticsearch": {{"9200", "9200"}},
	"kibana":    {{"5601", "5601"}},
	"grafana":   {{"3000", "3000"}},
	"prometheus": {{"9090", "9090"}},
	"sonarr":     {{"8989", "8989"}},
	"radarr":     {{"7878", "7878"}},
	"lidarr":     {{"8686", "8686"}},
	"readarr":    {{"8787", "8787"}},
	"prowlarr":   {{"9696", "9696"}},
	"jackett":    {{"9117", "9117"}},
	"transmission": {{"9091", "9091"}},
	"qbittorrent":  {{"8080", "8080"}},
	"deluge":       {{"8112", "8112"}},
	"sabnzbd":      {{"8080", "8080"}},
	"pihole":       {{"53", "53"}, {"8080", "80"}},
	"uptime-kuma":  {{"3001", "3001"}},
	"filebrowser":  {{"8087", "80"}},
	"libretranslate": {{"5000", "5000"}},
	"it-tools":     {{"8020", "80"}},
	"homepage":     {{"3002", "3000"}},
	"code-server":  {{"8443", "8080"}},
	"mealie":       {{"9925", "9000"}},
	"paperless":    {{"8010", "8000"}},
	"vaultwarden":  {{"8222", "80"}},
	"n8n":          {{"5678", "5678"}},
	"alist":        {{"5244", "5244"}},
	"jellyfin":     {{"8096", "8096"}},
	"emby":         {{"8096", "8096"}},
	"plex":         {{"32400", "32400"}},
	"navidrome":    {{"4533", "4533"}},
	"calibre-web":  {{"8083", "8083"}},
	"kavita":       {{"5000", "5000"}},
	"komga":        {{"25600", "25600"}},
	"tautulli":     {{"8181", "8181"}},
	"ombi":         {{"3579", "3579"}},
	"organizr":     {{"8080", "80"}},
	"heimdall":     {{"8080", "80"}},
	"dashy":        {{"8080", "80"}},
	"codiad":       {{"8080", "80"}},
	"guacamole":    {{"8080", "8080"}},
	"gitea":        {{"3000", "3000"}},
	"jenkins":      {{"8080", "8080"}},
	"rocketchat":   {{"3000", "3000"}},
	"zulip":        {{"8080", "80"}},
	"nextcloud":    {{"8080", "80"}},
	"owncloud":     {{"8080", "80"}},
	"wordpress":    {{"8080", "80"}},
	"ghost":        {{"2368", "2368"}},
	"matomo":       {{"8080", "80"}},
	"adminer":      {{"8080", "8080"}},
	"influxdb":     {{"8086", "8086"}},
	"paperless-ngx": {{"8080", "8000"}},
	"kimai":        {{"8001", "8001"}},
	"monica":       {{"8080", "80"}},
	"firefly":      {{"8080", "8080"}},
	"trilium":      {{"8080", "8080"}},
	"joplin":       {{"22300", "22300"}},
	"wallabag":     {{"8080", "80"}},
	"ttrss":        {{"8280", "80"}},
	"freshrss":     {{"8280", "80"}},
	"miniflux":     {{"8285", "8080"}},
	"rss-bridge":   {{"3000", "80"}},
	"kimai2":       {{"8001", "8001"}},
}

var emojiHints = map[string]string{
	"mysql": "🗄️", "postgres": "🐘", "postgresql": "🐘", "mongo": "🍃", "mongodb": "🍃",
	"redis": "⚡", "mariadb": "🐬", "nginx": "🧱", "httpd": "🧱", "caddy": "🛡️",
	"rabbitmq": "🐇", "kafka": "📬", "zookeeper": "🦓", "elasticsearch": "🔎", "kibana": "📊",
	"grafana": "📊", "prometheus": "🕰️", "influxdb": "📈", "clickhouse": "⚡",
	"sonarr": "📺", "radarr": "🎬", "lidarr": "🎵", "readarr": "📚", "prowlarr": "🔎", "jackett": "🧥",
	"transmission": "📡", "qbittorrent": "🧲", "deluge": "🌊", "sabnzbd": "⬇️",
	"jellyfin": "🎬", "emby": "🎞️", "plex": "📺", "navidrome": "🎵", "kavita": "📚", "komga": "📖",
	"calibre": "📗", "calibre-web": "📗", "photoprism": "🖼️", "immich": "📸", "lychee": "📷",
	"pihole": "🕳️", "wireguard": "🔒", "openvpn": "🔒", "cadvisor": "📊", "netdata": "🔥",
	"gitea": "🛠️", "jenkins": "👷", "drone": "🚁", "woodpecker": "🐦",
	"adminer": "🛢️", "mongo-express": "🍃", "phpmyadmin": "🗄️",
	"matomo": "📊", "umami": "📉", "plausible": "📊",
	"ghost": "👻", "wordpress": "📝", "drupal": "💠", "joomla": "🧩",
	"vaultwarden": "🔐", "bitwarden": "🔐", "paperless": "📄", "paperless-ngx": "📄",
	"nextcloud": "☁️", "owncloud": "☁️", "seafile": "🌊",
	"kimai": "⏱️", "monica": "💗", "trilium": "🗒️", "joplin": "📓",
	"freshrss": "📰", "miniflux": "🗞️", "wallabag": "📑", "rss": "📰",
	"code-server": "💻", "guacamole": "🥑", "vscode": "💻",
	"rocketchat": "💬", "matrix": "🗣️", "zulip": "💬", "synapse": "🗣️",
	"ollama": "🦙", "whisper": "🎤", "pytorch": "🔥", "tensorflow": "🧠",
	"alpine": "🏔️", "debian": "🌀", "ubuntu": "🔶", "centos": "💠", "fedora": "🔵", "busybox": "📦",
	"python": "🐍", "node": "🟢", "golang": "🐹", "openjdk": "☕", "php": "🐘", "ruby": "💎", "rust": "🦀", "perl": "🐪",
	"docker": "🐳", "registry": "🏗️", "portainer": "🐳", "consul": "📇", "etcd": "🗂️", "nats": "✉️",
}

func guessEmoji(name string) string {
	toks := tokenize(name)
	for w, e := range emojiHints {
		if toks[w] || strings.Contains(strings.ToLower(name), w) {
			return e
		}
	}
	return "🧩"
}

func guessTypeID(name, desc string) string {
	toks := tokenize(name)
	for w := range toks {
		for _, rule := range classifyRules {
			for _, rw := range rule.Words {
				if w == rw {
					return rule.TypeID
				}
			}
		}
	}
	// 名称里没有独立词,尝试子串匹配(如 "database" 嵌在复合词里)
	l := strings.ToLower(name + " " + desc)
	for _, rule := range classifyRules {
		for _, rw := range rule.Words {
			if len(rw) >= 4 && strings.Contains(l, rw) {
				return rule.TypeID
			}
		}
	}
	return "hot"
}

// ---- 源 1:Docker 官方镜像库(GitHub docker-library/official-images) ----

type officialCrawlResult struct {
	apps   []StoreApp
	failed string
}

func crawlDockerOfficial() []StoreApp {
	// tarball 一次下载,包含全部官方镜像定义
	url := "https://codeload.github.com/docker-library/official-images/tar.gz/refs/heads/master"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", crawlUA)
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("爬取官方镜像库失败: %v", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("爬取官方镜像库失败: HTTP %d", resp.StatusCode)
		return nil
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	apps := []StoreApp{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		p := hdr.Name
		i := strings.LastIndex(p, "/library/")
		if i < 0 {
			continue
		}
		img := p[i+len("/library/"):]
		if img == "" || strings.Contains(img, "/") {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(tr, 512<<10))
		if err != nil {
			continue
		}
		tags := parseOfficialTags(string(content))
		if len(tags) == 0 {
			continue
		}
		vers := make([]AppVersion, 0, len(tags))
		for _, t := range tags {
			vers = append(vers, AppVersion{
				Version: t,
				Image:   img + ":" + t,
				Network: "bridge",
				Ports:   knownPorts[img],
				Env:     []EnvVar{{Name: "TZ", Value: "Asia/Shanghai"}},
			})
		}
		apps = append(apps, StoreApp{
			ID:          img,
			Name:        strings.Title(img),
			Icon:        guessEmoji(img),
			Logo:        "https://cdn.jsdelivr.net/npm/simple-icons@13/icons/" + strings.ReplaceAll(img, "_", "-") + ".svg",
			Description: "Docker 官方镜像",
			TypeID:      guessTypeID(img, ""),
			Versions:    vers,
		})
	}
	log.Printf("官方镜像库爬取完成:%d 个", len(apps))
	return apps
}

func parseOfficialTags(content string) []string {
	seen := map[string]bool{}
	tags := []string{}
	add := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" || len(t) > 30 || strings.ContainsAny(t, "/ @") || seen[t] {
			return
		}
		seen[t] = true
		tags = append(tags, t)
	}
	for _, line := range strings.Split(content, "\n") {
		for _, prefix := range []string{"Tags:", "SharedTags:"} {
			if strings.HasPrefix(line, prefix) {
				for _, t := range strings.Split(strings.TrimPrefix(line, prefix), ",") {
					add(t)
				}
			}
		}
	}
	if len(tags) > 6 {
		tags = tags[:6]
	}
	if !seen["latest"] {
		tags = append(tags, "latest")
	}
	return tags
}

// ---- 源 2/3:GitHub org 仓库(linuxserver / bitnami) ----

type ghRepo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Archived    bool   `json:"archived"`
	Fork        bool   `json:"fork"`
}

// 无意义仓库名(org 内非镜像仓库)
var ghSkipNames = map[string]bool{
	"base": true, "unraid-templates": true, "containers": true, "charts": true,
	"docker-template": true, "website": true, "docs": true, ".github": true,
}

func crawlGitHubOrg(org string, prefix string, max int) []StoreApp {
	apps := []StoreApp{}
	seen := map[string]bool{}
	// bitnami 等组织 orgs API 返回 404,需 fallback 到 users 端点
	apiBase := ""
	for _, base := range []string{"orgs", "users"} {
		if err := fetchInto(fmt.Sprintf("https://api.github.com/%s/%s/repos?per_page=1", base, org), &[]ghRepo{}, 15*time.Second); err == nil {
			apiBase = base
			break
		}
	}
	if apiBase == "" {
		log.Printf("爬取 org %s 失败: API 不可达", org)
		return nil
	}
	for page := 1; page <= 4 && len(apps) < max; page++ {
		url := fmt.Sprintf("https://api.github.com/%s/%s/repos?per_page=100&page=%d&sort=pushed", apiBase, org, page)
		var repos []ghRepo
		if err := fetchInto(url, &repos, 30*time.Second); err != nil {
			log.Printf("爬取 org %s 第 %d 页失败: %v", org, page, err)
			break
		}
		if len(repos) == 0 {
			break
		}
		for _, r := range repos {
			if r.Archived || r.Fork || seen[r.Name] || ghSkipNames[strings.ToLower(r.Name)] {
				continue
			}
			seen[r.Name] = true
			name := r.Name
			desc := r.Description
			if len(desc) > 120 {
				desc = desc[:117] + "..."
			}
			img := prefix + "/" + name
			apps = append(apps, StoreApp{
				ID:          org + "-" + name,
				Name:        strings.Title(strings.ReplaceAll(name, "-", " ")),
				Icon:        guessEmoji(name + " " + desc),
				Description: desc,
				TypeID:      guessTypeID(name, desc),
				Versions: []AppVersion{{
					Version: "latest",
					Image:   img + ":latest",
					Network: "bridge",
					Ports:   knownPorts[name],
					Env:     []EnvVar{{Name: "TZ", Value: "Asia/Shanghai"}},
				}},
			})
			if len(apps) >= max {
				break
			}
		}
	}
	log.Printf("org %s 爬取完成:%d 个", org, len(apps))
	return apps
}

// ---- 源 4:quay.io 热门 ----

type quayRepo struct {
	Namespace   string  `json:"namespace"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Kind        string  `json:"kind"`
	Popularity  float64 `json:"popularity"`
}

func crawlQuay() []StoreApp {
	apps := []StoreApp{}
	seen := map[string]bool{}
	for page := 1; page <= 3; page++ {
		url := fmt.Sprintf("https://quay.io/api/v1/repository?public=true&page_size=100&popularity=true&page=%d", page)
		var out struct {
			Repositories []quayRepo `json:"repositories"`
		}
		if err := fetchInto(url, &out, 30*time.Second); err != nil {
			log.Printf("爬取 quay 第 %d 页失败: %v", page, err)
			break
		}
		if len(out.Repositories) == 0 {
			break
		}
		for _, r := range out.Repositories {
			if r.Kind != "image" || r.Popularity < 2 {
				continue
			}
			img := r.Namespace + "/" + r.Name
			if seen[img] {
				continue
			}
			seen[img] = true
			desc := r.Description
			if i := strings.Index(desc, "\n"); i > 0 {
				desc = desc[:i]
			}
			if len(desc) > 120 {
				desc = desc[:117] + "..."
			}
			if desc == "" {
				desc = "Quay.io 镜像"
			}
			apps = append(apps, StoreApp{
				ID:          "quay-" + r.Namespace + "-" + r.Name,
				Name:        strings.Title(strings.ReplaceAll(r.Name, "-", " ")),
				Icon:        guessEmoji(r.Name),
				Description: desc,
				TypeID:      guessTypeID(r.Name, desc),
				Versions: []AppVersion{{
					Version: "latest",
					Image:   "quay.io/" + img + ":latest",
					Network: "bridge",
					Env:     []EnvVar{{Name: "TZ", Value: "Asia/Shanghai"}},
				}},
			})
		}
	}
	log.Printf("quay 爬取完成:%d 个", len(apps))
	return apps
}

// ---- 爬取编排 ----

type crawlStoreFile struct {
	CrawledAt string     `json:"crawledAt"`
	Apps      []StoreApp `json:"apps"`
}

var crawlMu sync.Mutex

func handleCrawl(w http.ResponseWriter, r *http.Request) {
	// reset:清空爬取结果
	if r.URL.Query().Get("reset") == "1" {
		os.Remove(filepath.Join(dataDir(), "store-crawled.json"))
		jsonOK(w, "已清除爬取的镜像")
		return
	}
	crawlMu.Lock()
	defer crawlMu.Unlock()

	// 并发执行四路爬取
	var (
		mu          sync.Mutex
		official    []StoreApp
		linuxserver []StoreApp
		hotio       []StoreApp
		quay        []StoreApp
		wg          sync.WaitGroup
	)
	wg.Add(4)
	go func() { defer wg.Done(); a := crawlDockerOfficial(); mu.Lock(); official = a; mu.Unlock() }()
	go func() { defer wg.Done(); a := crawlGitHubOrg("linuxserver", "linuxserver", 300); mu.Lock(); linuxserver = a; mu.Unlock() }()
	go func() { defer wg.Done(); a := crawlGitHubOrg("hotio", "hotio", 100); mu.Lock(); hotio = a; mu.Unlock() }()
	go func() { defer wg.Done(); a := crawlQuay(); mu.Lock(); quay = a; mu.Unlock() }()
	wg.Wait()

	// 当前目录(内置+远程)已有镜像,按镜像名去重
	cur, _ := loadStore()
	existing := map[string]bool{}
	for _, a := range cur.Apps {
		for _, v := range a.Versions {
			base := v.Image
			if i := strings.LastIndex(base, ":"); i > 0 {
				base = base[:i]
			}
			existing[base] = true
		}
		existing[a.ID] = true
	}

	merged := []StoreApp{}
	added := map[string]bool{}
	stats := map[string]int{"official": 0, "linuxserver": 0, "hotio": 0, "quay": 0}
	appendApps := func(list []StoreApp, key string) {
		for _, a := range list {
			if len(a.Versions) == 0 {
				continue
			}
			base := a.Versions[0].Image
			if i := strings.LastIndex(base, ":"); i > 0 {
				base = base[:i]
			}
			if existing[base] || added[a.ID] {
				continue
			}
			added[a.ID] = true
			merged = append(merged, a)
			stats[key]++
		}
	}
	appendApps(official, "official")
	appendApps(linuxserver, "linuxserver")
	appendApps(hotio, "hotio")
	appendApps(quay, "quay")

	out := crawlStoreFile{
		CrawledAt: time.Now().Format("2006-01-02 15:04"),
		Apps:      merged,
	}
	b, _ := json.MarshalIndent(out, "", " ")
	if err := os.WriteFile(filepath.Join(dataDir(), "store-crawled.json"), b, 0600); err != nil {
		jsonErr(w, 500, "写入失败:"+err.Error())
		return
	}
	log.Printf("爬取完成:共收录 %d 个新镜像 %v", len(merged), stats)
	jsonOK(w, map[string]any{
		"message":     fmt.Sprintf("爬取完成,新增 %d 个镜像", len(merged)),
		"total":       len(merged),
		"official":    stats["official"],
		"linuxserver": stats["linuxserver"],
		"hotio":       stats["hotio"],
		"quay":        stats["quay"],
	})
}



// GET /api/status : docker 状态 + 商店统计
func handleStatus(w http.ResponseWriter, r *http.Request) {
	installed := dockerInstalled()
	alive := false
	var ver string
	if installed {
		if out, err := dockerCmd(5*time.Second, "version", "--format", "{{.Server.Version}}"); err == nil {
			alive = true
			ver = strings.TrimSpace(out)
		}
	}
	store, _ := loadStore()
	state.mu.Lock()
	depN := len(state.deployed)
	state.mu.Unlock()
	hint := ""
	if !installed {
		hint = "Alpine: apk add docker && rc-update add docker boot && service docker start; Debian/Ubuntu: curl -fsSL https://get.docker.com | sh"
	} else if !alive {
		hint = "Docker 已安装但守护进程未运行,请启动: service docker start 或 systemctl start docker"
	}
	jsonOK(w, map[string]any{
		"dockerInstalled": installed,
		"dockerAlive":     alive,
		"dockerVersion":   ver,
		"storeApps":       len(store.Apps),
		"storeTypes":      len(store.Types),
		"deployed":        depN,
		"installHint":     hint,
		"pluginVersion":   "1.3.0",
	})
}

// GET /api/store : 商店目录(合并已部署状态)
func handleStore(w http.ResponseWriter, r *http.Request) {
	store, err := loadStore()
	if err != nil {
		jsonErr(w, 500, "商店数据解析失败: "+err.Error())
		return
	}
	state.mu.Lock()
	dep := make(map[string]DeployedApp, len(state.deployed))
	for _, d := range state.deployed {
		dep[d.AppID] = d
	}
	state.mu.Unlock()
	type appOut struct {
		StoreApp
		Installed   bool   `json:"installed"`
		Instance    string `json:"instance,omitempty"`
		InstalledAt string `json:"installedAt,omitempty"`
	}
	apps := make([]appOut, 0, len(store.Apps))
	for _, a := range store.Apps {
		o := appOut{StoreApp: a}
		if d, ok := dep[a.ID]; ok {
			o.Installed = true
			o.Instance = d.Name
			o.InstalledAt = d.CreatedAt.Format("2006-01-02 15:04")
		}
		apps = append(apps, o)
	}
	jsonOK(w, map[string]any{"types": store.Types, "apps": apps, "version": store.Version})
}

// GET /api/meta : 商店源信息
func handleMeta(w http.ResponseWriter, r *http.Request) {
	store, _ := loadStore()
	updatedAt := ""
	remote := false
	if fi, err := os.Stat(filepath.Join(dataDir(), "store-remote.json")); err == nil {
		remote = true
		updatedAt = fi.ModTime().Format("2006-01-02 15:04")
	}
	crawled := 0
	crawledAt := ""
	if b, err := os.ReadFile(filepath.Join(dataDir(), "store-crawled.json")); err == nil {
		var cf crawlStoreFile
		if json.Unmarshal(b, &cf) == nil {
			crawled = len(cf.Apps)
			crawledAt = cf.CrawledAt
		}
	}
	jsonOK(w, map[string]any{
		"sources":     defaultSources,
		"usingRemote": remote,
		"updatedAt":   updatedAt,
		"apps":        len(store.Apps),
		"types":       len(store.Types),
		"crawled":     crawled,
		"crawledAt":   crawledAt,
	})
}

// fetchStoreSource 从 URL 拉取并校验 store.json,成功返回字节
func fetchStoreSource(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var s StoreData
	if err := json.Unmarshal(b, &s); err != nil || len(s.Apps) == 0 {
		return nil, fmt.Errorf("store.json 格式不合法")
	}
	return b, nil
}

// POST /api/refresh : 从远程源更新商店目录(body 可选 {"url":"..."});无 url 依次尝试默认源
func handleRefresh(w http.ResponseWriter, r *http.Request) {
	url := ""
	if r.Method == "POST" {
		var body struct{ URL string `json:"url"` }
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
		url = strings.TrimSpace(body.URL)
	} else {
		url = strings.TrimSpace(r.URL.Query().Get("url"))
	}
	// reset=1 清除远程缓存恢复内置
	if r.URL.Query().Get("reset") == "1" {
		os.Remove(filepath.Join(dataDir(), "store-remote.json"))
		jsonOK(w, "已恢复内置商店目录")
		return
	}
	var sources []string
	if url != "" {
		if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
			jsonErr(w, 400, "URL 必须以 http(s):// 开头")
			return
		}
		sources = []string{url}
	} else {
		sources = defaultSources
	}
	var (
		b   []byte
		err error
		tried string
	)
	for _, s := range sources {
		b, err = fetchStoreSource(s)
		if err == nil {
			break
		}
		tried += s + " (" + err.Error() + "); "
	}
	if err != nil {
		jsonErr(w, 502, "所有源均拉取失败: "+tried)
		return
	}
	if err := os.WriteFile(filepath.Join(dataDir(), "store-remote.json"), b, 0600); err != nil {
		jsonErr(w, 500, "缓存写入失败: "+err.Error())
		return
	}
	var s StoreData
	json.Unmarshal(b, &s)
	jsonOK(w, map[string]any{
		"message": fmt.Sprintf("已拉取最新目录:%d 个应用 / %d 个分类", len(s.Apps), len(s.Types)),
		"apps":    len(s.Apps),
		"types":   len(s.Types),
	})
}

// GET /api/installed : 已部署应用 + 容器实时状态
func handleInstalled(w http.ResponseWriter, r *http.Request) {
	if !dockerInstalled() {
		jsonErr(w, 503, "docker 未安装")
		return
	}
	out, err := dockerCmd(10*time.Second, "ps", "-a",
		"--filter", "label="+labelKey+"=1",
		"--format", "{{.Names}}|{{.Status}}|{{.Image}}|{{.Ports}}")
	if err != nil {
		jsonErr(w, 500, "docker 查询失败:"+out)
		return
	}
	type row struct {
		Name    string `json:"name"` // 实例名(去掉前缀)
		CName   string `json:"cName"`
		Status  string `json:"status"`
		Running bool   `json:"running"`
		Image   string `json:"image"`
		Ports   string `json:"ports"`
	}
	rows := []row{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p := strings.SplitN(line, "|", 4)
		for len(p) < 4 {
			p = append(p, "")
		}
		rows = append(rows, row{
			Name:    strings.TrimPrefix(p[0], containerPrefix),
			CName:   p[0],
			Status:  p[1],
			Running: strings.HasPrefix(p[1], "Up"),
			Image:   p[2],
			Ports:   p[3],
		})
	}
	jsonOK(w, rows)
}

// deploy 请求体
type deployReq struct {
	AppID   string      `json:"appId"`
	Version string      `json:"version"`
	Name    string      `json:"name"`
	Image   string      `json:"image"` // 自定义镜像(宝塔风格:从镜像直接创建)
	Ports   []PortMap   `json:"ports"`
	Volumes []VolumeMap `json:"volumes"`
	Env     []EnvVar    `json:"env"`
}

// ---------------- 异步部署任务 ----------------

type deployTask struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"` // pulling / running / done / error
	Stage     string    `json:"stage"`  // 人类可读进度文案
	Image     string    `json:"image"`
	AppName   string    `json:"appName"`
	Error     string    `json:"error,omitempty"`
	Container string    `json:"container,omitempty"`
	Access   string    `json:"access,omitempty"`
	StartedAt time.Time `json:"startedAt"`
	DoneAt   *time.Time `json:"doneAt,omitempty"`
}

var (
	deployTaskMu sync.Mutex
	deployTasks  = map[string]*deployTask{}
)

// POST /api/deploy : 一键部署(异步)
func handleDeploy(w http.ResponseWriter, r *http.Request) {
	if !dockerInstalled() {
		jsonErr(w, 503, "docker 未安装")
		return
	}
	if !dockerAlive() {
		jsonErr(w, 503, "docker 守护进程未运行")
		return
	}
	var req deployReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		jsonErr(w, 400, "请求体不合法")
		return
	}
	// 自定义镜像部署(宝塔风格:从任意镜像创建容器)
	if req.AppID == "__custom__" {
		img := strings.TrimSpace(req.Image)
		if img == "" {
			jsonErr(w, 400, "缺少镜像名")
			return
		}
		if strings.ContainsAny(img, " ;&|$`") {
			jsonErr(w, 400, "镜像名不合法")
			return
		}
		instance := req.Name
		if instance == "" {
			// 从镜像名生成合法实例名
			base := strings.ToLower(img)
			base = strings.ReplaceAll(base, ":", "-")
			base = strings.ReplaceAll(base, "/", "-")
			var b strings.Builder
			for _, c := range base {
				if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
					b.WriteRune(c)
				}
			}
			instance = b.String()
			if instance == "" {
				instance = "app"
			}
		}
		for _, c := range instance {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				jsonErr(w, 400, "实例名只能包含字母、数字、-、_")
				return
			}
		}
		cname := containerName(instance)
		if out, _ := dockerCmd(5*time.Second, "ps", "-a", "--filter", "name=^"+cname+"$", "--format", "{{.Names}}"); strings.TrimSpace(out) != "" {
			jsonErr(w, 409, "容器已存在: "+cname+",请先删除或换个实例名")
			return
		}
		// 若指定端口但未填主机端口,自动分配
		args := []string{"run", "-d", "--name", cname, "--restart", "unless-stopped", "--label", labelKey + "=1"}
		for _, p := range req.Ports {
			if p.Host != "" && p.Container != "" {
				args = append(args, "-p", p.Host+":"+p.Container)
			}
		}
		for _, v := range req.Volumes {
			if v.Host != "" && v.Container != "" {
				host := v.Host
				if !strings.HasPrefix(host, "/") {
					host = filepath.Join(dataDir(), "volumes", instance, host)
				}
				os.MkdirAll(host, 0777)
				args = append(args, "-v", host+":"+v.Container)
			}
		}
		for _, e := range req.Env {
			if e.Name != "" {
				args = append(args, "-e", e.Name+"="+e.Value)
			}
		}
		args = append(args, img)

		taskID := fmt.Sprintf("deploy-%d", time.Now().UnixNano())
		access := ""
		for _, p := range req.Ports {
			if p.Host != "" {
				access = "http://<服务器IP>:" + strings.Split(p.Host, ":")[0]
				break
			}
		}
		task := &deployTask{
			ID: taskID, Status: "pulling",
			Stage: fmt.Sprintf("正在拉取镜像 %s …", img),
			Image: img, AppName: img, StartedAt: time.Now(), Access: access,
		}
		deployTaskMu.Lock()
		deployTasks[taskID] = task
		deployTaskMu.Unlock()
		go func() {
			log.Printf("自定义部署 %s -> %s (async)", img, cname)
			pullOut, pullErr := dockerCmd(10*time.Minute, "pull", img)
			if pullErr != nil {
				deployTaskMu.Lock()
				task.Status, task.Stage = "error", "镜像拉取失败"
				task.Error = "镜像拉取失败:" + lastLines(pullOut, 3)
				now := time.Now()
				task.DoneAt = &now
				deployTaskMu.Unlock()
				return
			}
			deployTaskMu.Lock()
			task.Status, task.Stage = "running", fmt.Sprintf("正在启动容器 %s …", cname)
			deployTaskMu.Unlock()
			runOut, runErr := dockerCmd(60*time.Second, args...)
			if runErr != nil {
				dockerCmd(10*time.Second, "rm", "-f", cname)
				deployTaskMu.Lock()
				task.Status, task.Stage = "error", "容器启动失败"
				task.Error = "启动失败:" + lastLines(runOut, 5)
				now := time.Now()
				task.DoneAt = &now
				deployTaskMu.Unlock()
				return
			}
			state.mu.Lock()
			state.deployed = append(state.deployed, DeployedApp{
				Name: instance, AppID: "__custom__", Image: img, Version: "custom",
				Ports: req.Ports, CreatedAt: time.Now(),
			})
			saveStateLocked()
			state.mu.Unlock()
			deployTaskMu.Lock()
			task.Status, task.Stage, task.Container = "done", "部署成功", cname
			now := time.Now()
			task.DoneAt = &now
			deployTaskMu.Unlock()
		}()
		jsonOK(w, map[string]any{"taskId": taskID, "status": "pulling", "message": "已开始部署自定义镜像…"})
		return
	}
	store, err := loadStore()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	// 找应用
	var app *StoreApp
	for i := range store.Apps {
		if store.Apps[i].ID == req.AppID {
			app = &store.Apps[i]
			break
		}
	}
	if app == nil {
		jsonErr(w, 404, "应用不存在: "+req.AppID)
		return
	}
	// 找版本
	var ver *AppVersion
	for i := range app.Versions {
		if app.Versions[i].Version == req.Version {
			ver = &app.Versions[i]
			break
		}
	}
	if ver == nil && len(app.Versions) > 0 {
		ver = &app.Versions[0]
	}
	if ver == nil {
		jsonErr(w, 404, "应用无可用版本")
		return
	}
	// 实例名:默认 appId,只允许 [a-zA-Z0-9_-]
	instance := req.Name
	if instance == "" {
		instance = app.ID
	}
	for _, c := range instance {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			jsonErr(w, 400, "实例名只能包含字母、数字、-、_")
			return
		}
	}
	cname := containerName(instance)
	// 已存在同名容器?
	if out, _ := dockerCmd(5*time.Second, "ps", "-a", "--filter", "name=^"+cname+"$", "--format", "{{.Names}}"); strings.TrimSpace(out) != "" {
		jsonErr(w, 409, "容器已存在: "+cname+",请先删除或换个实例名")
		return
	}
	// 端口/卷/环境变量:请求缺省时用商店默认
	ports := req.Ports
	if len(ports) == 0 {
		ports = ver.Ports
	}
	volumes := req.Volumes
	if len(volumes) == 0 {
		volumes = ver.Volumes
	}
	envs := req.Env
	if len(envs) == 0 {
		envs = ver.Env
	}
	// 构造 docker run
	args := []string{"run", "-d",
		"--name", cname,
		"--restart", "unless-stopped",
		"--label", labelKey + "=1",
	}
	if ver.Network == "host" {
		args = append(args, "--network", "host")
	}
	for _, p := range ports {
		if p.Host != "" && p.Container != "" {
			args = append(args, "-p", p.Host+":"+p.Container)
		}
	}
	for _, v := range volumes {
		if v.Host != "" && v.Container != "" {
			// 相对路径挂载到面板数据目录下,避免污染根目录
			host := v.Host
			if !strings.HasPrefix(host, "/") {
				host = filepath.Join(dataDir(), "volumes", instance, host)
			}
			os.MkdirAll(host, 0777)
			args = append(args, "-v", host+":"+v.Container)
		}
	}
	for _, e := range envs {
		if e.Name != "" {
			args = append(args, "-e", e.Name+"="+e.Value)
		}
	}
	args = append(args, ver.Image)
	// 容器启动命令(如 minio 需要 server /data)
	if cmd := strings.TrimSpace(ver.Command); cmd != "" {
		args = append(args, strings.Fields(cmd)...)
	}

	// 访问提示
	access := ""
	for _, p := range ports {
		if p.Host != "" {
			access = "http://<服务器IP>:" + strings.Split(p.Host, ":")[0]
			break
		}
	}

	// ---- 异步部署:立即返回任务ID,后台执行 pull + run ----
	taskID := fmt.Sprintf("deploy-%d", time.Now().UnixNano())
	task := &deployTask{
		ID:        taskID,
		Status:    "pulling",
		Stage:     fmt.Sprintf("正在拉取镜像 %s …", ver.Image),
		Image:     ver.Image,
		AppName:   app.Name,
		StartedAt: time.Now(),
		Access:    access,
	}
	deployTaskMu.Lock()
	deployTasks[taskID] = task
	deployTaskMu.Unlock()

	go func() {
		log.Printf("部署 %s %s -> %s (async)", app.Name, ver.Version, ver.Image)
		// 阶段1:拉取镜像
		pullOut, pullErr := dockerCmd(10*time.Minute, "pull", ver.Image)
		if pullErr != nil {
			deployTaskMu.Lock()
			task.Status = "error"
			task.Stage = "镜像拉取失败"
			task.Error = "镜像拉取失败:" + lastLines(pullOut, 3)
			now := time.Now()
			task.DoneAt = &now
			deployTaskMu.Unlock()
			return
		}
		// 阶段2:启动容器
		deployTaskMu.Lock()
		task.Status = "running"
		task.Stage = fmt.Sprintf("镜像拉取完成,正在启动容器 %s …", cname)
		deployTaskMu.Unlock()

		runOut, runErr := dockerCmd(60*time.Second, args...)
		if runErr != nil {
			// 清理失败的容器
			dockerCmd(10*time.Second, "rm", "-f", cname)
			deployTaskMu.Lock()
			task.Status = "error"
			task.Stage = "容器启动失败"
			task.Error = "启动失败:" + lastLines(runOut, 5)
			now := time.Now()
			task.DoneAt = &now
			deployTaskMu.Unlock()
			return
		}
		// 成功
		state.mu.Lock()
		state.deployed = append(state.deployed, DeployedApp{
			Name:      instance,
			AppID:     app.ID,
			Image:     ver.Image,
			Version:   ver.Version,
			Ports:     ports,
			CreatedAt: time.Now(),
		})
		saveStateLocked()
		state.mu.Unlock()

		deployTaskMu.Lock()
		task.Status = "done"
		task.Stage = "部署成功"
		task.Container = cname
		now := time.Now()
		task.DoneAt = &now
		deployTaskMu.Unlock()
		log.Printf("部署完成 %s -> %s", app.Name, cname)
	}()

	jsonOK(w, map[string]any{
		"taskId":  taskID,
		"status":  "pulling",
		"message": "已开始异步部署,正在拉取镜像…",
	})
}

// GET /api/deploy/status?id=xxx : 轮询异步部署进度
func handleDeployStatus(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("id")
	if taskID == "" {
		jsonErr(w, 400, "缺少 id 参数")
		return
	}
	deployTaskMu.Lock()
	task, ok := deployTasks[taskID]
	deployTaskMu.Unlock()
	if !ok {
		jsonErr(w, 404, "任务不存在")
		return
	}
	// 清理超过30分钟的已完成任务
	if task.DoneAt != nil && time.Since(*task.DoneAt) > 30*time.Minute {
		deployTaskMu.Lock()
		delete(deployTasks, taskID)
		deployTaskMu.Unlock()
		jsonErr(w, 404, "任务已过期")
		return
	}
	jsonOK(w, task)
}

// POST /api/action : start / stop / restart / remove
func handleAction(w http.ResponseWriter, r *http.Request) {
	if !dockerInstalled() {
		jsonErr(w, 503, "docker 未安装")
		return
	}
	var req struct {
		Name   string `json:"name"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.Name == "" || req.Action == "" {
		jsonErr(w, 400, "参数不合法")
		return
	}
	cname := containerName(req.Name)
	var (
		out string
		err error
	)
	switch req.Action {
	case "start":
		out, err = dockerCmd(30*time.Second, "start", cname)
	case "stop":
		out, err = dockerCmd(60*time.Second, "stop", cname)
	case "restart":
		out, err = dockerCmd(90*time.Second, "restart", cname)
	case "remove":
		dockerCmd(60*time.Second, "stop", cname)
		out, err = dockerCmd(60*time.Second, "rm", "-f", cname)
		if err == nil {
			state.mu.Lock()
			keep := state.deployed[:0]
			for _, d := range state.deployed {
				if d.Name != req.Name {
					keep = append(keep, d)
				}
			}
			state.deployed = keep
			saveStateLocked()
			state.mu.Unlock()
		}
	default:
		jsonErr(w, 400, "未知操作: "+req.Action)
		return
	}
	if err != nil {
		jsonErr(w, 500, req.Action+" 失败:"+lastLines(out, 3))
		return
	}
	jsonOK(w, req.Action+" 成功")
}

// GET /api/logs?name=xxx&tail=200
func handleLogs(w http.ResponseWriter, r *http.Request) {
	if !dockerInstalled() {
		jsonErr(w, 503, "docker 未安装")
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		jsonErr(w, 400, "缺少 name 参数")
		return
	}
	tail := r.URL.Query().Get("tail")
	if tail == "" {
		tail = "200"
	}
	if _, err := strconv.Atoi(tail); err != nil {
		tail = "200"
	}
	out, err := dockerCmd(30*time.Second, "logs", "--tail", tail, "--timestamps", containerName(name))
	if err != nil && out == "" {
		jsonErr(w, 500, "日志获取失败:"+err.Error())
		return
	}
	jsonOK(w, out)
}

func lastLines(s string, n int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(无输出)"
	}
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// ---------------- 宝塔风格:容器/镜像管理 ----------------

// ContainerInfo : docker ps -a 的结构化行
type ContainerInfo struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Image   string   `json:"image"`
	State   string   `json:"state"`
	Status  string   `json:"status"`  // Up 2 hours / Exited (0)...
	Ports   []string `json:"ports"`
	Created string   `json:"created"` // 相对时间文案
	FromApp bool     `json:"fromApp"` // 是否由本插件部署
}

// GET /api/containers : 全部容器列表(宝塔风格)
func handleContainers(w http.ResponseWriter, r *http.Request) {
	if !dockerInstalled() {
		jsonErr(w, 503, "docker 未安装")
		return
	}
	if !dockerAlive() {
		jsonErr(w, 503, "docker 守护进程未运行")
		return
	}
	out, err := dockerCmd(15*time.Second, "ps", "-a",
		"--format", "{{.ID}}\x01{{.Names}}\x01{{.Image}}\x01{{.State}}\x01{{.Status}}\x01{{.Ports}}\x01{{.RunningFor}}")
	if err != nil {
		jsonErr(w, 500, "容器列表获取失败:"+lastLines(out, 2))
		return
	}
	// 本插件部署的容器名集合
	state.mu.Lock()
	appOwned := map[string]bool{}
	for _, d := range state.deployed {
		appOwned[containerName(d.Name)] = true
	}
	state.mu.Unlock()

	list := []ContainerInfo{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Split(line, "\x01")
		for len(f) < 7 {
			f = append(f, "")
		}
		ports := []string{}
		for _, p := range strings.Split(f[5], ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				ports = append(ports, p)
			}
		}
		ci := ContainerInfo{
			ID:      f[0],
			Name:    f[1],
			Image:   f[2],
			State:   f[3],
			Status:  f[4],
			Ports:   ports,
			Created: f[6],
			FromApp: appOwned[f[1]],
		}
		if ci.ID == "" && ci.Name == "" {
			continue
		}
		list = append(list, ci)
	}
	jsonOK(w, list)
}

// ImageInfo : docker images 的结构化行
type ImageInfo struct {
	ID      string `json:"id"`
	Repo    string `json:"repo"`
	Tag     string `json:"tag"`
	Size    string `json:"size"`
	Created string `json:"created"`
}

// GET /api/images : 本地镜像列表
func handleImages(w http.ResponseWriter, r *http.Request) {
	if !dockerInstalled() {
		jsonErr(w, 503, "docker 未安装")
		return
	}
	if !dockerAlive() {
		jsonErr(w, 503, "docker 守护进程未运行")
		return
	}
	out, err := dockerCmd(15*time.Second, "images", "--format",
		"{{.ID}}\x01{{.Repository}}\x01{{.Tag}}\x01{{.Size}}\x01{{.CreatedSince}}")
	if err != nil {
		jsonErr(w, 500, "镜像列表获取失败:"+lastLines(out, 2))
		return
	}
	list := []ImageInfo{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Split(line, "\x01")
		for len(f) < 5 {
			f = append(f, "")
		}
		list = append(list, ImageInfo{ID: f[0], Repo: f[1], Tag: f[2], Size: f[3], Created: f[4]})
	}
	jsonOK(w, list)
}

// POST /api/image/remove : 删除本地镜像
func handleImageRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.ID == "" {
		jsonErr(w, 400, "参数不合法")
		return
	}
	if strings.Contains(req.ID, " ") || strings.ContainsAny(req.ID, ";&|$`") {
		jsonErr(w, 400, "镜像 ID 不合法")
		return
	}
	out, err := dockerCmd(60*time.Second, "rmi", "-f", req.ID)
	if err != nil {
		jsonErr(w, 500, "镜像删除失败:"+lastLines(out, 3))
		return
	}
	jsonOK(w, "镜像已删除")
}

// OnlineImage : Docker Hub 搜索结果条目
type OnlineImage struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Stars       int    `json:"stars"`
	Official    bool   `json:"official"`
}

// GET /api/image/search?q=nginx : 线上镜像搜索(Docker Hub API,国内可达)
func handleImageSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		jsonErr(w, 400, "缺少搜索关键词")
		return
	}
	// Docker Hub 官方搜索 API(国内一般可达,失败则退回内置精选)
	type hubResp struct {
		Results []struct {
			RepoName    string `json:"repo_name"`
			ShortDesc   string `json:"short_description"`
			StarCount   int    `json:"star_count"`
			IsOfficial  bool   `json:"is_official"`
		} `json:"results"`
	}
	var hr hubResp
	url := "https://hub.docker.com/v2/search/repositories/?query=" + urlQueryEscape(q) + "&page_size=24"
	err := fetchInto(url, &hr, 15*time.Second)
	if err != nil {
		// 退回:本地商店模糊匹配
		store, _ := loadStore()
		qLower := strings.ToLower(q)
		fallback := []OnlineImage{}
		for _, a := range store.Apps {
			if len(fallback) >= 12 {
				break
			}
			if strings.Contains(strings.ToLower(a.Name), qLower) || strings.Contains(a.ID, qLower) {
				img := ""
				if len(a.Versions) > 0 {
					img = a.Versions[0].Image
				}
				fallback = append(fallback, OnlineImage{Name: img, Description: a.Description})
			}
		}
		if len(fallback) == 0 {
			jsonErr(w, 502, "搜索失败(Docker Hub 不可达):"+err.Error())
			return
		}
		jsonOK(w, map[string]any{"source": "builtin", "results": fallback})
		return
	}
	res := []OnlineImage{}
	for _, it := range hr.Results {
		name := it.RepoName
		if it.IsOfficial && !strings.Contains(name, "/") {
			name = "library/" + name
		}
		res = append(res, OnlineImage{
			Name:        name,
			Description: it.ShortDesc,
			Stars:       it.StarCount,
			Official:    it.IsOfficial,
		})
	}
	jsonOK(w, map[string]any{"source": "dockerhub", "results": res})
}

func urlQueryEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// POST /api/pull : 异步拉取镜像(复用 deployTask 机制)
func handlePull(w http.ResponseWriter, r *http.Request) {
	if !dockerInstalled() || !dockerAlive() {
		jsonErr(w, 503, "docker 未安装或未运行")
		return
	}
	var req struct {
		Image string `json:"image"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.Image == "" {
		jsonErr(w, 400, "参数不合法")
		return
	}
	img := strings.TrimSpace(req.Image)
	if strings.ContainsAny(img, " ;&|$`") {
		jsonErr(w, 400, "镜像名不合法")
		return
	}
	taskID := fmt.Sprintf("pull-%d", time.Now().UnixNano())
	task := &deployTask{
		ID:        taskID,
		Status:    "pulling",
		Stage:     fmt.Sprintf("正在拉取镜像 %s …", img),
		Image:     img,
		AppName:   img,
		StartedAt: time.Now(),
	}
	deployTaskMu.Lock()
	deployTasks[taskID] = task
	deployTaskMu.Unlock()
	go func() {
		out, err := dockerCmd(10*time.Minute, "pull", img)
		deployTaskMu.Lock()
		now := time.Now()
		task.DoneAt = &now
		if err != nil {
			task.Status = "error"
			task.Stage = "镜像拉取失败"
			task.Error = "拉取失败:" + lastLines(out, 3)
		} else {
			task.Status = "done"
			task.Stage = "镜像拉取成功"
		}
		deployTaskMu.Unlock()
	}()
	jsonOK(w, map[string]any{"taskId": taskID, "message": "已开始拉取镜像"})
}

// ContainerDetail : docker inspect 摘要
type ContainerDetail struct {
	Name    string            `json:"name"`
	ID      string            `json:"id"`
	Image   string            `json:"image"`
	State   string            `json:"state"`
	Status  string            `json:"status"`
	Created string            `json:"created"`
	Ports   []PortMap         `json:"ports"`
	Volumes []VolumeMap       `json:"volumes"`
	Env     []EnvVar          `json:"env"`
	Network string            `json:"network"`
	IP      string            `json:"ip"`
	Restart string            `json:"restartPolicy"`
	Command string            `json:"command"`
}

// GET /api/inspect?name=xxx : 容器详情(docker inspect 解析)
func handleInspect(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		jsonErr(w, 400, "缺少 name 参数")
		return
	}
	if strings.ContainsAny(name, " ;&|$`") {
		jsonErr(w, 400, "容器名不合法")
		return
	}
	out, err := dockerCmd(15*time.Second, "inspect", name)
	if err != nil {
		jsonErr(w, 404, "容器不存在:"+lastLines(out, 2))
		return
	}
	var arr []struct {
		Name      string `json:"Name"`
		ID        string `json:"Id"`
		Created   string `json:"Created"`
		State     struct {
			Status string `json:"Status"`
		} `json:"State"`
		Config struct {
			Image  string   `json:"Image"`
			Env    []string `json:"Env"`
			Cmd    []string `json:"Cmd"`
		} `json:"Config"`
		HostConfig struct {
			PortBindings map[string][]struct {
				HostPort string `json:"HostPort"`
			} `json:"PortBindings"`
			Binds         []string          `json:"Binds"`
			RestartPolicy struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
			NetworkMode string `json:"NetworkMode"`
		} `json:"HostConfig"`
		NetworkSettings struct {
			Networks map[string]struct {
				IPAddress string `json:"IPAddress"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if json.Unmarshal([]byte(out), &arr) != nil || len(arr) == 0 {
		jsonErr(w, 500, "inspect 解析失败")
		return
	}
	c := arr[0]
	d := ContainerDetail{
		ID:      c.ID,
		Image:   c.Config.Image,
		State:   c.State.Status,
		Status:  c.State.Status,
		Created: c.Created,
		Ports:   []PortMap{},
		Volumes: []VolumeMap{},
		Env:     []EnvVar{},
	}
	d.Name = strings.TrimPrefix(c.Name, "/")
	if len(c.Config.Cmd) > 0 {
		d.Command = strings.Join(c.Config.Cmd, " ")
	}
	for cport, binds := range c.HostConfig.PortBindings {
		for _, b := range binds {
			d.Ports = append(d.Ports, PortMap{Host: b.HostPort, Container: strings.Split(cport, "/")[0]})
		}
	}
	for _, b := range c.HostConfig.Binds {
		parts := strings.SplitN(b, ":", 2)
		v := VolumeMap{Host: parts[0]}
		if len(parts) > 1 {
			v.Container = parts[1]
		}
		d.Volumes = append(d.Volumes, v)
	}
	for _, e := range c.Config.Env {
		if i := strings.Index(e, "="); i > 0 {
			d.Env = append(d.Env, EnvVar{Name: e[:i], Value: e[i+1:]})
		}
	}
	d.Restart = c.HostConfig.RestartPolicy.Name
	d.Network = c.HostConfig.NetworkMode
	if n, ok := c.NetworkSettings.Networks[d.Network]; ok {
		d.IP = n.IPAddress
	}
	jsonOK(w, d)
}

// POST /api/container/action : 对任意容器执行操作(宝塔风格,不限于本插件部署)
func handleContainerAction(w http.ResponseWriter, r *http.Request) {
	if !dockerInstalled() {
		jsonErr(w, 503, "docker 未安装")
		return
	}
	var req struct {
		Name   string `json:"name"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.Name == "" || req.Action == "" {
		jsonErr(w, 400, "参数不合法")
		return
	}
	if strings.ContainsAny(req.Name, " ;&|$`") {
		jsonErr(w, 400, "容器名不合法")
		return
	}
	name := req.Name
	var (
		out string
		err error
	)
	switch req.Action {
	case "start":
		out, err = dockerCmd(30*time.Second, "start", name)
	case "stop":
		out, err = dockerCmd(60*time.Second, "stop", name)
	case "restart":
		out, err = dockerCmd(90*time.Second, "restart", name)
	case "remove":
		dockerCmd(60*time.Second, "stop", name)
		out, err = dockerCmd(60*time.Second, "rm", "-f", name)
	default:
		jsonErr(w, 400, "未知操作: "+req.Action)
		return
	}
	if err != nil {
		jsonErr(w, 500, req.Action+" 失败:"+lastLines(out, 3))
		return
	}
	jsonOK(w, req.Action+" 成功")
}

// GET /api/container/logs?name=xxx&tail=200 : 任意容器日志
func handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		jsonErr(w, 400, "缺少 name 参数")
		return
	}
	if strings.ContainsAny(name, " ;&|$`") {
		jsonErr(w, 400, "容器名不合法")
		return
	}
	tail := r.URL.Query().Get("tail")
	if tail == "" {
		tail = "300"
	}
	if _, err := strconv.Atoi(tail); err != nil {
		tail = "300"
	}
	out, err := dockerCmd(30*time.Second, "logs", "--tail", tail, "--timestamps", name)
	if err != nil && out == "" {
		jsonErr(w, 500, "日志获取失败:"+err.Error())
		return
	}
	jsonOK(w, out)
}

// ---------------- 路由 ----------------

func routes() *http.ServeMux {
	mux := http.NewServeMux()
	// 页面(相对路径,iframe 嵌入面板)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.NotFound(w, r)
			return
		}
		b, _ := webFS.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
	mux.HandleFunc("GET /api/status", handleStatus)
	mux.HandleFunc("GET /api/store", handleStore)
	mux.HandleFunc("GET /api/meta", handleMeta)
	mux.HandleFunc("POST /api/refresh", handleRefresh)
	mux.HandleFunc("GET /api/refresh", handleRefresh) // 兼容旧版
	mux.HandleFunc("POST /api/crawl", handleCrawl)
	mux.HandleFunc("GET /api/installed", handleInstalled)
	mux.HandleFunc("POST /api/deploy", handleDeploy)
	mux.HandleFunc("GET /api/deploy/status", handleDeployStatus)
	mux.HandleFunc("POST /api/action", handleAction)
	mux.HandleFunc("GET /api/logs", handleLogs)
	// 宝塔风格 Docker 管理
	mux.HandleFunc("GET /api/containers", handleContainers)
	mux.HandleFunc("GET /api/images", handleImages)
	mux.HandleFunc("POST /api/image/remove", handleImageRemove)
	mux.HandleFunc("GET /api/image/search", handleImageSearch)
	mux.HandleFunc("POST /api/pull", handlePull)
	mux.HandleFunc("GET /api/inspect", handleInspect)
	mux.HandleFunc("POST /api/container/action", handleContainerAction)
	mux.HandleFunc("GET /api/container/logs", handleContainerLogs)
	return mux
}

// ---------------- main ----------------

func main() {
	port := os.Getenv("PLUGIN_PORT")
	if port == "" {
		port = "19100" // 独立调试兜底
	}
	bind := os.Getenv("PLUGIN_BIND")
	if bind == "" {
		bind = "127.0.0.1"
	}
	homeDir = os.Getenv("PANEL_HOME")
	stateFile = filepath.Join(dataDir(), "appstore.json")
	os.MkdirAll(dataDir(), 0755)
	loadState()

	srv := &http.Server{
		Addr:              bind + ":" + port,
		Handler:           routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		srv.Close()
	}()

	log.Printf("app-store 插件启动 :%s (panel=%s)", bind+":"+port, homeDir)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
