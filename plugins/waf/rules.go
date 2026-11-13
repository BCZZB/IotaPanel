// SPDX-License-Identifier: Apache-2.0
// 规则引擎：内置 12 组防护规则（对标雷池社区版的攻击检测能力面）+ 用户自定义规则。
// 所有内置规则使用 Go RE2 正则（线性时间，无回溯爆炸风险），编译一次常驻复用。

package main

import (
	"fmt"
	"regexp"
	"strings"
)

// ---------- 检测目标 ----------

type Target uint16

const (
	TPath Target = 1 << iota
	TQuery
	THeaders
	TUA
	TReferer
	TCookie
	TBody
)
const TAll = TPath | TQuery | THeaders | TUA | TReferer | TCookie | TBody

func parseTarget(s string) Target {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "path":
		return TPath
	case "query":
		return TQuery
	case "headers":
		return THeaders
	case "ua", "user-agent":
		return TUA
	case "referer":
		return TReferer
	case "cookie":
		return TCookie
	case "body":
		return TBody
	default:
		return TAll
	}
}

func (t Target) has(x Target) bool { return t&x != 0 }

// ---------- 规则结构 ----------

// Rule 编译后的内置规则
type Rule struct {
	ID       string `json:"id"`
	Group    string `json:"group"`
	Desc     string `json:"desc"`
	Severity string `json:"severity"` // high | medium | low
	Target   Target `json:"-"`
	RawOnly  bool   `json:"-"` // 仅匹配原始串（防解码后误报）
	re       *regexp.Regexp
}

// RuleGroup 内置规则组（可整体启停）
type RuleGroup struct {
	Key   string  `json:"key"`
	Name  string  `json:"name"`
	Desc  string  `json:"desc"`
	Rules []*Rule `json:"rules"`
}

// RuleSet 某份配置编译出的完整规则集
type RuleSet struct {
	Groups      []*RuleGroup
	groupEnable map[string]bool
	custom      []*compiledCustom
	stats       *Stats // 命中计数挂到全局统计（重建不丢失）
}

type compiledCustom struct {
	def CustomRule
	re  *regexp.Regexp
}

// ---------- 内置规则定义表 ----------

type ruleDef struct {
	id, group, pattern, desc, severity string
	target                             Target
	rawOnly                            bool
}

var builtinRuleDefs = []ruleDef{
	// ===== SQL 注入 =====
	{"SQLI-001", "sqli", `(?i)union[\s+]+(all[\s+]+)?select\b`, "UNION SELECT 联合查询注入", "high", TAll, false},
	{"SQLI-002", "sqli", `(?i)\b(or|and)[\s+]*['"]?\d+['"]?[\s+]*=[\s+]*['"]?\d+`, "布尔盲注（or 1=1 形态）", "high", TAll, false},
	{"SQLI-003", "sqli", `(?i)['"]\s*(or|and)\s*['"]?\w+['"]?\s*=`, "引号拼接布尔注入", "medium", TAll, false},
	{"SQLI-004", "sqli", `(?i)\b(sleep|benchmark|pg_sleep)\s*\(`, "延时盲注（sleep/benchmark）", "high", TAll, false},
	{"SQLI-005", "sqli", `(?i)waitfor[\s+]+delay`, "MSSQL 延时注入（waitfor delay）", "high", TAll, false},
	{"SQLI-006", "sqli", `(?i)\b(information_schema|load_file|into[\s+]+(out|dump)file)\b`, "信息架构读取/文件读写", "high", TAll, false},
	{"SQLI-007", "sqli", `(?i)(extractvalue|updatexml|geometrycollection|multipoint|polygon)\s*\(`, "报错注入函数", "high", TAll, false},
	{"SQLI-008", "sqli", `(?i)/\*!?[0-9]`, "MySQL 版本注释（/*!50000）", "medium", TAll, false},
	{"SQLI-009", "sqli", `(?i);\s*(drop|delete|truncate|shutdown|alter|create)\b`, "堆叠查询（;drop ...）", "high", TAll, false},
	{"SQLI-010", "sqli", `(?i)\b(xp_cmdshell|sp_executesql|sp_makewebtask)\b`, "MSSQL 扩展存储过程", "high", TAll, false},
	{"SQLI-011", "sqli", `(?i)'\s*;?\s*--`, "引号 + SQL 行注释", "medium", TAll, false},
	{"SQLI-012", "sqli", `(?i)\b(exec(\s|\+)+(s|x)p\w+|sp_addextendedproc)\b`, "MSSQL 扩展执行", "medium", TAll, false},

	// ===== XSS 跨站脚本 =====
	{"XSS-001", "xss", `(?i)<script\b`, "Script 标签注入", "high", TAll, false},
	{"XSS-002", "xss", `(?i)javascript\s*:`, "javascript: 伪协议", "high", TAll, false},
	{"XSS-003", "xss", `(?i)\bon(error|load|click|dblclick|mouseover|mouseout|mouseenter|mouseleave|focus|blur|submit|change|keydown|keyup|keypress|input|abort|toggle|drag|dragstart|dragend|drop|wheel|scroll|copy|paste|cut|contextmenu|animationstart|animationend|animationiteration|transitionend|pointerover|pointerdown|pointerup|pointerenter|pointerleave|show|begin|finish|start|play|pause|canplay|volumechange|loadstart|progress)\s*=`, "事件属性注入（on*=）", "high", TAll, false},
	{"XSS-004", "xss", `(?i)<(svg|img|body|iframe|embed|object|video|audio|details|marquee|input|select|textarea|form|link|base|meta)\b[^>]{0,300}?\bon\w+\s*=`, "标签 + 事件属性组合", "high", TAll, false},
	{"XSS-005", "xss", `(?i)<(iframe|embed|object|base)\b`, "危险嵌入/劫持标签", "high", TAll, false},
	{"XSS-006", "xss", `(?i)(document\.cookie|document\.location|window\.location|document\.write|document\.domain|fromcharcode|\.innerhtml|\.outerhtml)`, "敏感 DOM 对象访问", "medium", TAll, false},
	{"XSS-007", "xss", `(?i)\b(eval|alert|prompt|confirm)\s*\(`, "JS 执行/弹窗函数", "medium", TAll, false},
	{"XSS-008", "xss", `(?i)(srcdoc\s*=|data:text/html|vbscript\s*:)`, "srcdoc/data URI/vbscript 注入", "high", TAll, false},
	{"XSS-009", "xss", `(?i)<meta[^>]{0,300}?http-equiv`, "meta refresh 跳转注入", "medium", TAll, false},
	{"XSS-010", "xss", `(?i)expression\s*\(`, "CSS expression() 执行", "medium", TAll, false},

	// ===== 命令注入 =====
	{"CMDI-001", "cmdi", `(?i);\s*(cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|zsh|python\d?|perl|ruby|php|rm|mv|cp|chmod|chown|touch|mkdir|ping|dig|nslookup|sleep|echo)\b`, "分号拼接命令执行", "high", TAll, false},
	{"CMDI-002", "cmdi", `(?i)(\||&&|%0a|\n)\s*(wget|curl|nc|ncat|bash|sh|python\d?|perl|rm|chmod|id|whoami|uname)\b`, "管道/换行接命令执行", "high", TAll, false},
	{"CMDI-003", "cmdi", `(?i)\$\(\s*(cat|id|whoami|uname|wget|curl|nc|bash|sh|rm|python)\b`, "$() 命令替换", "high", TAll, false},
	{"CMDI-004", "cmdi", `\x60[^\x60]{0,150}?(cat|id|whoami|uname|wget|curl|nc|bash|sh)\b`, "反引号命令替换", "high", TAll, false},
	{"CMDI-005", "cmdi", `(?i)\b(rm\s+-rf\s+/|rm\s+-rf\s+~|mkfs|dd\s+if=|:\(\)\{.*;\}:)`, "破坏性命令（rm -rf 等）", "high", TAll, false},
	{"CMDI-006", "cmdi", `(?i)/bin/(ba|z|da)?sh\b|/usr/bin/(env|python|perl)`, "Shell 绝对路径执行", "medium", TAll, false},
	{"CMDI-007", "cmdi", `(?i)\bnc\s+(-e|-c)\b|\bbash\s+-i\b[^;]{0,60}(&|>)|\bpowershell\b[^\n]{0,60}-(enc|e|w)\b|certutil\s+-urlcache|bitsadmin\s+/transfer|mshta\s+http`, "反弹 Shell/下载执行", "high", TAll, false},

	// ===== 路径穿越 =====
	{"TRAV-001", "traversal", `(\.\./|\.\.\\){2,}`, "目录穿越（../ 序列）", "high", TAll, false},
	{"TRAV-002", "traversal", `(?i)/etc/(passwd|shadow|hosts|group|fstab|sudoers|issue)\b`, "Linux 系统敏感文件读取", "high", TAll, false},
	{"TRAV-003", "traversal", `(?i)(win\.ini|boot\.ini|windows[/\\]system32|system32[/\\]config)`, "Windows 系统文件探测", "medium", TAll, false},
	{"TRAV-004", "traversal", `(?i)/proc/self/(environ|cmdline|maps|status)`, "/proc/self 信息泄露", "high", TAll, false},
	{"TRAV-005", "traversal", `(?i)(%c0%ae|\.\.%(2f|2e|5c))`, "编码绕过型穿越", "medium", TAll, true},

	// ===== 文件包含 =====
	{"INCL-001", "fileinc", `(?i)(php|data|expect|zip|phar|compress\.zlib|input|dict|ftp|gopher)://`, "PHP/伪协议文件包含", "high", TAll, false},
	{"INCL-002", "fileinc", `(?i)php://filter`, "php://filter 源码读取", "high", TAll, false},

	// ===== WebShell 上传（检测请求体） =====
	{"SHELL-001", "webshell", `<\?php|<\?=|<%[@!]|<script[^>]{0,120}?language\s*=\s*['"]?vbscript`, "脚本语言标签（PHP/ASP）", "high", TBody, false},
	{"SHELL-002", "webshell", `(?i)(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|urldecode|chunk_split|hex2bin)`, "加密 WebShell（eval+解码）", "high", TBody, false},
	{"SHELL-003", "webshell", `(?i)(system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec|assert)\s*\(\s*\$_(get|post|request|cookie|server)`, "命令执行型 WebShell", "high", TBody, false},
	{"SHELL-004", "webshell", `(?i)\b(c99shell|r57shell|wso|filesman|b374k|phpspy|cmdshell|backdoor|webshell|webr00t|alfa-shell)\b`, "已知 WebShell 家族特征", "high", TBody, false},
	{"SHELL-005", "webshell", `(?i)preg_replace\s*\(.{0,120}?/[a-z]*e['"]\s*,`, "preg_replace /e 修饰符执行", "high", TBody, false},
	{"SHELL-006", "webshell", `(?i)(move_uploaded_file|file_put_contents)\s*\(.{0,120}\$_(get|post|request)`, "上传落盘型 WebShell", "high", TBody, false},

	// ===== 扫描器识别（User-Agent） =====
	{"SCAN-001", "scanner", `(?i)\b(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|dirb|wfuzz|ffuf|gobuster|hydra|metasploit|acunetix|nessus|arachni|w3af|whatweb|openvas|qualys|nuclei|burpsuite|feroxbuster|hakrawler|crawlergo|xray|awvs|nsfocus|havij|jaeles)\b`, "安全扫描器 User-Agent", "high", TUA, false},
	{"SCAN-002", "scanner", `(?i)\b(libwww-perl|python-urllib|go-http-client|java/1\.|scrapy|curl/|wget)\b[^\n]{0,200}(select|union|insert|drop\s+table|%27|or\s+1=1)`, "脚本 UA + 注入载荷组合", "medium", THeaders, false},

	// ===== 敏感文件访问（路径） =====
	{"SENS-001", "sensitive", `(?i)^/\.env($|[?./])`, ".env 配置文件访问", "high", TPath, false},
	{"SENS-002", "sensitive", `(?i)/\.git($|/)|/\.svn($|/)|/\.hg($|/)`, "版本控制目录访问", "high", TPath, false},
	{"SENS-003", "sensitive", `(?i)/\.ds_store$|/\.htaccess$|/\.htpasswd$`, "服务器敏感配置文件", "medium", TPath, false},
	{"SENS-004", "sensitive", `(?i)(id_rsa|id_dsa|id_ed25519|\.ssh/|\.aws/credentials|\.aws/config|\.gnupg/)`, "私钥/凭据文件访问", "high", TPath, false},
	{"SENS-005", "sensitive", `(?i)\.(sql|dump|mdb|bak|old|orig|save|swp)(\?|$)`, "备份/数据库归档访问", "medium", TPath, false},
	{"SENS-006", "sensitive", `(?i)phpinfo(\.php)?($|[?/])`, "phpinfo 探测", "medium", TPath, false},
	{"SENS-007", "sensitive", `(?i)(wp-config\.php[~.]|web\.config\.bak|\.bash_history|\.mysql_history|\.git-credentials)`, "应用备份/历史文件", "medium", TPath, false},
	{"SENS-008", "sensitive", `(?i)^/(phpmyadmin|pma|mysql)(/|\.(php|asp|aspx|jsp))?$`, "常见管理入口探测", "low", TPath, false},

	// ===== XXE 注入（请求体） =====
	{"XXE-001", "xxe", `(?is)<!doctype\b[^>]{0,300}?<!entity`, "XXE 实体定义注入", "high", TBody, false},
	{"XXE-002", "xxe", `(?is)<!entity[^>]{0,200}?(system|public)\b`, "XXE 外部实体引用", "high", TBody, false},

	// ===== 反序列化 =====
	{"DESER-001", "deser", `\brO0AB\b`, "Java 序列化数据（rO0AB）", "high", TAll, false},
	{"DESER-002", "deser", `(?i)\bO:\d+:"[^"]{1,60}"`, "PHP 序列化对象注入", "medium", TAll, false},
	{"DESER-003", "deser", `(?i)(ysoserial|commons-collections|__destruct|__wakeup|__gadget|invokertransformer)`, "反序列化利用链特征", "high", TAll, false},

	// ===== SSRF 防护 =====
	{"SSRF-001", "ssrf", `169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|metadata\.azure\.com`, "云元数据接口探测", "high", TAll, false},
	{"SSRF-002", "ssrf", `(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])`, "内网回环地址出现在参数中", "medium", TQuery, false},

	// ===== CRLF 注入（仅原始串匹配） =====
	{"CRLF-001", "crlf", `(?i)(%0d%0a|%0d|%0a|\r\n|\r|\n)`, "CRLF 换行注入（响应拆分）", "high", TPath | TQuery, true},

	// ===== 协议异常 / 请求走私（OWASP CRS 协议层） =====
	{"PROTO-001", "protocol", `(?im)^content-length:\s*[^0-9\r\n]`, "Content-Length 非数字（CRS 920160）", "medium", THeaders, false},
	{"PROTO-002", "protocol", `(?i)(transfer-encoding\s*:[^\r\n]*\r?\n[^\r\n]*content-length\s*:|content-length\s*:[^\r\n]*(\r?\n|,)[^\r\n]*transfer-encoding\s*:)`, "同时存在 Transfer-Encoding 与 Content-Length（请求走私）", "high", THeaders, false},
	{"PROTO-003", "protocol", `(?im)^(transfer-encoding|content-length|host)\s*:\s*$`, "关键请求头为空", "medium", THeaders, false},
	{"PROTO-004", "protocol", `(?i)^(trailer|te|forwarded|via|origin|upgrade)\s*:\s*$`, "可疑请求头为空值", "low", THeaders, false},
	{"PROTO-005", "protocol", "\x00", "请求含 NUL 空字节（协议污染）", "high", TAll, false},

	// ===== 文件上传限制（1Panel 文件上传限制 / 扩展名黑名单） =====
	{"UPLOAD-001", "upload", `(?i)filename=["'][^"']+\.(php\d*|phtml|phar|asp|aspx|ashx|asmx|jsp|jspx|cgi|pl|py|sh|exe|bat|cmd|com)["']`, "上传危险脚本/可执行扩展名", "high", TBody, false},
	{"UPLOAD-002", "upload", `(?i)filename=["'][^"']+\.(env|ini|htaccess|htpasswd|sql|bak|old|log)["']`, "上传敏感配置/备份扩展名", "medium", TBody, false},

	// ===== LDAP 注入（OWASP CRS LDAP 检测） =====
	{"LDAP-001", "ldap", `(?i)\b(ldap[s]?://|ldapsearch\b)`, "LDAP URL/工具探测", "medium", TAll, false},
	{"LDAP-002", "ldap", `(?i)([(\s]\*[)\s]\s*\([&|]\s*\(|\*\)\s*\(\s*[&|]|\(&|\(\s*uid\s*=\s*\*)`, "LDAP 过滤器注入（通配/布尔拼接）", "medium", TQuery | TBody, false},
	{"LDAP-003", "ldap", `(?i)(%2a%29%28|%2a%28%7c%26|%29%28%7c)`, "LDAP 注入编码绕过", "medium", TAll, false},

	// ===== SQL 注入扩充（OWASP CRS 深度覆盖） =====
	{"SQLI-013", "sqli", `(?i)\binformation_schema[\s.]+(tables|columns|schemata|routines)\b`, "数据库元数据表枚举", "high", TAll, false},
	{"SQLI-014", "sqli", `(?i)\bcase\s+when[\s(]+[^)]{0,80}?\bthen\b`, "CASE WHEN 布尔盲注", "medium", TAll, false},
	{"SQLI-015", "sqli", `(?i)(if|iif)\s*\(\s*\w+\s*[=<>]`, "IF 函数条件注入", "medium", TAll, false},
	{"SQLI-016", "sqli", `(?i)\b(unhex|hex|concat|concat_ws|group_concat|char)\s*\(`, "字符串拼接/编码函数滥用", "low", TAll, false},

	// ===== XSS 扩充（OWASP CRS 深度覆盖） =====
	{"XSS-011", "xss", `(?i)</script`, "闭合 script 标签注入", "high", TAll, false},
	{"XSS-012", "xss", `(?i)url\s*\(\s*(java)?script\s*:`, "CSS url(javascript:) 注入", "high", TAll, false},
	{"XSS-013", "xss", `(?i)(alert|prompt|confirm)\s*\(\s*(document\.|location\.)?`, "弹窗函数变体", "low", TAll, false},

	// ===== 命令注入扩充（IFS/编码绕过） =====
	{"CMDI-008", "cmdi", `(?i)\$(IFS|BASH_ENV|ENV)\b|\{IFS\}|\$\{IFS\}`, "IFS 字段分隔符命令绕过", "medium", TAll, false},

	// ===== 敏感文件扩充 =====
	{"SENS-009", "sensitive", `(?i)(composer\.json|package(-lock)?\.json|yarn\.lock|pom\.xml|\.env\.(local|prod|example)|Dockerfile)$`, "源码/包清单/环境文件泄漏", "medium", TPath, false},
}

var groupMeta = []struct{ Key, Name, Desc string }{
	{"sqli", "SQL 注入", "UNION/布尔/延时/报错注入、堆叠查询与 MySQL 注释绕过"},
	{"xss", "XSS 跨站脚本", "脚本标签、事件属性、伪协议、敏感 DOM 访问与弹窗函数"},
	{"cmdi", "命令注入", "OS 命令拼接、命令替换、反弹 Shell 与破坏性命令"},
	{"traversal", "路径穿越", "../ 穿越、系统敏感文件读取与编码绕过"},
	{"fileinc", "文件包含", "PHP 伪协议、远程/本地文件包含"},
	{"webshell", "WebShell 上传", "脚本标签、一句话木马与已知 Shell 家族（检测请求体）"},
	{"scanner", "扫描器识别", "sqlmap/nikto/nuclei 等扫描工具 User-Agent 特征"},
	{"sensitive", "敏感文件访问", ".env/.git/私钥/备份文件/管理入口探测"},
	{"xxe", "XXE 注入", "XML 外部实体注入（检测请求体）"},
	{"deser", "反序列化", "Java/PHP 反序列化利用链特征"},
	{"ssrf", "SSRF 防护", "云元数据接口与内网回环地址探测"},
	{"crlf", "CRLF 注入", "响应拆分/头注入（%0d%0a）"},
	{"protocol", "协议异常（CRS）", "Content-Length/请求走私/关键头为空值"},
	{"upload", "文件上传限制", "危险脚本/敏感扩展名上传拦截"},
	{"ldap", "LDAP 注入", "LDAP 过滤器与编码绕过注入"},
}

// ---------- 编译与检测 ----------

// BuildRuleSet 按配置编译规则集；自定义规则正则有误时返回首个错误（内置规则不受影响）
func BuildRuleSet(cfg *Config, stats *Stats) (*RuleSet, error) {
	rs := &RuleSet{stats: stats, groupEnable: cfg.RuleGroups}
	byGroup := map[string]*RuleGroup{}
	for _, gm := range groupMeta {
		g := &RuleGroup{Key: gm.Key, Name: gm.Name, Desc: gm.Desc}
		byGroup[gm.Key] = g
		rs.Groups = append(rs.Groups, g)
	}
	for _, d := range builtinRuleDefs {
		re, err := regexp.Compile(d.pattern)
		if err != nil {
			continue // 内置规则理论上不会出错；防御性跳过
		}
		if g := byGroup[d.group]; g != nil {
			g.Rules = append(g.Rules, &Rule{
				ID: d.id, Group: d.group, Desc: d.desc, Severity: d.severity,
				Target: d.target, RawOnly: d.rawOnly, re: re,
			})
		}
	}
	var firstErr error
	for _, cr := range cfg.CustomRules {
		if cr.Regex == "" {
			continue
		}
		re, err := regexp.Compile(cr.Regex)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("自定义规则 %q 正则无效: %v", cr.Name, err)
			}
			continue
		}
		rs.custom = append(rs.custom, &compiledCustom{def: cr, re: re})
	}
	return rs, firstErr
}

// Hit 规则检测结果
type Hit struct {
	Rule    *Rule
	Snippet string
	Field   string
	Custom  *CustomRule
}

// Inspect 对请求数据执行全量规则匹配，返回首个命中（内置规则优先于自定义规则）
func (rs *RuleSet) Inspect(d *ReqData) *Hit {
	for _, g := range rs.Groups {
		if !rs.groupEnabled(g.Key) {
			continue
		}
		for _, r := range g.Rules {
			if h := rs.matchRule(r, d); h != nil {
				return h
			}
		}
	}
	for _, c := range rs.custom {
		if !c.def.Enabled {
			continue
		}
		t := parseTarget(c.def.Target)
		for _, f := range d.fieldsFor(t) {
			for _, v := range f.vars {
				if c.re.MatchString(v) {
					rs.stats.ruleHit(c.def.ID)
					return &Hit{Snippet: truncate(c.re.FindString(v), 120), Field: f.name, Custom: &c.def}
				}
			}
		}
	}
	return nil
}

func (rs *RuleSet) groupEnabled(key string) bool {
	if rs.groupEnable == nil {
		return true
	}
	return rs.groupEnable[key]
}

func (rs *RuleSet) matchRule(r *Rule, d *ReqData) *Hit {
	for _, f := range d.fieldsFor(r.Target) {
		for i, v := range f.vars {
			if r.RawOnly && i > 0 {
				continue
			}
			if r.re.MatchString(v) {
				rs.stats.ruleHit(r.ID)
				return &Hit{Rule: r, Snippet: truncate(r.re.FindString(v), 120), Field: f.name}
			}
		}
	}
	return nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
