// SPDX-License-Identifier: Apache-2.0
// 深度解码与归一化：模拟雷池语义分析引擎的「解码 → 归一化 → 检测」前置阶段。
// 对同一输入生成多个检测变体（原始 / 多层解码 / SQL 归一化），
// 让 union/**/select、%3Cscript%3E、&#x6a;avascript 之类的混淆全部现形。

package main

import (
	"html"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	reSQLComment = regexp.MustCompile(`(?s)/\*.*?\*/`) // /* ... */ 内联注释（union/**/select 绕过）
	reSQLLineCmt = regexp.MustCompile(`(--|#)[^\s]*`)  // 行内注释
	reSpaces     = regexp.MustCompile(`\s+`)
	reUniEscape  = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
)

// variants 生成 s 的检测变体序列：
//
//	[原始, 解码1, 解码1+SQL归一化, 解码2, ...] （去重，最多 3 层解码）
func variants(s string) []string {
	if s == "" {
		return nil
	}
	out := []string{s}
	seen := map[string]bool{s: true}
	cur := s
	for i := 0; i < 3; i++ {
		next := cur
		if u, err := url.QueryUnescape(next); err == nil && u != next {
			next = u
		}
		if h := html.UnescapeString(next); h != next {
			next = h
		}
		if u := unescapeUnicode(next); u != next {
			next = u
		}
		if next == cur {
			break
		}
		for _, v := range []string{next, sqlNorm(next)} {
			if v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
		cur = next
	}
	// 原始串的归一化变体也加入（注释剥离对原始串同样有效）
	if n := sqlNorm(s); n != "" && !seen[n] {
		out = append(out, n)
	}
	return out
}

// sqlNorm SQL 归一化：剥离注释、压缩空白、去重复引号间隔，
// 使 "union/**/select" 与 "union  select" 归一为同一形态。
func sqlNorm(s string) string {
	if !strings.ContainsAny(s, "/*-#") {
		return s
	}
	out := reSQLComment.ReplaceAllString(s, " ")
	out = reSQLLineCmt.ReplaceAllString(out, " ")
	out = reSpaces.ReplaceAllString(out, " ")
	return strings.TrimSpace(out)
}

// unescapeUnicode 解码 \uXXXX 转义（JSON/JS 场景常见）
func unescapeUnicode(s string) string {
	if !strings.Contains(s, `\u`) {
		return s
	}
	return reUniEscape.ReplaceAllStringFunc(s, func(m string) string {
		var r rune
		if _, err := fmtSscanHex(m[2:], &r); err != nil {
			return m
		}
		return string(r)
	})
}

// fmtSscanHex 小工具：解析 4 位十六进制为 rune
func fmtSscanHex(s string, r *rune) (int, error) {
	if len(s) != 4 {
		return 0, errBadHex
	}
	var v rune
	for i := 0; i < 4; i++ {
		c := rune(s[i])
		switch {
		case c >= '0' && c <= '9':
			v = v*16 + (c - '0')
		case c >= 'a' && c <= 'f':
			v = v*16 + (c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v = v*16 + (c - 'A' + 10)
		default:
			return 0, errBadHex
		}
	}
	if !utf8.ValidRune(v) {
		return 0, errBadHex
	}
	*r = v
	return 1, nil
}

type hexErr struct{}

func (hexErr) Error() string { return "bad hex" }

var errBadHex = hexErr{}

// lowerBytes 返回小写副本（快速路径特征扫描用）
func lowerBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}
