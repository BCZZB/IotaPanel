// SPDX-License-Identifier: Apache-2.0
// 精简 FastCGI 客户端（纯标准库）：与 php-fpm 通信所需的 RESPONDER 角色子集。
// 每个请求独占一条连接（requestId 恒为 1），避开多路复用的复杂度与竞态。
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

const (
	fcgiVersion = 1

	fcgiBeginRequest = 1
	fcgiEndRequest   = 3
	fcgiParams       = 4
	fcgiStdin        = 5
	fcgiStdout       = 6
	fcgiStderr       = 7

	fcgiResponder = 1 // PHP 处理 HTTP 请求的标准角色

	fcgiMaxContent = 65535 // 单条 record 内容上限（协议规定）
)

// fcgiHeader 8 字节记录头。
type fcgiHeader struct {
	version     byte
	recType     byte
	requestID   uint16
	contentLen  uint16
	paddingLen  byte
}

func writeRecord(w io.Writer, recType byte, requestID uint16, content []byte) error {
	total := len(content)
	for sent := 0; sent < total || total == 0; {
		chunk := content[sent:]
		if len(chunk) > fcgiMaxContent {
			chunk = chunk[:fcgiMaxContent]
		}
		pad := (8 - len(chunk)%8) % 8
		hdr := [8]byte{fcgiVersion, recType,
			byte(requestID >> 8), byte(requestID),
			byte(len(chunk) >> 8), byte(len(chunk)), byte(pad), 0}
		if _, err := w.Write(hdr[:]); err != nil {
			return err
		}
		if len(chunk) > 0 {
			if _, err := w.Write(chunk); err != nil {
				return err
			}
		}
		if pad > 0 {
			if _, err := w.Write(make([]byte, pad)); err != nil {
				return err
			}
		}
		sent += len(chunk)
		if total == 0 {
			break // 空记录（STDIN 结束标记）只发一次
		}
	}
	return nil
}

// fcgiEncodePairs 编码 FCGI_PARAMS 的 name-value 对（1/4 字节变长前缀）。
func fcgiEncodePairs(pairs [][2]string) []byte {
	var buf bytes.Buffer
	for _, kv := range pairs {
		writeLen := func(n int) {
			switch {
			case n < 128:
				buf.WriteByte(byte(n))
			case n < 1<<24:
				buf.WriteByte(byte(n>>24) | 0x80)
				buf.WriteByte(byte(n >> 16))
				buf.WriteByte(byte(n >> 8))
				buf.WriteByte(byte(n))
			}
		}
		writeLen(len(kv[0]))
		writeLen(len(kv[1]))
		buf.WriteString(kv[0])
		buf.WriteString(kv[1])
	}
	return buf.Bytes()
}

// FCGIError 带 appStatus 的执行结果错误。
type FCGIError struct{ Msg string }

func (e *FCGIError) Error() string { return e.Msg }

// fcgiResponse CGI 响应：stdout（含头+体）、stderr（PHP 日志）。
type fcgiResponse struct {
	stdout bytes.Buffer
	stderr bytes.Buffer
}

// fcgiDo 在一条连接上完成单个 RESPONDER 请求。
// stdout 逐块回调（onChunk 为 nil 时缓存到内存），实现大响应流式转发。
func fcgiDo(conn net.Conn, params [][2]string, body io.Reader, onChunk func([]byte)) (*fcgiResponse, error) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	// 1. BEGIN_REQUEST (RESPONDER, 保持连接)
	begin := make([]byte, 8)
	binary.BigEndian.PutUint16(begin[0:2], fcgiResponder)
	begin[2] = 1 // FCGI_KEEP_CONN
	if err := writeRecord(conn, fcgiBeginRequest, 1, begin); err != nil {
		return nil, err
	}
	// 2. PARAMS（可能多段）
	if b := fcgiEncodePairs(params); len(b) > 0 {
		if err := writeRecord(conn, fcgiParams, 1, b); err != nil {
			return nil, err
		}
	}
	if err := writeRecord(conn, fcgiParams, 1, nil); err != nil { // 结束标记
		return nil, err
	}
	// 3. STDIN（请求体，可能多段）
	buf := make([]byte, 32*1024)
	if body != nil {
		for {
			n, err := body.Read(buf)
			if n > 0 {
				if err := writeRecord(conn, fcgiStdin, 1, buf[:n]); err != nil {
					return nil, err
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
		}
	}
	if err := writeRecord(conn, fcgiStdin, 1, nil); err != nil { // 结束标记
		return nil, err
	}

	// 4. 读响应直到 END_REQUEST
	resp := &fcgiResponse{}
	header := make([]byte, 8)
	endSeen := false
	for !endSeen {
		if _, err := io.ReadFull(conn, header); err != nil {
			return nil, fmt.Errorf("fastcgi 读响应: %w", err)
		}
		contentLen := int(header[4])<<8 | int(header[5])
		paddingLen := int(header[6])
		content := make([]byte, contentLen)
		if contentLen > 0 {
			if _, err := io.ReadFull(conn, content); err != nil {
				return nil, err
			}
		}
		if paddingLen > 0 {
			if _, err := io.CopyN(io.Discard, conn, int64(paddingLen)); err != nil {
				return nil, err
			}
		}
		switch header[1] {
		case fcgiStdout:
			if onChunk != nil {
				onChunk(content)
			} else if contentLen > 0 {
				resp.stdout.Write(content)
			}
		case fcgiStderr:
			if contentLen > 0 {
				resp.stderr.Write(content)
			}
		case fcgiEndRequest:
			endSeen = true
		}
	}
	return resp, nil
}

// connPool 每个站点的连接池（FCGI_KEEP_CONN 复用连接，减少握手开销）。
type connPool struct {
	mu    sync.Mutex
	conns []net.Conn
	addr  func() (string, bool) // 返回 dial 地址（socket 路径）；false=不可用
}

func newConnPool(addrFn func() (string, bool)) *connPool {
	return &connPool{addr: addrFn}
}

func (p *connPool) get() (net.Conn, error) {
	p.mu.Lock()
	if n := len(p.conns); n > 0 {
		c := p.conns[n-1]
		p.conns = p.conns[:n-1]
		p.mu.Unlock()
		return c, nil
	}
	p.mu.Unlock()
	a, ok := p.addr()
	if !ok {
		return nil, errors.New("php 运行时未就绪")
	}
	return net.Dial("unix", a)
}

func (p *connPool) put(c net.Conn, broken bool) {
	if broken {
		c.Close()
		return
	}
	p.mu.Lock()
	if len(p.conns) < 4 { // 池上限 4
		p.conns = append(p.conns, c)
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	c.Close()
}

func (p *connPool) closeAll() {
	p.mu.Lock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
	p.mu.Unlock()
}
