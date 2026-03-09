package api

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// engineHTTP 测绘引擎专用 HTTP 客户端（跳过证书验证，30秒超时）
var engineHTTP = &http.Client{
	Timeout:   30 * time.Second,
	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
}

// EngineResult 统一的测绘引擎子域名查询结果
type EngineResult struct {
	Engine     string   // 引擎名称
	Subdomains []string // 发现的子域名列表
	Err        error    // 查询错误
}

// ═══════════════════ Fofa ═══════════════════
// API: https://fofa.info/api/v1/search/all
// 参数: email, key, qbase64(base64编码的查询语句), size, fields

func DiscoverFromFofa(domain, email, key string) ([]string, error) {
	key = strings.TrimSpace(key)
	email = strings.TrimSpace(email)
	if key == "" {
		return nil, fmt.Errorf("Fofa Key 未配置")
	}
	query := fmt.Sprintf(`domain="%s"`, domain)
	qb64 := base64.StdEncoding.EncodeToString([]byte(query))
	// 如果提供了邮箱则带上（部分 Fofa 账户需要）
	apiURL := fmt.Sprintf("https://fofa.info/api/v1/search/all?key=%s&qbase64=%s&size=500&fields=host", key, qb64)
	if email != "" {
		apiURL = fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=500&fields=host", email, key, qb64)
	}
	url := apiURL

	resp, err := engineHTTP.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Fofa 请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// 先解析外层（error + errmsg + results 用 RawMessage 接收）
	var outer struct {
		Error   bool            `json:"error"`
		ErrMsg  string          `json:"errmsg"`
		Results json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(body, &outer); err != nil {
		return nil, fmt.Errorf("Fofa 解析失败: %v\n原始响应: %s", err, string(body[:min(200, len(body))]))
	}
	if outer.Error {
		return nil, fmt.Errorf("Fofa 错误: %s", outer.ErrMsg)
	}

	// Results 可能是 [][]string 或 []string，逐一尝试
	var hosts []string
	var rows2D [][]string
	if err := json.Unmarshal(outer.Results, &rows2D); err == nil {
		// 二维数组：[["www.baidu.com"], ...]
		for _, row := range rows2D {
			if len(row) > 0 {
				hosts = append(hosts, row[0])
			}
		}
	} else {
		// 一维数组：["www.baidu.com", ...]
		var rows1D []string
		if err2 := json.Unmarshal(outer.Results, &rows1D); err2 == nil {
			hosts = rows1D
		}
	}

	seen := make(map[string]bool)
	var subs []string
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		host = strings.TrimPrefix(host, "https://")
		host = strings.TrimPrefix(host, "http://")
		host = strings.SplitN(host, ":", 2)[0]
		host = strings.SplitN(host, "/", 2)[0]
		host = strings.ToLower(host)
		if host != "" && strings.Contains(host, ".") && !seen[host] {
			seen[host] = true
			subs = append(subs, host)
		}
	}
	return subs, nil
}

// ═══════════════════ Shodan ═══════════════════
// API: https://api.shodan.io/dns/domain/{domain}?key=...

func DiscoverFromShodan(domain, key string) ([]string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("Shodan Key 未配置")
	}
	url := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, key)

	resp, err := engineHTTP.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Shodan 请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Domain     string   `json:"domain"`
		Subdomains []string `json:"subdomains"`
		Error      string   `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("Shodan 解析失败: %v", err)
	}
	if result.Error != "" {
		return nil, fmt.Errorf("Shodan 错误: %s", result.Error)
	}

	var subs []string
	for _, sub := range result.Subdomains {
		full := sub + "." + domain
		subs = append(subs, strings.ToLower(full))
	}
	return subs, nil
}

// ═══════════════════ Hunter (鹰图) ═══════════════════
// API: https://hunter.qianxin.com/openApi/search
// 参数: api-key, search(base64编码), page, page_size

func DiscoverFromHunter(domain, key string) ([]string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("Hunter Key 未配置")
	}
	query := fmt.Sprintf(`domain.suffix="%s"`, domain)
	qb64 := base64.StdEncoding.EncodeToString([]byte(query))
	url := fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=1&page_size=100&is_web=3", key, qb64)

	resp, err := engineHTTP.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Hunter 请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Code int `json:"code"`
		Data struct {
			Arr []struct {
				Domain string `json:"domain"`
			} `json:"arr"`
		} `json:"data"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("Hunter 解析失败: %v", err)
	}
	if result.Code != 200 {
		return nil, fmt.Errorf("Hunter 错误: %s", result.Message)
	}

	seen := make(map[string]bool)
	var subs []string
	for _, item := range result.Data.Arr {
		d := strings.ToLower(strings.TrimSpace(item.Domain))
		if d != "" && !seen[d] {
			seen[d] = true
			subs = append(subs, d)
		}
	}
	return subs, nil
}

// ═══════════════════ Quake (360) ═══════════════════
// API: https://quake.360.net/api/v3/search/quake_service
// Method: POST, Header: X-QuakeToken

func DiscoverFromQuake(domain, key string) ([]string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("Quake Key 未配置")
	}

	payload := fmt.Sprintf(`{"query":"domain:\"%s\"","size":500,"start":0,"include":["service.http.host"]}`, domain)
	req, err := http.NewRequest("POST", "https://quake.360.net/api/v3/search/quake_service", strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-QuakeToken", key)
	req.Header.Set("Content-Type", "application/json")

	resp, err := engineHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Quake 请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    []struct {
			Service struct {
				HTTP struct {
					Host string `json:"host"`
				} `json:"http"`
			} `json:"service"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("Quake 解析失败: %v", err)
	}
	if result.Code != 0 {
		return nil, fmt.Errorf("Quake 错误: %s", result.Message)
	}

	seen := make(map[string]bool)
	var subs []string
	for _, item := range result.Data {
		host := strings.ToLower(strings.TrimSpace(item.Service.HTTP.Host))
		if host != "" && strings.Contains(host, ".") && !seen[host] {
			seen[host] = true
			subs = append(subs, host)
		}
	}
	return subs, nil
}

// ═══════════════════ ZoomEye ═══════════════════
// API: https://api.zoomeye.org/domain/search?q=...&type=1
// Header: API-KEY

func DiscoverFromZoomEye(domain, key string) ([]string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("ZoomEye Key 未配置")
	}
	url := fmt.Sprintf("https://api.zoomeye.org/domain/search?q=%s&type=1&page=1", domain)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("API-KEY", key)

	resp, err := engineHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ZoomEye 请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Status int    `json:"status"`
		Msg    string `json:"msg"`
		List   []struct {
			Name string `json:"name"`
		} `json:"list"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("ZoomEye 解析失败: %v", err)
	}
	if result.Status != 200 && result.Status != 0 {
		return nil, fmt.Errorf("ZoomEye 错误 [%d]: %s", result.Status, result.Msg)
	}

	seen := make(map[string]bool)
	var subs []string
	for _, item := range result.List {
		d := strings.ToLower(strings.TrimSpace(item.Name))
		if d != "" && !seen[d] {
			seen[d] = true
			subs = append(subs, d)
		}
	}
	return subs, nil
}
