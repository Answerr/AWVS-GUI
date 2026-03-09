package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 默认扫描配置 Profile ID（来自 Acunetix 内置）
const (
	ProfileFullScan      = "11111111-1111-1111-1111-111111111111"
	ProfileHighRisk      = "11111111-1111-1111-1111-111111111112"
	ProfileSQLInjection  = "11111111-1111-1111-1111-111111111113"
	ProfileWeakPasswords = "11111111-1111-1111-1111-111111111115"
	ProfileXSS           = "11111111-1111-1111-1111-111111111116"
	ProfileCrawlOnly     = "11111111-1111-1111-1111-111111111117"
)

var scanProfileMap = map[string]string{
	"完整扫描":  ProfileFullScan,
	"高危漏洞":  ProfileHighRisk,
	"SQL注入": ProfileSQLInjection,
	"弱口令检测": ProfileWeakPasswords,
	"XSS漏洞": ProfileXSS,
	"仅爬取":   ProfileCrawlOnly,
}

var profileOrder = []string{"完整扫描", "高危漏洞", "SQL注入", "弱口令检测", "XSS漏洞", "仅爬取"}

// GetProfileNames 返回有序的扫描配置名称列表
func GetProfileNames() []string { return profileOrder }

// GetProfileID 根据名称返回配置 ID
func GetProfileID(name string) string {
	if id, ok := scanProfileMap[name]; ok {
		return id
	}
	return ProfileFullScan
}


// ExtractApexDomainPublic 导出版本（供 UI 层调用）
func ExtractApexDomainPublic(rawURL string) string { return extractApexDomain(rawURL) }

// extractApexDomain 从 URL 中提取顶级域名（去掉 www. 前缀和路径）
func extractApexDomain(rawURL string) string {
	host := strings.TrimPrefix(rawURL, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.SplitN(host, "/", 2)[0] // 去掉路径
	host = strings.SplitN(host, ":", 2)[0] // 去掉端口
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimPrefix(host, "www.")
	return host
}

// ─────────────────────── 数据结构 ───────────────────────

// Target 扫描目标
type Target struct {
	TargetID     string `json:"target_id"`
	Address      string `json:"address"`
	Description  string `json:"description"`
	Type         string `json:"type"`
	Criticality  int    `json:"criticality"`
	LastScanDate string `json:"last_scan_date"`
}

type addTargetReq struct {
	Address     string `json:"address"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Criticality int    `json:"criticality"`
}

type targetListResp struct {
	Targets    []Target   `json:"targets"`
	Pagination pagination `json:"pagination"`
}

// ScanTargetInfo 扫描任务中的目标信息
type ScanTargetInfo struct {
	Address     string `json:"address"`
	Description string `json:"description"`
}

// SeverityCounts 各严重等级漏洞数量（来自 current_session）
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// ScanSession 扫描会话信息
type ScanSession struct {
	Status         string         `json:"status"`
	Progress       int            `json:"progress"`
	SeverityCounts SeverityCounts `json:"severity_counts"`
}

// Scan 扫描任务
type Scan struct {
	ScanID      string         `json:"scan_id"`
	TargetID    string         `json:"target_id"`
	Target      ScanTargetInfo `json:"target"`
	ProfileID   string         `json:"profile_id"`
	ProfileName string         `json:"profile_name"`
	Session     ScanSession    `json:"current_session"`
}

type scanListResp struct {
	Scans      []Scan     `json:"scans"`
	Pagination pagination `json:"pagination"`
}

type startScanReq struct {
	TargetID  string   `json:"target_id"`
	ProfileID string   `json:"profile_id"`
	Schedule  schedule `json:"schedule"`
}

type schedule struct {
	Disable       bool    `json:"disable"`
	StartDate     *string `json:"start_date"`
	TimeSensitive bool    `json:"time_sensitive"`
}

// Vulnerability 漏洞信息
type Vulnerability struct {
	VulnID     string `json:"vuln_id"`
	Status     string `json:"status"`
	AffectsURL string `json:"affects_url"`
	Severity   int    `json:"severity"`
	VtName     string `json:"vt_name"`
	TargetID   string `json:"target_id"`
	LastSeen   string `json:"last_seen"`
}

type vulnListResp struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Pagination      pagination      `json:"pagination"`
}

type pagination struct {
	Offset     int `json:"offset"`
	Limit      int `json:"limit"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}

// ─────────────────────── 客户端 ───────────────────────

// Client AWVS API 客户端
type Client struct {
	BaseURL string
	APIKey  string
	http    *http.Client
}

// NewClient 创建不带代理的 AWVS API 客户端
func NewClient(baseURL, apiKey string) *Client {
	return NewClientWithProxy(baseURL, apiKey, "", "")
}

// NewClientWithProxy 创建支持 HTTP 代理的 AWVS API 客户端
func NewClientWithProxy(baseURL, apiKey, proxyHost, proxyPort string) *Client {
	var transport *http.Transport

	if proxyHost != "" && proxyPort != "" {
		proxyRawURL := fmt.Sprintf("http://%s:%s", proxyHost, proxyPort)
		if proxyURL, err := url.Parse(proxyRawURL); err == nil {
			transport = &http.Transport{
				Proxy:           http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			}
		}
	}
	if transport == nil {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}

	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		http: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}
}

// doRequest 执行 HTTP 请求，返回响应对象、响应体字节、错误
func (c *Client) doRequest(method, path string, body interface{}) (*http.Response, []byte, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, bodyReader)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("X-Auth", c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, err
	}
	return resp, respBody, nil
}

// ─────────────────────── 分页工具 ───────────────────────

// pageURL 构造分页请求 URL
// cursor=0 时不附加 c= 参数（保持与 AWVS 原始接口兼容），
// cursor>0 时附加 c=cursor 跳过已取条目。
// extra 为附加查询参数（如 "s=severity:desc"），可为空字符串。
func pageURL(base string, limit, cursor int, extra string) string {
	url := fmt.Sprintf("%s?l=%d", base, limit)
	if cursor > 0 {
		url += fmt.Sprintf("&c=%d", cursor)
	}
	if extra != "" {
		url += "&" + extra
	}
	return url
}

// fetchAllPages 通用自动分页函数
// fn(limit, cursor) → (当前页数据, 总条数, 错误)
// 每次取 100 条，直到取完所有数据
func fetchAllPages[T any](fn func(limit, cursor int) ([]T, int, error)) ([]T, error) {
	const pageSize = 100
	var all []T
	cursor := 0
	for {
		items, total, err := fn(pageSize, cursor)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		cursor += len(items)
		// 已取完 或 本页未满（最后一页） 则停止
		if len(items) < pageSize || cursor >= total {
			break
		}
	}
	return all, nil
}

// ─────────────────────── API 方法 ───────────────────────

// TestConnection 测试 AWVS 连接可用性
func (c *Client) TestConnection() error {
	resp, _, err := c.doRequest("GET", "/api/v1/me", nil)
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	if resp.StatusCode == 401 {
		return fmt.Errorf("认证失败，请检查 API Key 是否正确")
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("连接异常，HTTP 状态码: %d", resp.StatusCode)
	}
	return nil
}

// GetTargets 获取所有扫描目标（自动分页，无上限）
func (c *Client) GetTargets() ([]Target, error) {
	return fetchAllPages(func(limit, cursor int) ([]Target, int, error) {
		path := pageURL("/api/v1/targets", limit, cursor, "")
		_, body, err := c.doRequest("GET", path, nil)
		if err != nil {
			return nil, 0, err
		}
		var resp targetListResp
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, 0, fmt.Errorf("解析响应失败: %v", err)
		}
		return resp.Targets, resp.Pagination.TotalCount, nil
	})
}

// AddTarget 添加扫描目标
func (c *Client) AddTarget(address, description string) (*Target, error) {
	req := addTargetReq{
		Address:     address,
		Description: description,
		Type:        "default",
		Criticality: 10,
	}
	resp, body, err := c.doRequest("POST", "/api/v1/targets", req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 201 {
		return nil, fmt.Errorf("添加目标失败 [HTTP %d]: %s", resp.StatusCode, string(body))
	}
	var target Target
	if err := json.Unmarshal(body, &target); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}
	return &target, nil
}

// DeleteTarget 删除扫描目标
func (c *Client) DeleteTarget(targetID string) error {
	resp, body, err := c.doRequest("DELETE", "/api/v1/targets/"+targetID, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != 204 {
		return fmt.Errorf("删除目标失败 [HTTP %d]: %s", resp.StatusCode, string(body))
	}
	return nil
}

// StartScan 对目标启动扫描，返回扫描 ID
func (c *Client) StartScan(targetID, profileID string) (string, error) {
	req := startScanReq{
		TargetID:  targetID,
		ProfileID: profileID,
		Schedule: schedule{
			Disable:       false,
			StartDate:     nil,
			TimeSensitive: false,
		},
	}
	resp, body, err := c.doRequest("POST", "/api/v1/scans", req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 201 {
		return "", fmt.Errorf("启动扫描失败 [HTTP %d]: %s", resp.StatusCode, string(body))
	}
	location := resp.Header.Get("Location")
	if location == "" {
		return "", nil
	}
	parts := strings.Split(location, "/")
	return parts[len(parts)-1], nil
}

// GetScans 获取所有扫描任务（自动分页，无上限）
func (c *Client) GetScans() ([]Scan, error) {
	return fetchAllPages(func(limit, cursor int) ([]Scan, int, error) {
		path := pageURL("/api/v1/scans", limit, cursor, "")
		_, body, err := c.doRequest("GET", path, nil)
		if err != nil {
			return nil, 0, err
		}
		var resp scanListResp
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, 0, fmt.Errorf("解析响应失败: %v", err)
		}
		return resp.Scans, resp.Pagination.TotalCount, nil
	})
}

// AbortScan 中止正在进行的扫描
func (c *Client) AbortScan(scanID string) error {
	_, _, err := c.doRequest("POST", "/api/v1/scans/"+scanID+"/abort", nil)
	return err
}

// DeleteScan 删除扫描记录
func (c *Client) DeleteScan(scanID string) error {
	_, _, err := c.doRequest("DELETE", "/api/v1/scans/"+scanID, nil)
	return err
}

// GetVulnerabilities 获取所有漏洞（自动分页，无上限，按严重程度降序）
func (c *Client) GetVulnerabilities() ([]Vulnerability, error) {
	return fetchAllPages(func(limit, cursor int) ([]Vulnerability, int, error) {
		path := pageURL("/api/v1/vulnerabilities", limit, cursor, "s=severity:desc")
		_, body, err := c.doRequest("GET", path, nil)
		if err != nil {
			return nil, 0, err
		}
		var resp vulnListResp
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, 0, fmt.Errorf("解析响应失败: %v", err)
		}
		return resp.Vulnerabilities, resp.Pagination.TotalCount, nil
	})
}

// VulnDetails 漏洞详细内容（描述/影响/修复建议）
type VulnDetails struct {
	Description    string `json:"description"`
	Impact         string `json:"impact"`
	Recommendation string `json:"recommendation"`
}

// VulnDetail 单个漏洞完整详情（含HTTP请求/响应、漏洞描述和修复建议）
type VulnDetail struct {
	VulnID          string      `json:"vuln_id"`
	VtID            string      `json:"vt_id"`
	VtName          string      `json:"vt_name"`
	AffectsURL      string      `json:"affects_url"`
	AffectsDetail   string      `json:"affects_detail"` // 攻击详情（特定发现描述）
	Severity        int         `json:"severity"`
	Status          string      `json:"status"`
	Request         string      `json:"-"` // HTTP 请求原文
	Response        string      `json:"-"` // HTTP 响应原文（AWVS API 可能不返回）
	Description     string      `json:"-"` // 顶层通用漏洞说明
	LongDescription string      `json:"-"` // 顶层详细漏洞说明
	Impact          string      `json:"-"` // 顶层漏洞影响
	Recommendation  string      `json:"-"` // 顶层修复建议
	Details         VulnDetails `json:"-"` // details 字段（具体发现描述 HTML）
}

// GetVulnerabilityDetail 获取单个漏洞的完整详情
// ★ 关键发现：AWVS API 字段名使用 空格 而非下划线（如 "vt name" 而非 "vt_name"）
//
//	且 description/impact/recommendation 是顶层字段，不在 details 对象内。
//	details 字段包含的是具体发现描述（如受影响的 URL 列表）。
//	response 字段在此 API 端点中不存在（AWVS web 界面从其他来源获取）。
func (c *Client) GetVulnerabilityDetail(vulnID string) (*VulnDetail, error) {
	_, body, err := c.doRequest("GET", "/api/v1/vulnerabilities/"+vulnID, nil)
	if err != nil {
		return nil, err
	}

	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(body, &rawMap); err != nil {
		return nil, fmt.Errorf("解析漏洞详情失败: %v", err)
	}

	// ── getString：兼容 AWVS 空格/下划线两种字段名风格 ──
	// 例如 getString("vt_name") 会同时尝试 "vt_name" 和 "vt name"
	getString := func(keys ...string) string {
		for _, k := range keys {
			// 尝试原始 key
			if v, ok := rawMap[k]; ok {
				if s := extractRawField(v); s != "" {
					return s
				}
			}
			// 尝试下划线→空格变体
			spaced := strings.ReplaceAll(k, "_", " ")
			if spaced != k {
				if v, ok := rawMap[spaced]; ok {
					if s := extractRawField(v); s != "" {
						return s
					}
				}
			}
		}
		return ""
	}
	getInt := func(key string) int {
		for _, k := range []string{key, strings.ReplaceAll(key, "_", " ")} {
			if v, ok := rawMap[k]; ok {
				var n int
				_ = json.Unmarshal(v, &n)
				if n != 0 {
					return n
				}
			}
		}
		return 0
	}

	detail := &VulnDetail{
		VulnID:        getString("vuln_id"),
		VtID:          getString("vt_id"),
		VtName:        getString("vt_name"),
		AffectsURL:    getString("affects_url"),
		AffectsDetail: getString("affects_detail"),
		Severity:      getInt("severity"),
		Status:        getString("status"),
		// HTTP 请求
		Request: getString("request", "http_request"),
		// HTTP 响应（此 API 端点通常不返回）
		Response: getString("response", "http_response"),
		// ★ 顶层字段（非 details 子对象）
		Description:     getString("description"),
		LongDescription: getString("long_description"),
		Impact:          getString("impact"),
		Recommendation:  getString("recommendation"),
	}

	// ── 解析 details 字段（具体发现描述，通常为 HTML）──
	for _, dk := range []string{"details"} {
		if v, ok := rawMap[dk]; ok && len(v) > 0 {
			if err := json.Unmarshal(v, &detail.Details); err != nil {
				var s string
				if err2 := json.Unmarshal(v, &s); err2 == nil && s != "" {
					if err3 := json.Unmarshal([]byte(s), &detail.Details); err3 != nil {
						detail.Details.Description = s
					}
				}
			}
		}
	}

	return detail, nil
}

// extractRawField 从 json.RawMessage 中提取字符串内容
// 兼容三种 AWVS 返回格式：
//   - JSON 字符串 "GET / HTTP/1.1\r\n..."  → 直接返回字符串值
//   - JSON null / 空                        → 返回 ""
//   - JSON 对象 {"status":200, ...}        → 格式化为可读文本
func extractRawField(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	s := string(raw)
	if s == "null" || s == `""` || s == "" {
		return ""
	}
	// 尝试作为 JSON 字符串解析（最常见）
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return str
	}
	// 尝试作为 JSON 对象解析，格式化为文本
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err == nil {
		lines := []string{}
		// 尝试提取常见 HTTP 响应字段
		if status, ok := obj["status_line"]; ok {
			lines = append(lines, fmt.Sprintf("%v", status))
		} else if code, ok := obj["status_code"]; ok {
			msg, _ := obj["status_message"]
			lines = append(lines, fmt.Sprintf("HTTP %v %v", code, msg))
		}
		if hdrs, ok := obj["headers"]; ok {
			switch v := hdrs.(type) {
			case string:
				lines = append(lines, v)
			case map[string]interface{}:
				for k, val := range v {
					lines = append(lines, fmt.Sprintf("%s: %v", k, val))
				}
			case []interface{}:
				for _, h := range v {
					if hm, ok := h.(map[string]interface{}); ok {
						lines = append(lines, fmt.Sprintf("%v: %v", hm["name"], hm["value"]))
					}
				}
			}
		}
		if body, ok := obj["body"]; ok && body != nil && body != "" {
			lines = append(lines, "", fmt.Sprintf("%v", body))
		}
		if len(lines) > 0 {
			result := ""
			for _, l := range lines {
				result += l + "\n"
			}
			return result
		}
		// 兜底：返回格式化 JSON
		b, _ := json.MarshalIndent(obj, "", "  ")
		return string(b)
	}
	// 最后兜底：返回原始字节
	return s
}

// GetVulnerabilitiesByTarget 获取指定目标的漏洞列表（自动分页，按严重程度降序）
func (c *Client) GetVulnerabilitiesByTarget(targetID string) ([]Vulnerability, error) {
	return fetchAllPages(func(limit, cursor int) ([]Vulnerability, int, error) {
		extra := fmt.Sprintf("q=target_id:%s&s=severity:desc", targetID)
		path := pageURL("/api/v1/vulnerabilities", limit, cursor, extra)
		_, body, err := c.doRequest("GET", path, nil)
		if err != nil {
			return nil, 0, err
		}
		var resp vulnListResp
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, 0, fmt.Errorf("解析响应失败: %v", err)
		}
		return resp.Vulnerabilities, resp.Pagination.TotalCount, nil
	})
}
