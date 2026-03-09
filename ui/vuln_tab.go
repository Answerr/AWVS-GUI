package ui

import (
	"awvs-client/api"
	"fmt"
	"image/color"
	"regexp"
	"sort"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// ═══════════════════ clickableCell：scans_tab URL 列专用（手型光标 + RichText）═══════════════════

type clickableCell struct {
	widget.BaseWidget
	richText *widget.RichText
	isLink   bool
}

func newClickableCell() *clickableCell {
	c := &clickableCell{richText: widget.NewRichText()}
	c.ExtendBaseWidget(c)
	return c
}

func (c *clickableCell) Cursor() desktop.Cursor {
	if c.isLink {
		return desktop.PointerCursor
	}
	return desktop.DefaultCursor
}

func (c *clickableCell) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(c.richText)
}

// ═══════════════════ cursorLabel：targets_tab URL 列专用（手型光标 + Label + 省略截断）═══════════════════

type cursorLabel struct {
	widget.BaseWidget
	label  *widget.Label
	isLink bool
}

func newCursorLabel() *cursorLabel {
	lbl := widget.NewLabel("")
	lbl.Truncation = fyne.TextTruncateEllipsis
	c := &cursorLabel{label: lbl}
	c.ExtendBaseWidget(c)
	return c
}

func (c *cursorLabel) Cursor() desktop.Cursor {
	if c.isLink {
		return desktop.PointerCursor
	}
	return desktop.DefaultCursor
}

func (c *cursorLabel) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(c.label)
}

// ═══════════════════ vulnCell：漏洞表格专用（彩色圆 + Label + 手型光标）═══════════════════
//
// 相比 makeCircleCell 返回的 *fyne.Container，vulnCell 额外实现了 desktop.Cursorable，
// 可在漏洞名称列（col=2）显示手型光标，指示该格可点击查看详情。
//
// 内部 content 结构（Border 布局）：Objects[0]=lbl(center), Objects[1]=circleBox(left)

type vulnCell struct {
	widget.BaseWidget
	content *fyne.Container // border layout: circleBox(left) + lbl(center)
	isLink  bool            // true = 鼠标悬停显示手型光标
}

func newVulnCell() *vulnCell {
	circle := canvas.NewCircle(color.Transparent)
	circleBox := container.New(layout.NewGridWrapLayout(fyne.NewSize(12, 12)), circle)
	lbl := widget.NewLabel("")
	lbl.Truncation = fyne.TextTruncateEllipsis
	// Objects[0]=lbl(center), Objects[1]=circleBox(left)
	content := container.NewBorder(nil, nil, circleBox, nil, lbl)
	vc := &vulnCell{content: content}
	vc.ExtendBaseWidget(vc)
	return vc
}

func (vc *vulnCell) Cursor() desktop.Cursor {
	if vc.isLink {
		return desktop.PointerCursor
	}
	return desktop.DefaultCursor
}

func (vc *vulnCell) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(vc.content)
}

// updateVulnCell 更新 vulnCell 的圆形颜色、文字和光标样式
func updateVulnCell(cell fyne.CanvasObject, showCircle bool, circleColor color.Color, text string, bold bool, isLink bool) {
	vc := cell.(*vulnCell)
	vc.isLink = isLink
	// Objects[0]=lbl(center), Objects[1]=circleBox(left)
	lbl := vc.content.Objects[0].(*widget.Label)
	circleBox := vc.content.Objects[1].(*fyne.Container)
	circle := circleBox.Objects[0].(*canvas.Circle)

	if showCircle {
		circle.FillColor = circleColor
	} else {
		circle.FillColor = color.Transparent
	}
	circle.Refresh()
	lbl.TextStyle = fyne.TextStyle{Bold: bold}
	lbl.SetText(text)
}

// ═══════════════════ hoverCopyBtn：悬浮高亮复制按钮 ═══════════════════

type hoverCopyBtn struct {
	widget.Button
}

func newHoverCopyBtn(onCopy func()) *hoverCopyBtn {
	b := &hoverCopyBtn{}
	b.Text = "复制"
	b.Importance = widget.LowImportance
	b.OnTapped = onCopy
	b.ExtendBaseWidget(b)
	return b
}

func (b *hoverCopyBtn) Cursor() desktop.Cursor { return desktop.PointerCursor }

func (b *hoverCopyBtn) MouseIn(_ *desktop.MouseEvent) {
	b.Importance = widget.HighImportance
	b.Refresh()
}

func (b *hoverCopyBtn) MouseMoved(_ *desktop.MouseEvent) {}

func (b *hoverCopyBtn) MouseOut() {
	b.Importance = widget.LowImportance
	b.Refresh()
}

// ═══════════════════ 包级别共享工具函数 ═══════════════════

var severityColorsRGBA = []color.NRGBA{
	{R: 120, G: 120, B: 120, A: 255}, // 0: 信息 - 灰色
	{R: 30, G: 120, B: 220, A: 255},  // 1: 低危 - 蓝色
	{R: 230, G: 170, B: 0, A: 255},   // 2: 中危 - 琥珀黄
	{R: 220, G: 50, B: 30, A: 255},   // 3: 高危 - 红色
	{R: 160, G: 0, B: 0, A: 255},     // 4: 严重 - 深红色
}

func getSeverityColor(severity int) color.Color {
	if severity >= 0 && severity < len(severityColorsRGBA) {
		return severityColorsRGBA[severity]
	}
	return color.NRGBA{R: 128, G: 128, B: 128, A: 255}
}

func getSeverityName(severity int) string {
	names := []string{"信息", "低危", "中危", "高危", "严重"}
	if severity >= 0 && severity < len(names) {
		return names[severity]
	}
	return fmt.Sprintf("等级%d", severity)
}

// makeSeverityBadge 风险等级徽标（彩色圆 + 名称），用于详情弹窗标题区
func makeSeverityBadge(severity int) fyne.CanvasObject {
	circle := canvas.NewCircle(getSeverityColor(severity))
	circleBox := container.New(layout.NewGridWrapLayout(fyne.NewSize(14, 14)), circle)
	return container.NewHBox(circleBox, widget.NewLabel(" "+getSeverityName(severity)))
}

func translateVulnName(name string) string {
	if zh, ok := vulnTranslations[name]; ok {
		return zh
	}
	return name
}

func truncateStr(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes-1]) + "…"
	}
	return s
}

func vulnStatusText(status string) string {
	switch status {
	case "open":
		return "🔓 未修复"
	case "fixed":
		return "✅ 已修复"
	case "ignored":
		return "🔕 已忽略"
	case "false_positive":
		return "⚡ 误报"
	default:
		return status
	}
}

// 保留旧接口（供其他可能的调用点）
func makeCircleCell() fyne.CanvasObject { return newVulnCell() }
func updateCircleCell(cell fyne.CanvasObject, showCircle bool, circleColor color.Color, text string, bold bool) {
	updateVulnCell(cell, showCircle, circleColor, text, bold, false)
}

// ═══════════════════ HTML 清洗 ═══════════════════

var htmlTagRegex = regexp.MustCompile(`<[^>]+>`)
var multiNewlineRegex = regexp.MustCompile(`\n{3,}`)

func cleanHTML(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "</p>", "\n\n")
	s = strings.ReplaceAll(s, "<br>", "\n")
	s = strings.ReplaceAll(s, "<br/>", "\n")
	s = strings.ReplaceAll(s, "<br />", "\n")
	s = strings.ReplaceAll(s, "</li>", "\n")
	s = strings.ReplaceAll(s, "<li>", "  • ")
	s = strings.ReplaceAll(s, "</ul>", "\n")
	s = strings.ReplaceAll(s, "</ol>", "\n")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = htmlTagRegex.ReplaceAllString(s, "")
	s = multiNewlineRegex.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}

// makeDetailText 创建全展开文字展示区（漏洞描述/攻击详情等）
// 使用 Label 无边框展示，内容完整显示，自动换行
func makeDetailText(text string) fyne.CanvasObject {
	lbl := widget.NewLabel(text)
	lbl.Wrapping = fyne.TextWrapWord
	return lbl
}

// makeCodeLabel 创建全展开等宽代码展示区（HTTP 请求/响应）
// 使用 Label 无边框展示，内容完整显示
func makeCodeLabel(text string) fyne.CanvasObject {
	lbl := widget.NewLabelWithStyle(text, fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
	lbl.Wrapping = fyne.TextWrapWord
	return lbl
}

// ═══════════════════ AWVS 英文描述内容翻译（正则匹配常见固定格式）═══════════════════

// awvsDescPatterns AWVS 扫描引擎自动生成的英文描述前缀 → 中文替换
// 路径列表、数据包、技术名称等保持原样不翻译
var awvsDescPatterns = []struct {
	pattern *regexp.Regexp
	replace string
}{
	// 受影响路径类
	{regexp.MustCompile(`(?i)Affected paths?\s*\(max\.\s*(\d+)\)\s*:`), "受影响路径（最多 $1 条）："},
	{regexp.MustCompile(`(?i)Affected paths?\s*:`), "受影响路径："},
	{regexp.MustCompile(`(?i)Locations?\s+without\s+([\w\-/()]+(?:\s+[\w\-/()]+)*)\s+header\s*:`), "未配置 $1 响应头的路径："},
	{regexp.MustCompile(`(?i)Paths?\s+without\s+([\w\-/()]+(?:\s+[\w\-/()]+)*)\s+header\s*:`), "未配置 $1 响应头的路径："},
	{regexp.MustCompile(`(?i)The following (?:URLs?|locations?|paths?) (?:do not|don't) (?:have|include|implement|set)\s*`), "以下路径未配置"},
	{regexp.MustCompile(`(?i)^Locations?:\s*$`), "路径："},
	{regexp.MustCompile(`(?i)^Paths?:\s*$`), "路径："},
	// SSL/TLS 类
	{regexp.MustCompile(`(?i)Cipher suites? susceptible to Sweet32 attack \((TLS[\d.]+) on port (\d+)\)\s*:`), "受 Sweet32 攻击影响的加密套件（$1，端口 $2）："},
	{regexp.MustCompile(`(?i)SSL server \(port (\d+)\) uses (TLS[\d.]+|SSLv[\d.]+) for encryption`), "SSL 服务器（端口 $1）使用 $2 加密流量"},
	{regexp.MustCompile(`(?i)The SSL server supports? (TLS[\d.]+|SSLv[\d.]+)`), "SSL 服务器支持 $1 协议"},
	// 通用弱加密
	{regexp.MustCompile(`(?i)Weak cipher suites? supported\s*:`), "支持的弱加密套件："},
}

// translateAffectsContent 将 AWVS 自动生成的英文描述前缀翻译为中文
// URL 路径、加密套件名称、数据包内容保持英文原样
func translateAffectsContent(s string) string {
	if s == "" {
		return ""
	}
	for _, p := range awvsDescPatterns {
		s = p.pattern.ReplaceAllString(s, p.replace)
	}
	return s
}

// truncateLongText 截断文本，仅保留前 maxLines 行，并附加截断说明
func truncateLongText(s string, maxLines int) string {
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	if len(lines) <= maxLines {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:maxLines], "\n") +
		fmt.Sprintf("\n\n... (共 %d 行，仅显示前 %d 行)", len(lines), maxLines)
}

// ═══════════════════ showVulnDetailDialog：漏洞完整详情弹窗（精简4节）═══════════════════

// showVulnDetailDialog 固定展示4个节：攻击详情 / 漏洞描述 / HTTP请求 / HTTP响应
// 规则：
//   - 攻击详情、漏洞描述内容翻译前缀，路径及数据包原样保留
//   - 若攻击详情与漏洞描述内容完全相同，只显示漏洞描述
//   - HTTP响应为空时显示提示语
func showVulnDetailDialog(detail *api.VulnDetail, window fyne.Window) {
	// ── 标题（中文 + 英文）──
	chName := translateVulnName(detail.VtName)
	titleText := chName
	if chName != detail.VtName {
		titleText = chName + "\n(" + detail.VtName + ")"
	}
	titleLbl := widget.NewLabelWithStyle(titleText, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	titleLbl.Wrapping = fyne.TextWrapWord

	// ── 基本信息行 ──
	sevRow := container.NewHBox(widget.NewLabel("风险等级："), makeSeverityBadge(detail.Severity))
	urlLbl := widget.NewLabel(detail.AffectsURL)
	urlLbl.Truncation = fyne.TextTruncateEllipsis
	urlCopyBtn := newHoverCopyBtn(func() { window.Clipboard().SetContent(detail.AffectsURL) })
	urlRow := container.NewBorder(nil, nil, widget.NewLabel("影响URL："), urlCopyBtn, urlLbl)

	sections := []fyne.CanvasObject{
		titleLbl,
		widget.NewSeparator(),
		sevRow,
		urlRow,
		widget.NewSeparator(),
	}

	// ── 节构建助手 ──
	// makeSectionHeader 创建节标题行：左侧标题 + 右侧悬浮高亮"复制"按钮
	makeSectionHeader := func(title, copyText string) fyne.CanvasObject {
		titleLbl := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		copyBtn := newHoverCopyBtn(func() { window.Clipboard().SetContent(copyText) })
		return container.NewBorder(nil, nil, nil, copyBtn, titleLbl)
	}

	addTextSec := func(title, content string) {
		cleaned := strings.TrimSpace(cleanHTML(content))
		if cleaned == "" {
			return
		}
		translated := translateAffectsContent(cleaned)
		sections = append(sections,
			makeSectionHeader(title, translated),
			makeDetailText(translated),
			widget.NewSeparator(),
		)
	}
	addCodeSec := func(title, content string, maxLines int) {
		if content == "" {
			return // 无数据则不显示该节
		}
		truncated := truncateLongText(content, maxLines)
		sections = append(sections,
			makeSectionHeader(title, content), // 复制完整内容（不截断）
			makeCodeLabel(truncated),
			widget.NewSeparator(),
		)
	}

	// ── 节1：漏洞描述（顶层 description 字段 = 通用漏洞说明）──
	// 若为空则用 long_description 兜底
	generalDesc := detail.Description
	if generalDesc == "" {
		generalDesc = detail.LongDescription
	}
	addTextSec("📝 漏洞描述", generalDesc)

	// ── 节2：攻击详情（details 字段 = 具体发现描述，如受影响 URL 列表）──
	// 若与漏洞描述内容重复则跳过
	findingText := strings.TrimSpace(cleanHTML(detail.Details.Description))
	descText := strings.TrimSpace(cleanHTML(generalDesc))
	if findingText != "" && findingText != descText &&
		!strings.Contains(descText, findingText) {
		addTextSec("📋 攻击详情", findingText)
	}

	// ── 节3：HTTP 请求（原样显示）──
	addCodeSec("📤 HTTP 请求", detail.Request, 80)

	// ── 节4：HTTP 响应（原样显示）──
	// 注：AWVS 的 /api/v1/vulnerabilities/{id} 端点不返回响应包数据
	// AWVS web 界面的响应包来自其他内部来源，当前 API 无法获取
	addCodeSec("📥 HTTP 响应", detail.Response, 60)

	content := container.NewVBox(sections...)
	scroll := container.NewScroll(content)
	scroll.SetMinSize(fyne.NewSize(740, 460))

	d := dialog.NewCustom(
		fmt.Sprintf("📋 漏洞详情 - %s", getSeverityName(detail.Severity)),
		"关闭",
		scroll,
		window,
	)
	d.Resize(fyne.NewSize(900, 680)) // 加大对话框高度，让各节内容更充裕
	d.Show()
}

// ═══════════════════ showVulnDialog：漏洞列表弹窗（支持点击名称查看详情）═══════════════════

func showVulnDialog(address string, vulns []api.Vulnerability, client *api.Client, window fyne.Window) {
	sortDesc := true
	sortedVulns := make([]api.Vulnerability, len(vulns))
	copy(sortedVulns, vulns)

	doSort := func() {
		sort.Slice(sortedVulns, func(i, j int) bool {
			if sortDesc {
				return sortedVulns[i].Severity > sortedVulns[j].Severity
			}
			return sortedVulns[i].Severity < sortedVulns[j].Severity
		})
	}
	doSort()

	dlgCols := []string{"序号", "风险等级", "漏洞名称（点击查看详情）", "影响 URL", "状态"}
	dlgColWidths := []float32{50, 95, 250, 318, 88}

	var vulnTable *widget.Table
	vulnTable = widget.NewTable(
		func() (int, int) { return len(sortedVulns) + 1, len(dlgCols) },
		// ★ 使用 vulnCell（支持手型光标）
		func() fyne.CanvasObject { return newVulnCell() },
		func(id widget.TableCellID, cell fyne.CanvasObject) {
			if id.Row == 0 {
				// 表头：无光标
				updateVulnCell(cell, false, color.Transparent, dlgCols[id.Col], true, false)
				return
			}
			row := id.Row - 1
			if row >= len(sortedVulns) {
				updateVulnCell(cell, false, color.Transparent, "", false, false)
				return
			}
			vuln := sortedVulns[row]
			switch id.Col {
			case 0:
				updateVulnCell(cell, false, color.Transparent, fmt.Sprintf("%d", row+1), false, false)
			case 1:
				updateVulnCell(cell, true, getSeverityColor(vuln.Severity), " "+getSeverityName(vuln.Severity), false, false)
			case 2: // ★ 漏洞名称：isLink=true → 手型光标
				updateVulnCell(cell, false, color.Transparent, truncateStr(translateVulnName(vuln.VtName), 20), false, true)
			case 3:
				updateVulnCell(cell, false, color.Transparent, truncateStr(vuln.AffectsURL, 36), false, false)
			case 4:
				updateVulnCell(cell, false, color.Transparent, vulnStatusText(vuln.Status), false, false)
			}
		},
	)
	for i, w := range dlgColWidths {
		vulnTable.SetColumnWidth(i, w)
	}

	// 点击漏洞名称（col=2）→ 查看详情；立即 Unselect 确保可重复点击
	vulnTable.OnSelected = func(id widget.TableCellID) {
		if id.Row <= 0 || id.Col != 2 || client == nil {
			return
		}
		row := id.Row - 1
		if row >= len(sortedVulns) {
			return
		}
		vuln := sortedVulns[row]
		vulnTable.Unselect(id)
		go func() {
			detail, err := client.GetVulnerabilityDetail(vuln.VulnID)
			if err != nil {
				dialog.ShowError(fmt.Errorf("获取漏洞详情失败: %v", err), window)
				return
			}
			showVulnDetailDialog(detail, window)
		}()
	}

	counts := make(map[int]int)
	for _, v := range vulns {
		counts[v.Severity]++
	}
	statsLabel := widget.NewLabel(fmt.Sprintf(
		"共 %d 个漏洞   严重: %d  高危: %d  中危: %d  低危: %d  信息: %d",
		len(vulns), counts[4], counts[3], counts[2], counts[1], counts[0],
	))

	var sortBtnRef *widget.Button
	sortBtnRef = widget.NewButton("↓ 高危优先", func() {
		sortDesc = !sortDesc
		doSort()
		vulnTable.Refresh()
		if sortDesc {
			sortBtnRef.SetText("↓ 高危优先")
		} else {
			sortBtnRef.SetText("↑ 低危优先")
		}
	})

	toolbar := container.NewHBox(sortBtnRef, layout.NewSpacer(), statsLabel)
	content := container.NewBorder(
		container.NewVBox(toolbar, widget.NewSeparator()),
		nil, nil, nil,
		vulnTable,
	)

	d := dialog.NewCustom(
		fmt.Sprintf("⚠️ 漏洞详情 - %s（共 %d 个）", address, len(vulns)),
		"关闭",
		content,
		window,
	)
	d.Resize(fyne.NewSize(900, 560))
	d.Show()
}

// ═══════════════════ 常见漏洞名称中文翻译表 ═══════════════════

var vulnTranslations = map[string]string{
	"Insecure Transportation Security Protocol Supported (TLS 1.0)": "支持不安全的TLS 1.0协议",
	"Insecure Transportation Security Protocol Supported (TLS 1.1)": "支持不安全的TLS 1.1协议",
	"Insecure Transportation Security Protocol Supported (SSLv2)":   "支持不安全的SSLv2协议",
	"Insecure Transportation Security Protocol Supported (SSLv3)":   "支持不安全的SSLv3协议",
	"TLS/SSL Sweet32 attack":                                   "TLS/SSL Sweet32攻击漏洞",
	"TLS/SSL Weak Cipher Suites":                               "TLS/SSL弱加密套件",
	"SSL/TLS Not Implemented":                                  "未启用SSL/TLS加密传输",
	"HTTP Strict Transport Security (HSTS) Policy Not Enabled": "未启用HTTP严格传输安全(HSTS)",
	"TLS Certificate is self-signed":                           "TLS证书为自签名证书",
	"TLS Certificate Expired":                                  "TLS证书已过期",
	"TLS Certificate - Subject Does Not Match":                 "TLS证书域名不匹配",
	"Cross-site Scripting":                                     "跨站脚本攻击(XSS)",
	"Cross-site Scripting (XSS)":                               "跨站脚本攻击(XSS)",
	"Reflected Cross-site Scripting":                           "反射型跨站脚本(XSS)",
	"Stored Cross-site Scripting":                              "存储型跨站脚本(XSS)",
	"DOM-based Cross-site Scripting":                           "DOM型跨站脚本(XSS)",
	"Cross-site Scripting (verified)":                          "跨站脚本攻击-已验证(XSS)",
	"SQL Injection":                                            "SQL注入",
	"Blind SQL Injection":                                      "盲注SQL注入",
	"SQL Injection (verified)":                                 "SQL注入（已验证）",
	"Blind SQL Injection (verified)":                           "盲注SQL注入（已验证）",
	"SQL Injection via HTTP Headers":                           "通过HTTP头的SQL注入",
	"Content Security Policy (CSP) Not Implemented":            "未实现内容安全策略(CSP)",
	"X-Content-Type-Options (XCTO) Not Implemented":            "未实现X-Content-Type-Options响应头",
	"X-Frame-Options (XFO) Not Implemented":                    "未实现X-Frame-Options防点击劫持头",
	"Access-Control-Allow-Origin Header with Wildcard":         "CORS跨域允许任意来源(通配符)",
	"Permissions-Policy header not implemented":                "未实现Permissions-Policy响应头",
	"Missing object-src in CSP Declaration":                    "CSP声明缺少object-src指令",
	"Referrer-Policy Not Implemented":                          "未实现Referrer-Policy响应头",
	"HTTP Security Headers Missing":                            "缺少HTTP安全响应头",
	"TRACE Method enabled":                                     "HTTP TRACE方法已启用",
	"OPTIONS Method enabled":                                   "HTTP OPTIONS方法已启用",
	"HTTP Methods Enabled":                                     "HTTP危险方法已启用",
	"Cookie Without HttpOnly Flag":                             "Cookie未设置HttpOnly标志",
	"Cookie Without Secure Flag":                               "Cookie未设置Secure标志",
	"Session Fixation":                                         "会话固定漏洞",
	"Weak Passwords":                                           "弱口令",
	"CSRF":                                                     "跨站请求伪造(CSRF)",
	"Cross-site Request Forgery":                               "跨站请求伪造(CSRF)",
	"Unencrypted Login Form":                                   "未加密的登录表单",
	"Password Transmitted in Clear Text":                       "密码以明文方式传输",
	"Command Injection":                                        "操作系统命令注入",
	"Code Injection":                                           "代码注入",
	"CRLF Injection":                                           "CRLF注入",
	"HTML Injection":                                           "HTML注入",
	"Server Side Template Injection (SSTI)":                    "服务端模板注入(SSTI)",
	"XML External Entity (XXE) Injection":                      "XML外部实体注入(XXE)",
	"Host Header Injection":                                    "Host请求头注入",
	"Directory Traversal":                                      "目录遍历漏洞",
	"Path Traversal":                                           "路径遍历漏洞",
	"Local File Inclusion (LFI)":                               "本地文件包含(LFI)",
	"Remote File Inclusion (RFI)":                              "远程文件包含(RFI)",
	"File Upload":                                              "任意文件上传漏洞",
	"Directory Listing Enabled":                                "目录列表已开启",
	"Backup File Found":                                        "发现备份文件",
	"Configuration File Found":                                 "发现配置文件",
	"Version Disclosure (PHP)":                                 "PHP版本信息泄露",
	"Version Disclosure (Apache)":                              "Apache版本信息泄露",
	"Version Disclosure (IIS)":                                 "IIS版本信息泄露",
	"Version Disclosure (nginx)":                               "Nginx版本信息泄露",
	"Application Error Disclosure":                             "应用程序错误信息泄露",
	"Private IP Disclosure":                                    "内网IP地址泄露",
	"phpinfo() Page Found":                                     "phpinfo()信息泄露页面",
	"Sensitive Data Exposure":                                  "敏感数据暴露",
	"Git Repository Found":                                     "Git仓库暴露",
	"SVN Repository Found":                                     "SVN仓库暴露",
	"robots.txt Contains Disallowed Entries":                   "robots.txt包含敏感路径信息",
	"Open Redirect":                                            "开放重定向漏洞",
	"Clickjacking - Frameable Response":                        "点击劫持漏洞",
	"Server-side Request Forgery (SSRF)":                       "服务端请求伪造(SSRF)",
	"Insecure Deserialization":                                 "不安全的反序列化漏洞",
	"Cross-Origin Resource Sharing (CORS)":                     "CORS跨域资源共享配置不当",
	"Log4j Remote Code Execution":                              "Log4j远程代码执行漏洞",
	"Spring4Shell - Remote Code Execution":                     "Spring4Shell远程代码执行漏洞",
	"ShellShock - Remote Code Execution":                       "ShellShock远程代码执行漏洞",
	"Heartbleed OpenSSL":                                       "Heartbleed OpenSSL漏洞",
	// RSA/私钥泄露
	"RSA Private Key Detected":   "RSA私钥泄露",
	"RSA Private Key Disclosure": "RSA私钥泄露",
	"Private Key Detected":       "私钥文件泄露",
	// SVN/Git 仓库
	"SVN Detected":            "SVN仓库暴露",
	"SVN Repository Detected": "SVN仓库暴露",
	// 混合内容
	"Active Mixed Content":       "活动混合内容(HTTP资源在HTTPS页面中加载)",
	"Active Mixed Content Found": "发现活动混合内容",
	"Passive Mixed Content":      "被动混合内容漏洞",
	// AngularJS
	"AngularJS Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')": "AngularJS XSS输入过滤不当",
	"AngularJS Improper Neutralization of Input During Web Page Generation":                          "AngularJS XSS输入过滤不当",
	"AngularJS Other Vulnerabilities":          "AngularJS 其他安全漏洞",
	"AngularJS Client-Side Template Injection": "AngularJS 客户端模板注入",
	// Bootstrap
	"Bootstrap Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')": "Bootstrap XSS输入过滤不当",
	"Bootstrap Improper Neutralization of Input During Web Page Generation":                          "Bootstrap XSS输入过滤不当",
	"Bootstrap Other Vulnerabilities": "Bootstrap 其他安全漏洞",
	// Moment.js
	"Moment.js Improper Library Usage":                     "Moment.js 不当的库使用方式",
	"Moment.js Uncontrolled Regular Expression Complexity": "Moment.js 正则表达式复杂度不可控(ReDoS)",
	"Moment.js ReDoS": "Moment.js 正则拒绝服务(ReDoS)",
	// Next.js
	"Next.js Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')": "Next.js HTTP请求解析不一致(请求走私)",
	"Next.js Inconsistent Interpretation of HTTP Requests":                                     "Next.js HTTP请求解析不一致",
	"Next.js HTTP Request Smuggling":                                                           "Next.js HTTP请求走私",
	// jQuery
	"jQuery Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')": "jQuery XSS输入过滤不当",
	"jQuery Improper Neutralization of Input During Web Page Generation":                          "jQuery XSS输入过滤不当",
	"jQuery Other Vulnerabilities": "jQuery 其他安全漏洞",
	// React/Vue
	"React Improper Neutralization of Input During Web Page Generation": "React XSS输入过滤不当",
	"Vue.js Other Vulnerabilities":                                      "Vue.js 其他安全漏洞",
	// Lodash/Prototype
	"Lodash Prototype Pollution": "Lodash 原型链污染漏洞",
	"Prototype Pollution":        "原型链污染漏洞",
	"ReDoS":                      "正则表达式拒绝服务(ReDoS)",
	// 其他常见漏洞
	"DNS Zone Transfer":                           "DNS区域传输漏洞",
	"Email Header Injection":                      "邮件头注入漏洞",
	"HTTP Parameter Pollution":                    "HTTP参数污染漏洞",
	"Web Cache Poisoning":                         "Web缓存投毒漏洞",
	"Subdomain Takeover":                          "子域名接管漏洞",
	"Open Database":                               "数据库未授权访问",
	"MongoDB Unauthenticated Access":              "MongoDB未授权访问",
	"Redis Unauthenticated Access":                "Redis未授权访问",
	"Elasticsearch Unauthenticated Access":        "Elasticsearch未授权访问",
	"Memcached Unauthenticated Access":            "Memcached未授权访问",
	"API Documentation Exposed":                   "API文档暴露",
	"GraphQL Introspection Enabled":               "GraphQL自省功能已启用",
	"Swagger UI Exposed":                          "Swagger UI接口文档暴露",
	"Source Code Disclosure":                      "源代码泄露",
	"AWS Access Key Exposed":                      "AWS访问密钥泄露",
	"Google API Key Exposed":                      "Google API密钥泄露",
	"Moment.js Uncontrolled Resource Consumption": "Moment.js 资源消耗不可控",
	"WordPress Configuration File":                "WordPress配置文件泄露",
	"Laravel Debug Mode Enabled":                  "Laravel调试模式已启用",
	"Django Debug Mode Enabled":                   "Django调试模式已启用",
	"WordPress Outdated":                          "WordPress版本过旧",
	// 通用名称模式补全
	"Insecure Transportation Security Protocol Supported": "支持不安全的传输安全协议",
	"Weak SSL/TLS Cipher Suites Supported":                "支持弱SSL/TLS加密套件",
	"Certificate Transparency":                            "证书透明度问题",
	// 目录列表（AWVS 有时用小写 listings）
	"Directory listings": "目录列表已开启",
	"Directory listing":  "目录列表已开启",
	// 开发配置文件（AWVS 准确名称含 files 复数）
	"Development configuration files":              "开发配置文件泄露",
	"Development configuration files found":        "发现开发配置文件",
	"Development configuration":                    "开发配置文件泄露",
	"Development configuration file":               "开发配置文件泄露",
	"Development configuration file found":         "发现开发配置文件",
	"Development configuration in source code":     "源码中发现开发配置信息",
	// Host 头攻击（AWVS 多种写法）
	"Host header attack":    "Host头注入攻击",
	"Host Header Attack":    "Host头注入攻击",
	"Host header injection": "Host头注入漏洞",
	// Active Mixed Content - AWVS 各种写法（注意：不能重复已有的 key）
	"Active mixed content": "活动混合内容漏洞",
	"Mixed Content":        "混合内容漏洞",
	// 通用 XSS 缺翻译补全
	"Cross-site Scripting (DOM-based)": "DOM型跨站脚本攻击(XSS)",
	"Cross-site Scripting (Reflected)": "反射型跨站脚本攻击(XSS)",
	"Cross-site Scripting (Stored)":    "存储型跨站脚本攻击(XSS)",
	// 其他常见
	"Information Disclosure":    "信息泄露漏洞",
	"Security Misconfiguration": "安全配置错误",
	"Remote Code Execution":     "远程代码执行漏洞(RCE)",
	"Buffer Overflow":           "缓冲区溢出漏洞",
	"Race Condition":            "竞态条件漏洞",
}

// ═══════════════════ VulnTab：漏洞列表主标签页 ═══════════════════

type VulnTab struct {
	mu          sync.RWMutex // 保护 allVulns 和 vulns 的并发读写
	client      *api.Client
	window      fyne.Window
	allVulns    []api.Vulnerability
	vulns       []api.Vulnerability
	table       *widget.Table
	statusLabel *widget.Label
	statsLabel  *widget.Label
	sortDesc    bool
	sortBtn     *widget.Button
}

func NewVulnTab(client *api.Client, window fyne.Window) *VulnTab {
	return &VulnTab{client: client, window: window, sortDesc: true}
}

func (v *VulnTab) Build() fyne.CanvasObject {
	v.statusLabel = widget.NewLabel("就绪")
	v.statsLabel = widget.NewLabel("")

	columns := []string{"序号", "风险等级", "漏洞名称（点击查看详情）", "影响 URL", "状态"}
	colWidths := []float32{55, 100, 285, 362, 92}

	v.table = widget.NewTable(
		func() (int, int) {
			v.mu.RLock()
			n := len(v.vulns)
			v.mu.RUnlock()
			return n + 1, len(columns)
		},
		func() fyne.CanvasObject { return newVulnCell() },
		func(id widget.TableCellID, cell fyne.CanvasObject) {
			if id.Row == 0 {
				updateVulnCell(cell, false, color.Transparent, columns[id.Col], true, false)
				return
			}
			row := id.Row - 1

			// 快照当前行数据后立即释放锁，避免持锁期间触发 UI 操作
			v.mu.RLock()
			if row >= len(v.vulns) {
				v.mu.RUnlock()
				updateVulnCell(cell, false, color.Transparent, "", false, false)
				return
			}
			vuln := v.vulns[row]
			v.mu.RUnlock()

			switch id.Col {
			case 0:
				updateVulnCell(cell, false, color.Transparent, fmt.Sprintf("%d", row+1), false, false)
			case 1:
				updateVulnCell(cell, true, getSeverityColor(vuln.Severity), " "+getSeverityName(vuln.Severity), false, false)
			case 2:
				updateVulnCell(cell, false, color.Transparent, truncateStr(translateVulnName(vuln.VtName), 22), false, true)
			case 3:
				updateVulnCell(cell, false, color.Transparent, truncateStr(vuln.AffectsURL, 44), false, false)
			case 4:
				updateVulnCell(cell, false, color.Transparent, vulnStatusText(vuln.Status), false, false)
			}
		},
	)
	for i, w := range colWidths {
		v.table.SetColumnWidth(i, w)
	}

	// 点击漏洞名称（col=2）→ 查看详情；立即 Unselect 确保可重复点击
	v.table.OnSelected = func(id widget.TableCellID) {
		if id.Row <= 0 || id.Col != 2 || v.client == nil {
			return
		}
		row := id.Row - 1

		v.mu.RLock()
		if row >= len(v.vulns) {
			v.mu.RUnlock()
			return
		}
		vuln := v.vulns[row]
		v.mu.RUnlock()

		v.table.Unselect(id)
		go func() {
			detail, err := v.client.GetVulnerabilityDetail(vuln.VulnID)
			if err != nil {
				dialog.ShowError(fmt.Errorf("获取漏洞详情失败: %v", err), v.window)
				return
			}
			showVulnDetailDialog(detail, v.window)
		}()
	}

	refreshBtn := widget.NewButton("🔄 刷新漏洞列表", func() { go v.refresh() })

	v.sortBtn = widget.NewButton("↓ 高危优先", func() {
		v.sortDesc = !v.sortDesc
		v.applySort()
		if v.sortDesc {
			v.sortBtn.SetText("↓ 高危优先")
		} else {
			v.sortBtn.SetText("↑ 低危优先")
		}
	})

	toolbar := container.NewHBox(refreshBtn, v.sortBtn, layout.NewSpacer(), v.statsLabel)
	topSection := container.NewVBox(container.NewPadded(toolbar), widget.NewSeparator())
	statusBar := container.NewHBox(widget.NewLabel("状态:"), v.statusLabel)

	if v.client != nil {
		go v.refresh()
	}
	return container.NewBorder(topSection, statusBar, nil, nil, v.table)
}

func (v *VulnTab) applySort() {
	v.mu.Lock()
	cp := make([]api.Vulnerability, len(v.allVulns))
	copy(cp, v.allVulns)
	desc := v.sortDesc
	sort.Slice(cp, func(i, j int) bool {
		if desc {
			return cp[i].Severity > cp[j].Severity
		}
		return cp[i].Severity < cp[j].Severity
	})
	v.vulns = cp
	v.mu.Unlock()
	v.table.Refresh()
}

func (v *VulnTab) buildStats() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if len(v.allVulns) == 0 {
		return "暂无漏洞数据"
	}
	counts := make(map[int]int)
	for _, vuln := range v.allVulns {
		counts[vuln.Severity]++
	}
	return fmt.Sprintf("严重: %d  高危: %d  中危: %d  低危: %d  信息: %d",
		counts[4], counts[3], counts[2], counts[1], counts[0])
}

func (v *VulnTab) setStatus(msg string) { v.statusLabel.SetText(msg) }

func (v *VulnTab) refresh() {
	if v.client == nil {
		v.setStatus("未配置 AWVS 连接，请进入【系统配置】")
		return
	}
	v.setStatus("⏳ 正在加载漏洞数据...")
	vulns, err := v.client.GetVulnerabilities()
	if err != nil {
		v.setStatus("❌ 加载失败: " + err.Error())
		dialog.ShowError(err, v.window)
		return
	}
	// 写锁：原子性替换 allVulns，再触发排序和渲染
	v.mu.Lock()
	v.allVulns = vulns
	v.mu.Unlock()

	v.applySort()
	v.statsLabel.SetText(v.buildStats())
	v.setStatus(fmt.Sprintf("✅ 共发现 %d 个漏洞", len(vulns)))
}

func (v *VulnTab) SetClient(client *api.Client) {
	v.client = client
	go v.refresh()
}
