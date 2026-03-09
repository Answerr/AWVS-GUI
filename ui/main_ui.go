package ui

import (
	"awvs-client/api"
	"awvs-client/config"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// MainUI 主界面管理
type MainUI struct {
	app    fyne.App
	window fyne.Window
	cfg    *config.Config
	client *api.Client

	configTab  *ConfigTab
	enginesTab *EnginesTab
	targetsTab *TargetsTab
	scansTab   *ScansTab
	vulnTab    *VulnTab
}

// NewMainUI 创建主界面
func NewMainUI(app fyne.App, window fyne.Window, cfg *config.Config) *MainUI {
	m := &MainUI{
		app:    app,
		window: window,
		cfg:    cfg,
	}
	// 启动时如果已有配置则初始化客户端（含代理支持）
	if cfg.APIKey != "" && cfg.BaseURL != "" {
		m.client = api.NewClientWithProxy(cfg.BaseURL, cfg.APIKey, cfg.ProxyHost, cfg.ProxyPort)
	}
	return m
}

// Build 构建并返回主界面内容
func (m *MainUI) Build() fyne.CanvasObject {
	m.configTab = NewConfigTab(m.cfg, m.window, m.onClientChanged)
	m.enginesTab = NewEnginesTab(m.cfg, m.window)
	m.targetsTab = NewTargetsTab(m.client, m.window, m.cfg)
	m.scansTab = NewScansTab(m.client, m.window)
	m.vulnTab = NewVulnTab(m.client, m.window)

	tabs := container.NewAppTabs(
		container.NewTabItem("🎯 扫描目标", m.targetsTab.Build()),
		container.NewTabItem("🔍 扫描任务", m.scansTab.Build()),
		container.NewTabItem("⚠️ 漏洞列表", m.vulnTab.Build()),
		container.NewTabItem("🌐 测绘引擎配置", m.enginesTab.Build()),
		container.NewTabItem("⚙️ 系统配置", m.configTab.Build()),
		container.NewTabItem("ℹ 关于", buildAbout()),
	)
	tabs.SetTabLocation(container.TabLocationTop)
	return tabs
}

// onClientChanged 当配置更新后，同步刷新所有标签页的客户端
func (m *MainUI) onClientChanged(client *api.Client) {
	m.client = client
	if m.targetsTab != nil {
		m.targetsTab.SetClient(client)
	}
	if m.scansTab != nil {
		m.scansTab.SetClient(client)
	}
	if m.vulnTab != nil {
		m.vulnTab.SetClient(client)
	}
}

// buildAbout 构建"关于"页面
func buildAbout() fyne.CanvasObject {
	title := widget.NewLabelWithStyle(
		"AWVS GUI",
		fyne.TextAlignCenter,
		fyne.TextStyle{Bold: true},
	)
	lines := []string{
		"版本: V1.0",
		"作者：信益安",
		"",
		"─────────────────────────────────────────",
		"功能介绍:",
		"  • 通过 Acunetix Web Vulnerability Scanner API 管理扫描",
		"  • 支持单个 URL 添加 和 TXT 文件批量导入（每行一个域名）",
		"  • 支持域名格式：baidu.com / http://... / https://...",
		"  • 支持扫描任务多选批量删除",
		"  • 支持 HTTP 代理配置",
		"",
		"─────────────────────────────────────────",
		"使用说明:",
		"  1. 进入【系统配置】填写 AWVS 地址 和 API Key，保存并应用",
		"  2. 进入【扫描目标】添加目标 URL 或从 TXT 批量导入",
		"  3. 选择扫描配置，点击「扫描选中」或「扫描全部」",
		"  4. 进入【扫描任务】查看实时扫描进度，支持多选批量删除",
		"",
		"─────────────────────────────────────────",
		"开源声明:",
		"  本项目基于 MIT License 开源，欢迎自由使用、修改与分发。",
		"  请在衍生项目中保留原作者署名：信益安。",
		"",
		"免责声明:",
		"  本工具仅限于授权范围内的合法安全测试与研究用途。",
		"  使用者须自行承担因不当使用本工具而产生的一切法律责任。",
		"  对于任何未经授权的使用行为，作者不承担任何连带责任。",
		"",
		"⚠️ 警告: 未经目标系统所有者明确授权，使用本工具进行测试属违法行为！",
	}
	// 公众号二维码
	qrImg := canvas.NewImageFromResource(resourceGzhJpg)
	qrImg.FillMode = canvas.ImageFillContain
	qrImg.SetMinSize(fyne.NewSize(160, 160))
	qrBox := container.NewCenter(container.NewVBox(
		widget.NewLabelWithStyle("公众号", fyne.TextAlignCenter, fyne.TextStyle{}),
		qrImg,
	))

	items := []fyne.CanvasObject{title}
	for _, line := range lines {
		items = append(items, widget.NewLabel(line))
	}
	items = append(items, widget.NewSeparator(), qrBox)

	return container.NewScroll(container.NewCenter(container.NewVBox(items...)))
}
