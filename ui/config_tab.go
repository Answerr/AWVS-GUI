package ui

import (
	"awvs-client/api"
	"awvs-client/config"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// ConfigTab 系统配置标签页
type ConfigTab struct {
	cfg             *config.Config
	window          fyne.Window
	onClientChanged func(*api.Client)
}

// NewConfigTab 创建配置标签页
func NewConfigTab(cfg *config.Config, window fyne.Window, onChanged func(*api.Client)) *ConfigTab {
	return &ConfigTab{cfg: cfg, window: window, onClientChanged: onChanged}
}

// Build 构建配置标签页界面
func (c *ConfigTab) Build() fyne.CanvasObject {

	// ── AWVS 连接配置 ──
	baseURLEntry := widget.NewEntry()
	baseURLEntry.SetText(c.cfg.BaseURL)
	baseURLEntry.SetPlaceHolder("https://localhost:3443")

	apiKeyEntry := widget.NewPasswordEntry()
	apiKeyEntry.SetText(c.cfg.APIKey)
	apiKeyEntry.SetPlaceHolder("在 AWVS 用户设置中生成 API Key")

	statusLabel := widget.NewLabel("请配置 AWVS 连接信息后点击「测试连接」")

	// ── 代理配置 ──
	proxyHostEntry := widget.NewEntry()
	proxyHostEntry.SetText(c.cfg.ProxyHost)
	proxyHostEntry.SetPlaceHolder("代理 IP 地址（留空不使用代理）")

	proxyPortEntry := widget.NewEntry()
	proxyPortEntry.SetText(c.cfg.ProxyPort)
	proxyPortEntry.SetPlaceHolder("代理端口，如: 8080")

	// ── 测试连接 ──
	testBtn := widget.NewButton("🔌 测试连接", func() {
		awvsURL := baseURLEntry.Text
		key := apiKeyEntry.Text
		if awvsURL == "" || key == "" {
			dialog.ShowError(fmt.Errorf("请填写 AWVS 地址和 API Key"), c.window)
			return
		}
		statusLabel.SetText("⏳ 正在连接中，请稍候...")
		proxyHost := proxyHostEntry.Text
		proxyPort := proxyPortEntry.Text
		go func() {
			client := api.NewClientWithProxy(awvsURL, key, proxyHost, proxyPort)
			if err := client.TestConnection(); err != nil {
				statusLabel.SetText("❌ " + err.Error())
			} else {
				statusLabel.SetText("✅ 连接成功！AWVS 服务运行正常")
			}
		}()
	})

	// ── 保存并应用 ──
	saveBtn := widget.NewButton("💾 保存并应用", func() {
		awvsURL := baseURLEntry.Text
		key := apiKeyEntry.Text
		if awvsURL == "" || key == "" {
			dialog.ShowError(fmt.Errorf("请填写完整的 AWVS 连接信息"), c.window)
			return
		}
		c.cfg.BaseURL = awvsURL
		c.cfg.APIKey = key
		c.cfg.ProxyHost = proxyHostEntry.Text
		c.cfg.ProxyPort = proxyPortEntry.Text

		if err := c.cfg.Save(); err != nil {
			dialog.ShowError(fmt.Errorf("保存配置失败: %v", err), c.window)
			return
		}
		client := api.NewClientWithProxy(awvsURL, key, c.cfg.ProxyHost, c.cfg.ProxyPort)
		c.onClientChanged(client)
		statusLabel.SetText("✅ 配置已保存并应用，各标签页数据已同步刷新")
		dialog.ShowInformation("保存成功", "AWVS 连接配置已保存并应用", c.window)
	})

	// ── AWVS 配置区 ──
	awvsForm := widget.NewForm(
		widget.NewFormItem("AWVS 地址:", baseURLEntry),
		widget.NewFormItem("API Key:", apiKeyEntry),
	)
	awvsCard := widget.NewCard(
		"AWVS 连接配置",
		"Acunetix Web Vulnerability Scanner",
		container.NewVBox(
			awvsForm,
			container.NewGridWithColumns(2, testBtn, saveBtn),
			widget.NewSeparator(),
			statusLabel,
			widget.NewSeparator(),
			widget.NewLabel("获取 API Key: 登录 AWVS → 右上角用户头像 → Profile → API Key → 生成并复制"),
		),
	)

	// ── 代理配置区 ──
	proxyForm := widget.NewForm(
		widget.NewFormItem("代理 IP:", proxyHostEntry),
		widget.NewFormItem("代理端口:", proxyPortEntry),
	)
	proxyCard := widget.NewCard(
		"HTTP 代理配置（可选）",
		"通过代理服务器与 AWVS 通信，留空则直连",
		container.NewVBox(
			proxyForm,
			widget.NewLabel("示例：代理 IP = 127.0.0.1，端口 = 8080"),
		),
	)

	return container.NewPadded(container.NewVBox(awvsCard, proxyCard))
}
