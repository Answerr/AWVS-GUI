package ui

import (
	"awvs-client/config"
	"fmt"
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// dotWidget 固定尺寸的彩色圆点，用于引擎卡片标题图标
type dotWidget struct {
	widget.BaseWidget
	circle *canvas.Circle
}

func newDotWidget(c color.Color) *dotWidget {
	d := &dotWidget{circle: canvas.NewCircle(c)}
	d.ExtendBaseWidget(d)
	return d
}

// MinSize 覆盖 BaseWidget，确保布局为圆点分配固定空间
func (d *dotWidget) MinSize() fyne.Size         { return fyne.NewSize(16, 16) }
func (d *dotWidget) CreateRenderer() fyne.WidgetRenderer { return widget.NewSimpleRenderer(d.circle) }

// buildEngineCard 构建统一样式的引擎配置卡片（canvas 圆点 + 名称 + URL + 表单）
func buildEngineCard(dotColor color.Color, name, url string, content fyne.CanvasObject) fyne.CanvasObject {
	dot := newDotWidget(dotColor)
	nameLabel := widget.NewRichText(&widget.TextSegment{
		Text: name,
		Style: widget.RichTextStyle{
			TextStyle: fyne.TextStyle{Bold: true},
			SizeName:  theme.SizeNameSubHeadingText,
		},
	})
	urlLabel := widget.NewLabel(url)
	titleRow := container.NewBorder(nil, nil, container.NewCenter(dot), nil, nameLabel)
	return widget.NewCard("", "", container.NewVBox(titleRow, urlLabel, content))
}

// EnginesTab 测绘引擎配置标签页
type EnginesTab struct {
	cfg    *config.Config
	window fyne.Window
}

// NewEnginesTab 创建测绘引擎配置标签页
func NewEnginesTab(cfg *config.Config, window fyne.Window) *EnginesTab {
	return &EnginesTab{cfg: cfg, window: window}
}

// makeKeyEntry 创建带外置显示/隐藏切换按钮的密码输入框
// 避免内置 PasswordEntry 的光标位置偏移问题
func makeKeyEntry(placeholder, initVal string) (*widget.Entry, fyne.CanvasObject) {
	entry := widget.NewEntry()
	entry.Password = true
	entry.SetPlaceHolder(placeholder)
	if initVal != "" {
		entry.SetText(initVal)
	}
	entry.Refresh()

	// 外置显示/隐藏切换按钮（不影响文本区域宽度，光标定位准确）
	showBtn := widget.NewButtonWithIcon("", theme.VisibilityIcon(), nil)
	showBtn.OnTapped = func() {
		entry.Password = !entry.Password
		entry.Refresh()
		if entry.Password {
			showBtn.SetIcon(theme.VisibilityIcon())
		} else {
			showBtn.SetIcon(theme.VisibilityOffIcon())
		}
	}

	row := container.NewBorder(nil, nil, nil, showBtn, entry)
	return entry, row
}

// Build 构建测绘引擎配置界面
func (e *EnginesTab) Build() fyne.CanvasObject {

	// ── Fofa ──
	fofaEmailEntry := widget.NewEntry()
	fofaEmailEntry.SetText(e.cfg.FofaEmail)
	fofaEmailEntry.SetPlaceHolder("可选，部分账户需要填写")

	fofaKeyEntry, fofaKeyRow := makeKeyEntry("Fofa API Key", e.cfg.FofaKey)

	fofaCard := buildEngineCard(
		color.NRGBA{R: 0x00, G: 0x78, B: 0xFF, A: 0xFF}, // 蓝色
		"Fofa", "https://fofa.info",
		widget.NewForm(
			widget.NewFormItem("邮箱(可选):", fofaEmailEntry),
			widget.NewFormItem("API Key:", fofaKeyRow),
		),
	)

	// ── Shodan ──
	shodanKeyEntry, shodanKeyRow := makeKeyEntry("Shodan API Key", e.cfg.ShodanKey)

	shodanCard := buildEngineCard(
		color.NRGBA{R: 0xE5, G: 0x39, B: 0x35, A: 0xFF}, // 红色
		"Shodan", "https://www.shodan.io",
		widget.NewForm(
			widget.NewFormItem("API Key:", shodanKeyRow),
		),
	)

	// ── Hunter (鹰图) ──
	hunterKeyEntry, hunterKeyRow := makeKeyEntry("Hunter API Key", e.cfg.HunterKey)

	hunterCard := buildEngineCard(
		color.NRGBA{R: 0xFF, G: 0xC1, B: 0x07, A: 0xFF}, // 黄色
		"Hunter (鹰图)", "https://hunter.qianxin.com",
		widget.NewForm(
			widget.NewFormItem("API Key:", hunterKeyRow),
		),
	)

	// ── Quake (360) ──
	quakeKeyEntry, quakeKeyRow := makeKeyEntry("Quake API Key", e.cfg.QuakeKey)

	quakeCard := buildEngineCard(
		color.NRGBA{R: 0x4C, G: 0xAF, B: 0x50, A: 0xFF}, // 绿色
		"Quake (360)", "https://quake.360.net",
		widget.NewForm(
			widget.NewFormItem("API Key:", quakeKeyRow),
		),
	)

	// ── ZoomEye ──
	zoomeyeKeyEntry, zoomeyeKeyRow := makeKeyEntry("ZoomEye API Key", e.cfg.ZoomEyeKey)

	zoomeyeCard := buildEngineCard(
		color.NRGBA{R: 0xE8, G: 0xE8, B: 0xE8, A: 0xFF}, // 白/浅灰
		"ZoomEye", "https://www.zoomeye.org",
		widget.NewForm(
			widget.NewFormItem("API Key:", zoomeyeKeyRow),
		),
	)

	// ── 保存按钮 ──
	saveBtn := widget.NewButton("💾 保存所有引擎配置", func() {
		e.cfg.FofaEmail = strings.TrimSpace(fofaEmailEntry.Text)
		e.cfg.FofaKey = strings.TrimSpace(fofaKeyEntry.Text)
		e.cfg.ShodanKey = strings.TrimSpace(shodanKeyEntry.Text)
		e.cfg.HunterKey = strings.TrimSpace(hunterKeyEntry.Text)
		e.cfg.QuakeKey = strings.TrimSpace(quakeKeyEntry.Text)
		e.cfg.ZoomEyeKey = strings.TrimSpace(zoomeyeKeyEntry.Text)

		if err := e.cfg.Save(); err != nil {
			dialog.ShowError(fmt.Errorf("保存失败: %v", err), e.window)
			return
		}
		dialog.ShowInformation("保存成功", "测绘引擎配置已保存", e.window)
	})

	statusLabel := widget.NewLabel("配置说明：填入对应平台的 API Key 后保存，在【扫描目标】页添加目标时即可选择使用这些引擎自动发现子域名。")
	statusLabel.Wrapping = fyne.TextWrapWord

	leftCol := container.NewVBox(fofaCard, hunterCard, zoomeyeCard)
	rightCol := container.NewVBox(shodanCard, quakeCard)
	engineGrid := container.NewGridWithColumns(2, leftCol, rightCol)

	return container.NewVBox(
		container.NewPadded(statusLabel),
		widget.NewSeparator(),
		container.NewPadded(engineGrid),
		widget.NewSeparator(),
		container.NewPadded(saveBtn),
	)
}
