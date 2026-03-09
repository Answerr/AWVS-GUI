package ui

import (
	"awvs-client/api"
	"awvs-client/config"
	"bufio"
	"context"
	"fmt"
	"image/color"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	nativeDlg "github.com/sqweek/dialog"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// TargetsTab 扫描目标管理标签页
type TargetsTab struct {
	client      *api.Client
	cfg         *config.Config
	window      fyne.Window
	mu          sync.RWMutex // 保护 targets 切片的并发读写
	targets     []api.Target
	table        *widget.Table
	selectedRows map[int]bool // 多选支持
	selectAllBtn *widget.Button
	statusLabel  *widget.Label
	countLabel  *widget.Label
	// 导入控制
	importing    bool               // 是否正在导入
	cancelImport context.CancelFunc // 取消导入
	importBtn    *widget.Button     // 导入/取消 切换按钮（在Build中赋值）
	// 测绘引擎探测控制
	cancelEngineDiscover context.CancelFunc // 取消测绘引擎子域名添加
	engCancelBtn         *widget.Button     // 测绘引擎取消按钮
}

// NewTargetsTab 创建扫描目标标签页
func NewTargetsTab(client *api.Client, window fyne.Window, cfg *config.Config) *TargetsTab {
	return &TargetsTab{client: client, window: window, cfg: cfg, selectedRows: make(map[int]bool)}
}

// normalizeURL 将各种域名格式补全为带协议的 URL
func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "http://" + raw
	}
	return raw
}

// fixWindowsPath 修正 fyne URI 返回的 Windows 路径（/C:/... → C:\...）
func fixWindowsPath(uriPath string) string {
	if len(uriPath) >= 3 && uriPath[0] == '/' && uriPath[2] == ':' {
		return strings.ReplaceAll(uriPath[1:], "/", "\\")
	}
	return uriPath
}

// Build 构建扫描目标标签页界面
func (t *TargetsTab) Build() fyne.CanvasObject {
	t.statusLabel = widget.NewLabel("就绪")
	t.countLabel = widget.NewLabel("共 0 个目标")

	// ── 单个 URL 添加区 ──
	urlEntry := widget.NewEntry()
	urlEntry.SetPlaceHolder("baidu.com 或 http://example.com 或 https://example.com")

	descEntry := widget.NewEntry()
	descEntry.SetPlaceHolder("目标描述（可选）")

	// ── 测绘引擎内联选择（勾选主选项后展示具体引擎复选框）──
	fofaSub := widget.NewCheck("Fofa", nil)
	shodanSub := widget.NewCheck("Shodan", nil)
	hunterSub := widget.NewCheck("Hunter", nil)
	quakeSub := widget.NewCheck("Quake", nil)
	zoomeyeSub := widget.NewCheck("ZoomEye", nil)
	// engineRow 前置声明（实际创建在 inputRow 之后，但回调中需要引用）
	var engineRow *fyne.Container

	engineSubdomainCheck := widget.NewCheck("🌐 自动扫描子域名（通过测绘引擎发现）", func(checked bool) {
		if checked {
			// 根据已配置的 Key 启用/禁用对应引擎复选框
			cfg := t.cfg
			setupEngCheck := func(chk *widget.Check, name string, hasKey bool) {
				if hasKey {
					chk.Enable()
					chk.SetText(name)
					chk.SetChecked(true) // 默认勾选已配置的引擎
				} else {
					chk.Disable()
					chk.SetText(name + "（未配置）")
					chk.SetChecked(false)
				}
			}
			setupEngCheck(fofaSub, "Fofa", cfg.FofaKey != "") // 邮箱可选
			setupEngCheck(shodanSub, "Shodan", cfg.ShodanKey != "")
			setupEngCheck(hunterSub, "Hunter", cfg.HunterKey != "")
			setupEngCheck(quakeSub, "Quake", cfg.QuakeKey != "")
			setupEngCheck(zoomeyeSub, "ZoomEye", cfg.ZoomEyeKey != "")
			engineRow.Show()
		} else {
			engineRow.Hide()
		}
	})

	addBtn := widget.NewButton("➕ 添加目标", func() {
		rawURL := strings.TrimSpace(urlEntry.Text)
		if rawURL == "" {
			dialog.ShowError(fmt.Errorf("请输入目标 URL 或域名"), t.window)
			return
		}
		if t.client == nil {
			dialog.ShowError(fmt.Errorf("请先在【系统配置】中配置 AWVS 连接信息"), t.window)
			return
		}
		targetURL := normalizeURL(rawURL)

		// 收集选中的测绘引擎
		var selectedEngines []string
		if engineSubdomainCheck.Checked {
			if fofaSub.Checked {
				selectedEngines = append(selectedEngines, "Fofa")
			}
			if shodanSub.Checked {
				selectedEngines = append(selectedEngines, "Shodan")
			}
			if hunterSub.Checked {
				selectedEngines = append(selectedEngines, "Hunter")
			}
			if quakeSub.Checked {
				selectedEngines = append(selectedEngines, "Quake")
			}
			if zoomeyeSub.Checked {
				selectedEngines = append(selectedEngines, "ZoomEye")
			}
		}

		go func() {
			t.setStatus("⏳ 正在添加目标: " + targetURL)
			mainTarget, err := t.client.AddTarget(targetURL, descEntry.Text)
			if err != nil {
				t.setStatus("❌ 添加失败: " + err.Error())
				dialog.ShowError(err, t.window)
				return
			}
			t.appendTargets([]api.Target{*mainTarget})
			urlEntry.SetText("")
			descEntry.SetText("")
			t.setStatus("✅ 添加成功: " + targetURL)

			if len(selectedEngines) > 0 {
				ctx, cancel := context.WithCancel(context.Background())
				t.cancelEngineDiscover = cancel
				t.engCancelBtn.Show()
				t.discoverFromEngines(ctx, rawURL, selectedEngines)
				t.cancelEngineDiscover = nil
				t.engCancelBtn.Hide()
			}
		}()
	})

	// ── 批量导入区（支持取消）──
	importPathEntry := widget.NewEntry()
	importPathEntry.SetPlaceHolder("直接输入 TXT 文件路径，如: D:\\urls.txt")

	browseBtn := widget.NewButton("浏览...", func() {
		// 在 goroutine 中调用原生 Windows 文件对话框（阻塞调用不能在主线程）
		go func() {
			filename, err := nativeDlg.File().
				Title("选择 URL 列表文件").
				Filter("文本文件 (*.txt)", "txt").
				Load()
			if err != nil {
				return // 用户取消或出错，静默忽略
			}
			importPathEntry.SetText(filename)
		}()
	})

	// 导入/取消 切换按钮
	t.importBtn = widget.NewButton("📂 导入", nil)
	t.importBtn.OnTapped = func() {
		if t.importing {
			// 正在导入 → 取消
			if t.cancelImport != nil {
				t.cancelImport()
			}
			return
		}
		// 未在导入 → 开始导入
		path := strings.TrimSpace(importPathEntry.Text)
		if path == "" {
			dialog.ShowError(fmt.Errorf("请输入或选择 TXT 文件路径"), t.window)
			return
		}
		if t.client == nil {
			dialog.ShowError(fmt.Errorf("请先在【系统配置】中配置 AWVS 连接信息"), t.window)
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		t.cancelImport = cancel
		t.importing = true
		t.importBtn.SetText("❌ 取消导入")
		go func() {
			defer func() {
				t.importing = false
				t.cancelImport = nil
				t.importBtn.SetText("📂 导入")
			}()
			t.importFromFile(ctx, path)
		}()
	}

	// ── 扫描配置选择 ──
	profileNames := api.GetProfileNames()
	profileSelect := widget.NewSelect(profileNames, nil)
	profileSelect.SetSelected("完整扫描")

	// ── 操作按钮 ──
	// 全选/取消全选
	t.selectAllBtn = widget.NewButton("全选", func() {
		t.mu.RLock()
		n := len(t.targets)
		t.mu.RUnlock()
		allSel := len(t.selectedRows) > 0 && len(t.selectedRows) == n
		if allSel {
			t.selectedRows = make(map[int]bool)
			t.selectAllBtn.SetText("全选")
		} else {
			t.mu.RLock()
			for i := range t.targets {
				t.selectedRows[i] = true
			}
			t.mu.RUnlock()
			t.selectAllBtn.SetText("取消全选")
		}
		t.table.Refresh()
	})

	// 复制选中行 URL 到剪贴板
	copyURLBtn := widget.NewButton("📋 复制URL", func() {
		t.mu.RLock()
		var urls []string
		for idx := range t.selectedRows {
			if t.selectedRows[idx] && idx < len(t.targets) {
				urls = append(urls, t.targets[idx].Address)
			}
		}
		t.mu.RUnlock()
		if len(urls) == 0 {
			dialog.ShowError(fmt.Errorf("请先勾选目标行"), t.window)
			return
		}
		t.window.Clipboard().SetContent(strings.Join(urls, "\n"))
		t.setStatus(fmt.Sprintf("✅ 已复制 %d 个 URL 到剪贴板", len(urls)))
	})

	scanSelectedBtn := widget.NewButton("▶ 扫描选中", func() {
		t.mu.RLock()
		var targets []api.Target
		for idx := range t.selectedRows {
			if t.selectedRows[idx] && idx < len(t.targets) {
				targets = append(targets, t.targets[idx])
			}
		}
		t.mu.RUnlock()
		if len(targets) == 0 {
			dialog.ShowError(fmt.Errorf("请先勾选要扫描的目标行"), t.window)
			return
		}
		if t.client == nil {
			dialog.ShowError(fmt.Errorf("请先配置 AWVS 连接"), t.window)
			return
		}
		profileID := api.GetProfileID(profileSelect.Selected)
		go func() {
			successCount := 0
			for _, target := range targets {
				t.setStatus(fmt.Sprintf("⏳ 提交扫描: %s", target.Address))
				if _, err := t.client.StartScan(target.TargetID, profileID); err == nil {
					successCount++
				}
			}
			t.setStatus(fmt.Sprintf("✅ 已提交 %d 个扫描任务", successCount))
		}()
	})

	scanAllBtn := widget.NewButton("▶▶ 扫描全部", func() {
		t.mu.RLock()
		n := len(t.targets)
		targets := make([]api.Target, n)
		copy(targets, t.targets)
		t.mu.RUnlock()

		if n == 0 {
			dialog.ShowError(fmt.Errorf("目标列表为空，请先添加目标"), t.window)
			return
		}
		if t.client == nil {
			dialog.ShowError(fmt.Errorf("请先配置 AWVS 连接"), t.window)
			return
		}
		profileID := api.GetProfileID(profileSelect.Selected)
		dialog.ShowConfirm("确认批量扫描",
			fmt.Sprintf("确定要扫描全部 %d 个目标吗？\n扫描配置: %s", n, profileSelect.Selected),
			func(confirmed bool) {
				if !confirmed {
					return
				}
				go func() {
					successCount := 0
					for _, target := range targets {
						t.setStatus(fmt.Sprintf("⏳ 提交中: %s", target.Address))
						if _, err := t.client.StartScan(target.TargetID, profileID); err == nil {
							successCount++
						}
					}
					t.setStatus(fmt.Sprintf("✅ 已提交 %d / %d 个扫描任务，请切换到【扫描任务】查看进度", successCount, n))
					dialog.ShowInformation("批量扫描已提交",
						fmt.Sprintf("成功提交 %d 个扫描任务", successCount), t.window)
				}()
			},
			t.window,
		)
	})

	deleteBtn := widget.NewButton("🗑 删除选中", func() {
		t.mu.RLock()
		var toDelete []api.Target
		for idx := range t.selectedRows {
			if t.selectedRows[idx] && idx < len(t.targets) {
				toDelete = append(toDelete, t.targets[idx])
			}
		}
		t.mu.RUnlock()
		if len(toDelete) == 0 {
			dialog.ShowError(fmt.Errorf("请先勾选要删除的目标行"), t.window)
			return
		}
		if t.client == nil {
			return
		}
		dialog.ShowConfirm("确认删除",
			fmt.Sprintf("确定删除选中的 %d 个目标？", len(toDelete)),
			func(confirmed bool) {
				if confirmed {
					go func() {
						for _, target := range toDelete {
							_ = t.client.DeleteTarget(target.TargetID)
						}
						t.refresh(context.Background())
					}()
				}
			},
			t.window,
		)
	})

	// 清空全部：立即清除本地数据（UI立即响应），再后台并发删除 AWVS 记录
	clearAllBtn := widget.NewButton("🧹 清空全部", func() {
		t.mu.RLock()
		n := len(t.targets)
		if n == 0 {
			t.mu.RUnlock()
			return
		}
		// 保存所有 target ID 用于后台删除
		ids := make([]string, n)
		for i, tg := range t.targets {
			ids[i] = tg.TargetID
		}
		t.mu.RUnlock()

		if t.client == nil {
			return
		}

		dialog.ShowConfirm("⚠️ 确认清空",
			fmt.Sprintf("确定要清空全部 %d 个目标吗？\n（将立即从列表移除，并后台从 AWVS 删除）", n),
			func(confirmed bool) {
				if !confirmed {
					return
				}
				// ★ 立即清空本地数据，UI 无需等待
				t.mu.Lock()
				t.targets = nil
				t.mu.Unlock()
				t.selectedRows = make(map[int]bool)
				if t.selectAllBtn != nil {
					t.selectAllBtn.SetText("全选")
				}
				t.table.Refresh()
				t.updateCount()
				t.setStatus(fmt.Sprintf("⏳ 正在后台从 AWVS 删除 %d 个目标...", n))

				// 后台并发删除（5个并发）
				go func() {
					const concurrency = 5
					sem := make(chan struct{}, concurrency)
					var wg sync.WaitGroup
					var success int32

					for _, id := range ids {
						wg.Add(1)
						sem <- struct{}{}
						go func(tid string) {
							defer wg.Done()
							defer func() { <-sem }()
							if err := t.client.DeleteTarget(tid); err == nil {
								atomic.AddInt32(&success, 1)
							}
						}(id)
					}
					wg.Wait()
					t.setStatus(fmt.Sprintf("✅ 已从 AWVS 删除 %d / %d 个目标", atomic.LoadInt32(&success), n))
				}()
			},
			t.window,
		)
	})

	refreshBtn := widget.NewButton("🔄 刷新", func() {
		go t.refresh(context.Background())
	})

	// ── 目标列表表格（✓ 复选列 + 多选支持）──
	columns := []string{"✓", "序号", "目标 URL（点击查看完整）", "描述", "最后扫描时间"}
	colWidths := []float32{40, 55, 380, 175, 130}

	t.table = widget.NewTable(
		func() (int, int) {
			t.mu.RLock()
			n := len(t.targets)
			t.mu.RUnlock()
			return n + 1, len(columns)
		},
		func() fyne.CanvasObject {
			return newCursorLabel()
		},
		func(id widget.TableCellID, cell fyne.CanvasObject) {
			c := cell.(*cursorLabel)
			label := c.label
			if id.Row == 0 {
				c.isLink = false
				label.TextStyle = fyne.TextStyle{Bold: true}
				label.SetText(columns[id.Col])
				return
			}
			row := id.Row - 1
			t.mu.RLock()
			if row >= len(t.targets) {
				t.mu.RUnlock()
				c.isLink = false
				label.SetText("")
				return
			}
			target := t.targets[row]
			t.mu.RUnlock()
			// 只有数据行的 URL 列显示手型光标
			c.isLink = (id.Col == 2)
			label.TextStyle = fyne.TextStyle{}
			switch id.Col {
			case 0: // 选中标记
				if t.selectedRows[row] {
					label.SetText("✓")
				} else {
					label.SetText("")
				}
			case 1:
				label.SetText(fmt.Sprintf("%d", row+1))
			case 2:
				label.SetText(target.Address)
			case 3:
				label.SetText(target.Description)
			case 4:
				if target.LastScanDate != "" {
					d := target.LastScanDate
					if len(d) > 10 {
						d = d[:10]
					}
					label.SetText(d)
				} else {
					label.SetText("未扫描")
				}
			}
		},
	)

	for i, w := range colWidths {
		t.table.SetColumnWidth(i, w)
	}
	// ★ 点击行事件
	// - 只有点击 col=0（✓列）才切换选中
	// - 点击 col=2（URL列）弹窗显示完整URL（可选中/复制）
	// - 每次处理后立即 Unselect，确保下次点击同一格仍能触发
	t.table.OnSelected = func(id widget.TableCellID) {
		// 表头行不处理
		t.table.Unselect(id) // ★ 立即重置 fyne 内部选中，下次点击才能再触发
		if id.Row <= 0 {
			return
		}
		row := id.Row - 1
		t.mu.RLock()
		if row >= len(t.targets) {
			t.mu.RUnlock()
			return
		}
		target := t.targets[row]
		t.mu.RUnlock()

		switch id.Col {
		case 0: // ✓ 列：切换多选状态
			t.selectedRows[row] = !t.selectedRows[row]
			t.table.Refresh()
			count := 0
			for _, v := range t.selectedRows {
				if v {
					count++
				}
			}
			t.mu.RLock()
			n := len(t.targets)
			t.mu.RUnlock()
			if count > 0 && count == n {
				t.selectAllBtn.SetText("取消全选")
			} else {
				t.selectAllBtn.SetText("全选")
			}
			t.setStatus(fmt.Sprintf("已选中 %d / %d 个目标", count, n))

		case 2: // URL 列：弹窗展示完整 URL（可选中复制）
			t.showURLDetail(target.Address)

		default:
			t.setStatus(fmt.Sprintf("目标: %s", target.Address))
		}
	}

	// ── 布局组装 ──
	// 引擎选择行（独立于输入网格，避免展开时撑大布局）
	engineRow = container.NewHBox(
		widget.NewLabel("      选择引擎:"),
		fofaSub, shodanSub, hunterSub, quakeSub, zoomeyeSub,
	)
	engineRow.Hide()

	inputRow := container.NewGridWithColumns(3,
		container.NewBorder(nil, nil, widget.NewLabel("URL:"), nil, urlEntry),
		container.NewBorder(nil, nil, widget.NewLabel("描述:"), nil, descEntry),
		container.NewVBox(addBtn, engineSubdomainCheck),
	)

	importRow := container.NewBorder(
		nil, nil,
		widget.NewLabel("批量导入:"),
		container.NewHBox(browseBtn, t.importBtn),
		importPathEntry,
	)

	actionRow := container.NewHBox(
		widget.NewLabel("扫描配置:"),
		profileSelect,
		t.selectAllBtn,
		scanSelectedBtn,
		scanAllBtn,
		copyURLBtn,
		layout.NewSpacer(),
		deleteBtn,
		clearAllBtn,
		refreshBtn,
	)

	topSection := container.NewVBox(
		container.NewPadded(inputRow),
		engineRow, // 引擎选择行（勾选后展开，不影响上方布局）
		widget.NewSeparator(),
		container.NewPadded(importRow),
		widget.NewSeparator(),
		container.NewPadded(actionRow),
		widget.NewSeparator(),
	)

	// 测绘引擎取消按钮（探测中显示，平时隐藏）
	t.engCancelBtn = widget.NewButton("⏹ 取消子域名添加", func() {
		if t.cancelEngineDiscover != nil {
			t.cancelEngineDiscover()
		}
	})
	t.engCancelBtn.Hide()

	statusBar := container.NewHBox(
		widget.NewLabel("状态:"),
		t.statusLabel,
		t.engCancelBtn,
		layout.NewSpacer(),
		t.countLabel,
	)

	if t.client != nil {
		go t.refresh(context.Background())
	}

	return container.NewBorder(topSection, statusBar, nil, nil, t.table)
}

// ─────────────────── 工具方法 ───────────────────

func (t *TargetsTab) setStatus(msg string) { t.statusLabel.SetText(msg) }

func (t *TargetsTab) updateCount() {
	t.mu.RLock()
	n := len(t.targets)
	t.mu.RUnlock()
	t.countLabel.SetText(fmt.Sprintf("共 %d 个目标", n))
}

// appendTargets 线程安全地追加目标并刷新表格
func (t *TargetsTab) appendTargets(newTargets []api.Target) {
	if len(newTargets) == 0 {
		return
	}
	t.mu.Lock()
	t.targets = append(t.targets, newTargets...)
	t.mu.Unlock()
	t.table.Refresh()
	t.updateCount()
}

// scrollToTop 让表格滚动回第一行
func (t *TargetsTab) scrollToTop() {
	t.mu.RLock()
	n := len(t.targets)
	t.mu.RUnlock()
	t.table.Refresh()
	if n > 0 {
		t.table.ScrollTo(widget.TableCellID{Row: 1, Col: 0})
	}
}

// ─────────────────── 导入逻辑 ───────────────────

// importFromFile 从文件路径读取 URL 列表并批量导入
func (t *TargetsTab) importFromFile(ctx context.Context, path string) {
	file, err := os.Open(path)
	if err != nil {
		dialog.ShowError(fmt.Errorf("打开文件失败: %v\n路径: %s", err, path), t.window)
		return
	}
	defer file.Close()
	t.importFromReader(ctx, file)
}

// importFromReader 从 io.Reader 读取 URL 并批量导入，支持取消
func (t *TargetsTab) importFromReader(ctx context.Context, r io.Reader) {
	// 先解析所有 URL
	var urls []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if u := normalizeURL(line); u != "" {
			urls = append(urls, u)
		}
	}

	if len(urls) == 0 {
		dialog.ShowError(
			fmt.Errorf("文件中未找到有效 URL\n\n格式说明：\n  每行一个目标\n  支持: baidu.com / http://... / https://...\n  # 开头为注释行"),
			t.window,
		)
		return
	}

	t.setStatus(fmt.Sprintf("⏳ 准备导入 %d 个目标，可点击按钮取消...", len(urls)))

	successCount, failCount := 0, 0
	const refreshEvery = 20 // 每成功 N 个才刷新一次 UI，避免刷新过于频繁

	var batch []api.Target

	for i, u := range urls {
		// 检查取消信号
		select {
		case <-ctx.Done():
			// 将剩余 batch 追加
			t.appendTargets(batch)
			t.scrollToTop()
			msg := fmt.Sprintf("⏹ 导入已取消  ✅ 成功 %d 个  ❌ 失败 %d 个", successCount, failCount)
			t.setStatus(msg)
			return
		default:
		}

		t.setStatus(fmt.Sprintf("⏳ 导入中 [%d/%d]: %s", i+1, len(urls), u))

		target, err := t.client.AddTarget(u, "批量导入")
		if err != nil {
			failCount++
			continue
		}
		batch = append(batch, *target)
		successCount++

		// 批量追加并刷新（避免每次都刷新导致 UI 抖动）
		if len(batch) >= refreshEvery {
			t.appendTargets(batch)
			batch = nil
		}
	}

	// 追加剩余
	t.appendTargets(batch)
	t.scrollToTop()

	msg := fmt.Sprintf("✅ 导入完成  成功 %d 个  ❌ 失败 %d 个", successCount, failCount)
	t.setStatus(msg)
	dialog.ShowInformation("批量导入完成", msg, t.window)
}

// ─────────────────── 刷新目标列表 ───────────────────

// refresh 从 AWVS 重新获取目标列表（线程安全）
func (t *TargetsTab) refresh(ctx context.Context) {
	if t.client == nil {
		t.setStatus("未配置 AWVS 连接，请进入【系统配置】")
		return
	}
	t.setStatus("⏳ 正在刷新目标列表...")

	targets, err := t.client.GetTargets()
	if err != nil {
		t.setStatus("❌ 刷新失败: " + err.Error())
		return
	}

	t.mu.Lock()
	t.targets = targets
	t.mu.Unlock()

	t.selectedRows = make(map[int]bool)
	if t.selectAllBtn != nil {
		t.selectAllBtn.SetText("全选")
	}
	t.table.Refresh()
	t.updateCount()
	t.scrollToTop()
	t.setStatus(fmt.Sprintf("✅ 刷新成功，共 %d 个目标", len(targets)))
}

// showVulnsForTarget 获取选中目标的漏洞并弹窗展示
func (t *TargetsTab) showVulnsForTarget(target api.Target) {
	t.setStatus(fmt.Sprintf("⏳ 正在获取 %s 的漏洞数据...", target.Address))
	vulns, err := t.client.GetVulnerabilitiesByTarget(target.TargetID)
	if err != nil {
		t.setStatus("❌ 获取漏洞失败: " + err.Error())
		dialog.ShowError(fmt.Errorf("获取漏洞列表失败: %v", err), t.window)
		return
	}
	if len(vulns) == 0 {
		t.setStatus("ℹ️ 该目标暂无漏洞记录")
		dialog.ShowInformation("漏洞详情",
			fmt.Sprintf("目标 %s 暂无漏洞记录\n可能原因：扫描未完成 或 未发现漏洞", target.Address),
			t.window)
		return
	}
	t.setStatus(fmt.Sprintf("✅ 获取到 %d 个漏洞", len(vulns)))
	// 传入 t.client 以支持点击漏洞名称查看详情
	showVulnDialog(target.Address, vulns, t.client, t.window)
}

// showURLDetail 弹窗显示完整 URL，支持文本选中和复制
func (t *TargetsTab) showURLDetail(addr string) {
	entry := widget.NewEntry()
	entry.SetText(addr)
	entry.MultiLine = false

	copyBtn := widget.NewButton("📋 复制", func() {
		t.window.Clipboard().SetContent(addr)
		t.setStatus("✅ 已复制到剪贴板: " + addr)
	})

	content := container.NewBorder(nil, nil, nil, copyBtn, entry)
	d := dialog.NewCustom("🔗 完整 URL（可选中复制）", "关闭",
		container.NewPadded(content), t.window)
	d.Resize(fyne.NewSize(780, 130))
	d.Show()
}

// SetClient 更新客户端并刷新数据
func (t *TargetsTab) SetClient(client *api.Client) {
	t.client = client
	go t.refresh(context.Background())
}

// discoverFromEngines 调用选中的测绘引擎发现子域名并自动添加到 AWVS
// 支持去重（跳过已存在目标）和取消（通过 ctx）
func (t *TargetsTab) discoverFromEngines(ctx context.Context, rawDomain string, engines []string) {
	domain := api.ExtractApexDomainPublic(rawDomain)
	if domain == "" {
		return
	}

	// ── 构建已有目标 URL 集合，用于去重 ──
	existingHosts := make(map[string]bool)
	t.mu.RLock()
	for _, target := range t.targets {
		addr := strings.ToLower(strings.TrimRight(target.Address, "/"))
		existingHosts[addr] = true
		// 同时记录不带协议头的版本
		h := strings.TrimPrefix(addr, "http://")
		h = strings.TrimPrefix(h, "https://")
		h = strings.TrimRight(h, "/")
		existingHosts[h] = true
	}
	t.mu.RUnlock()

	cfg := t.cfg
	allSubs := make(map[string]bool)

	// ── 逐个引擎查询 ──
	for _, eng := range engines {
		// 检查取消
		select {
		case <-ctx.Done():
			t.setStatus("⏹ 子域名探测已取消")
			return
		default:
		}

		t.setStatus(fmt.Sprintf("🌐 正在通过 %s 发现子域名...", eng))

		var subs []string
		var err error
		switch eng {
		case "Fofa":
			subs, err = api.DiscoverFromFofa(domain, cfg.FofaEmail, cfg.FofaKey)
		case "Shodan":
			subs, err = api.DiscoverFromShodan(domain, cfg.ShodanKey)
		case "Hunter":
			subs, err = api.DiscoverFromHunter(domain, cfg.HunterKey)
		case "Quake":
			subs, err = api.DiscoverFromQuake(domain, cfg.QuakeKey)
		case "ZoomEye":
			subs, err = api.DiscoverFromZoomEye(domain, cfg.ZoomEyeKey)
		}

		if err != nil {
			t.setStatus(fmt.Sprintf("⚠️ %s 查询失败: %v", eng, err))
			dialog.ShowError(fmt.Errorf("%s 子域名查询失败: %v", eng, err), t.window)
			continue
		}
		t.setStatus(fmt.Sprintf("✅ %s 发现 %d 个子域名", eng, len(subs)))

		for _, s := range subs {
			allSubs[s] = true
		}
	}

	if len(allSubs) == 0 {
		t.setStatus("ℹ️ 测绘引擎未发现任何子域名")
		dialog.ShowInformation("测绘引擎查询结果",
			"所有引擎均未发现子域名\n\n可能原因：\n• API Key 无效或已过期\n• 该域名在平台无记录\n• 网络连接问题",
			t.window)
		return
	}

	// ── 去重：过滤掉已存在于 AWVS 的目标 ──
	var newSubs []string
	duplicateCount := 0
	for sub := range allSubs {
		if existingHosts[sub] || existingHosts["http://"+sub] || existingHosts["https://"+sub] {
			duplicateCount++
			continue
		}
		newSubs = append(newSubs, sub)
	}

	// ── 展示确认弹窗，让用户决定是否添加 ──
	t.setStatus(fmt.Sprintf("✅ 发现 %d 个子域名，去重后 %d 个新目标，等待确认...", len(allSubs), len(newSubs)))

	confirmMsg := fmt.Sprintf(
		"测绘引擎探测完成！\n\n"+
			"  🔍 共发现子域名:    %d 个\n"+
			"  🔄 已存在(重复):    %d 个\n"+
			"  ✅ 待添加新目标:    %d 个\n\n"+
			"是否确认将 %d 个新子域名添加到 AWVS 扫描目标？",
		len(allSubs), duplicateCount, len(newSubs), len(newSubs),
	)

	if len(newSubs) == 0 {
		dialog.ShowInformation("探测结果",
			fmt.Sprintf("共发现 %d 个子域名，但全部已存在于目标列表\n无需重复添加", len(allSubs)),
			t.window)
		t.setStatus(fmt.Sprintf("ℹ️ 发现 %d 个，全部已存在，无需添加", len(allSubs)))
		return
	}

	// 用 channel 在 goroutine 中等待用户点击确认/取消
	confirmed := make(chan bool, 1)
	dialog.ShowConfirm("📋 确认添加子域名", confirmMsg,
		func(ok bool) { confirmed <- ok },
		t.window,
	)

	// 等待用户响应
	select {
	case ok := <-confirmed:
		if !ok {
			t.setStatus("❌ 已取消，未添加任何子域名")
			return
		}
	case <-ctx.Done():
		t.setStatus("⏹ 已取消")
		return
	}

	// ── 确认后批量添加（支持取消）──
	t.setStatus(fmt.Sprintf("⏳ 开始添加 %d 个新子域名...", len(newSubs)))
	var batch []api.Target
	successCount, failCount := 0, 0
	total := len(newSubs)

	for i, sub := range newSubs {
		select {
		case <-ctx.Done():
			t.appendTargets(batch)
			msg := fmt.Sprintf("⏹ 已取消  ✅ 已添加 %d 个  ❌ 失败 %d 个", successCount, failCount)
			t.setStatus(msg)
			dialog.ShowInformation("添加已取消", msg, t.window)
			return
		default:
		}

		subURL := "http://" + sub
		t.setStatus(fmt.Sprintf("⏳ 添加中 [%d/%d]: %s", i+1, total, sub))

		target, err := t.client.AddTarget(subURL, "测绘引擎发现")
		if err != nil {
			failCount++
			continue
		}
		batch = append(batch, *target)
		successCount++
		if len(batch) >= 20 {
			t.appendTargets(batch)
			batch = nil
		}
	}
	t.appendTargets(batch)

	dupNote := ""
	if duplicateCount > 0 {
		dupNote = fmt.Sprintf("\n（已跳过 %d 个重复目标）", duplicateCount)
	}
	msg := fmt.Sprintf("添加完成：✅ 成功 %d 个  ❌ 失败 %d 个%s", successCount, failCount, dupNote)
	t.setStatus(msg)
	dialog.ShowInformation("测绘引擎子域名添加完成", msg, t.window)
}

// 消除 color 包未使用的编译错误
var _ color.Color = color.Transparent
