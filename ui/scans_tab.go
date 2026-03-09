package ui

import (
	"awvs-client/api"
	"fmt"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// ScansTab 扫描任务监控标签页
type ScansTab struct {
	mu           sync.RWMutex // 保护 scans 和 selectedRows 的并发读写
	client       *api.Client
	window       fyne.Window
	scans        []api.Scan
	table        *widget.Table
	selectedRows map[int]bool
	statusLabel  *widget.Label
	selectAllBtn *widget.Button
}

// NewScansTab 创建扫描任务标签页
func NewScansTab(client *api.Client, window fyne.Window) *ScansTab {
	return &ScansTab{
		client:       client,
		window:       window,
		selectedRows: make(map[int]bool),
	}
}

// formatSeverityCounts 将漏洞统计格式化为 "1严重 2高危 3中危" 形式（跳过零值）
func formatSeverityCounts(c api.SeverityCounts) string {
	var parts []string
	if c.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d严重", c.Critical))
	}
	if c.High > 0 {
		parts = append(parts, fmt.Sprintf("%d高危", c.High))
	}
	if c.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d中危", c.Medium))
	}
	if c.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d低危", c.Low))
	}
	if c.Info > 0 {
		parts = append(parts, fmt.Sprintf("%d信息", c.Info))
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, " ")
}

// Build 构建扫描任务标签页界面
func (s *ScansTab) Build() fyne.CanvasObject {
	s.statusLabel = widget.NewLabel("就绪")

	columns := []string{"✓", "序号", "目标 URL", "扫描配置", "状态", "进度", "漏洞结果"}
	colWidths := []float32{40, 55, 265, 130, 110, 65, 208}

	s.table = widget.NewTable(
		func() (int, int) {
			s.mu.RLock()
			n := len(s.scans)
			s.mu.RUnlock()
			return n + 1, len(columns)
		},
		func() fyne.CanvasObject {
			return newClickableCell()
		},
		func(id widget.TableCellID, cell fyne.CanvasObject) {
			c := cell.(*clickableCell)

			// ── 表头行 ──
			if id.Row == 0 {
				c.isLink = false
				c.richText.Segments = []widget.RichTextSegment{
					&widget.TextSegment{
						Text:  columns[id.Col],
						Style: widget.RichTextStyle{TextStyle: fyne.TextStyle{Bold: true}},
					},
				}
				c.richText.Refresh()
				return
			}

			row := id.Row - 1

			// 加读锁，快照当前行数据后立即释放，避免持锁期间触发渲染死锁
			s.mu.RLock()
			if row >= len(s.scans) {
				s.mu.RUnlock()
				c.isLink = false
				c.richText.Segments = nil
				c.richText.Refresh()
				return
			}
			scan := s.scans[row]
			selected := s.selectedRows[row]
			s.mu.RUnlock()

			c.isLink = (id.Col == 2)

			var text string
			var colorName fyne.ThemeColorName

			switch id.Col {
			case 0:
				if selected {
					text = "✓"
				}
			case 1:
				text = fmt.Sprintf("%d", row+1)
			case 2:
				text = truncateStr(scan.Target.Address, 36)
				colorName = theme.ColorNamePrimary
			case 3:
				text = truncateStr(scan.ProfileName, 18)
			case 4:
				text = scanStatusText(scan.Session.Status)
			case 5:
				text = fmt.Sprintf("%d%%", scan.Session.Progress)
			case 6:
				text = formatSeverityCounts(scan.Session.SeverityCounts)
			}

			seg := &widget.TextSegment{Text: text}
			if colorName != "" {
				seg.Style = widget.RichTextStyle{ColorName: colorName}
			}
			c.richText.Segments = []widget.RichTextSegment{seg}
			c.richText.Refresh()
		},
	)

	for i, w := range colWidths {
		s.table.SetColumnWidth(i, w)
	}

	s.table.OnSelected = func(id widget.TableCellID) {
		if id.Row <= 0 {
			s.table.Unselect(id)
			return
		}
		row := id.Row - 1

		s.mu.RLock()
		if row >= len(s.scans) {
			s.mu.RUnlock()
			s.table.Unselect(id)
			return
		}
		scan := s.scans[row]
		s.mu.RUnlock()

		switch id.Col {
		case 0:
			// ✓ 列：立即切换选中状态
			s.mu.Lock()
			s.selectedRows[row] = !s.selectedRows[row]
			s.mu.Unlock()
			// 必须 Unselect，使下次点击同一格时仍能触发 OnSelected
			s.table.Unselect(id)
			s.table.Refresh()
			s.updateSelectionStatus()
		case 2:
			// URL 列：打开漏洞详情
			s.table.Unselect(id)
			if s.client != nil {
				go s.showVulnsForScan(scan)
			}
		default:
			// 其他列：不触发选中，直接取消高亮
			s.table.Unselect(id)
		}
	}

	// ── 工具栏 ──
	refreshBtn := widget.NewButton("🔄 刷新", func() {
		go s.refresh()
	})

	s.selectAllBtn = widget.NewButton("全选", func() {
		s.toggleSelectAll()
	})

	abortBtn := widget.NewButton("⏹ 终止扫描", func() {
		selected := s.getSelectedScans()
		if len(selected) == 0 {
		dialog.ShowError(fmt.Errorf("请先勾选至少一个扫描任务（点击 ✓ 列选中）"), s.window)
		return
	}
	if s.client == nil {
		return
	}
	dialog.ShowConfirm("确认终止",
			fmt.Sprintf("确定要终止选中的 %d 个扫描任务？", len(selected)),
			func(confirmed bool) {
				if confirmed {
					go func() {
						for _, scan := range selected {
							_ = s.client.AbortScan(scan.ScanID)
						}
						s.setStatus(fmt.Sprintf("✅ 已终止 %d 个扫描任务", len(selected)))
						s.refresh()
					}()
				}
			},
			s.window,
		)
	})

	batchDeleteBtn := widget.NewButton("🗑 批量删除", func() {
		selected := s.getSelectedScans()
		if len(selected) == 0 {
		dialog.ShowError(fmt.Errorf("请先勾选至少一个扫描任务（点击 ✓ 列选中）"), s.window)
		return
	}
	if s.client == nil {
		return
	}
	dialog.ShowConfirm("⚠️ 确认批量删除",
			fmt.Sprintf("确定要删除选中的 %d 个扫描记录？\n此操作不可撤销！", len(selected)),
			func(confirmed bool) {
				if confirmed {
					go func() {
						successCount := 0
						for _, scan := range selected {
							if err := s.client.DeleteScan(scan.ScanID); err == nil {
								successCount++
							}
						}
						s.setStatus(fmt.Sprintf("✅ 已删除 %d 个扫描记录", successCount))
						s.refresh()
					}()
				}
			},
			s.window,
		)
	})

	toolbar := container.NewHBox(
		refreshBtn,
		s.selectAllBtn,
		layout.NewSpacer(),
		abortBtn,
		batchDeleteBtn,
	)

	statusBar := container.NewHBox(
		widget.NewLabel("状态:"),
		s.statusLabel,
		layout.NewSpacer(),
		widget.NewLabel("提示: 点击 ✓ 列选中任务；点击 URL 列查看漏洞"),
	)

	topSection := container.NewVBox(
		container.NewPadded(toolbar),
		widget.NewSeparator(),
	)

	if s.client != nil {
		go s.refresh()
	}

	return container.NewBorder(topSection, statusBar, nil, nil, s.table)
}

// showVulnsForScan 获取指定扫描的目标漏洞并调用通用弹窗展示
func (s *ScansTab) showVulnsForScan(scan api.Scan) {
	s.setStatus(fmt.Sprintf("⏳ 正在获取 %s 的漏洞数据...", scan.Target.Address))

	vulns, err := s.client.GetVulnerabilitiesByTarget(scan.TargetID)
	if err != nil {
		s.setStatus("❌ 获取漏洞失败: " + err.Error())
		dialog.ShowError(fmt.Errorf("获取漏洞列表失败: %v", err), s.window)
		return
	}

	if len(vulns) == 0 {
		s.setStatus("ℹ️ 该扫描目标暂无漏洞记录")
		dialog.ShowInformation("漏洞详情",
			fmt.Sprintf("目标 %s 暂无漏洞记录\n\n可能原因：\n  • 扫描尚未完成\n  • 未发现安全漏洞", scan.Target.Address),
			s.window)
		return
	}

	s.setStatus(fmt.Sprintf("✅ 获取到 %d 个漏洞，正在打开漏洞详情窗口...", len(vulns)))
	showVulnDialog(scan.Target.Address, vulns, s.client, s.window)
}

func (s *ScansTab) getSelectedScans() []api.Scan {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var selected []api.Scan
	for idx, ok := range s.selectedRows {
		if ok && idx < len(s.scans) {
			selected = append(selected, s.scans[idx])
		}
	}
	return selected
}

func (s *ScansTab) toggleSelectAll() {
	s.mu.Lock()
	allSelected := len(s.scans) > 0
	for i := range s.scans {
		if !s.selectedRows[i] {
			allSelected = false
			break
		}
	}
	if allSelected {
		s.selectedRows = make(map[int]bool)
	} else {
		for i := range s.scans {
			s.selectedRows[i] = true
		}
	}
	s.mu.Unlock()

	// 锁释放后再操作 UI，避免死锁
	if allSelected {
		s.selectAllBtn.SetText("全选")
	} else {
		s.selectAllBtn.SetText("取消全选")
	}
	s.table.Refresh()
	s.updateSelectionStatus()
}

func (s *ScansTab) updateSelectionStatus() {
	s.mu.RLock()
	count := 0
	for _, v := range s.selectedRows {
		if v {
			count++
		}
	}
	total := len(s.scans)
	s.mu.RUnlock()

	if count > 0 {
		s.setStatus(fmt.Sprintf("已选中 %d / %d 个任务", count, total))
	} else {
		s.setStatus(fmt.Sprintf("共 %d 个扫描任务", total))
	}
}

func scanStatusText(status string) string {
	switch status {
	case "processing":
		return "🔄 扫描中"
	case "completed":
		return "✅ 已完成"
	case "scheduled":
		return "📅 已计划"
	case "failed":
		return "❌ 失败"
	case "aborted":
		return "⏹ 已终止"
	case "paused":
		return "⏸ 已暂停"
	case "queued":
		return "⌛ 排队中"
	default:
		if status == "" {
			return "—"
		}
		return status
	}
}

func (s *ScansTab) setStatus(msg string) { s.statusLabel.SetText(msg) }

func (s *ScansTab) refresh() {
	if s.client == nil {
		s.setStatus("未配置 AWVS 连接，请进入【系统配置】")
		return
	}
	s.setStatus("⏳ 正在刷新扫描任务...")
	scans, err := s.client.GetScans()
	if err != nil {
		s.setStatus("❌ 刷新失败: " + err.Error())
		return
	}

	// 写锁：原子性替换数据，再触发渲染，避免表格回调读到中间状态
	s.mu.Lock()
	s.scans = scans
	s.selectedRows = make(map[int]bool)
	s.mu.Unlock()

	if s.selectAllBtn != nil {
		s.selectAllBtn.SetText("全选")
	}
	s.table.Refresh()
	s.setStatus(fmt.Sprintf("✅ 共 %d 个扫描任务", len(scans)))
}

func (s *ScansTab) SetClient(client *api.Client) {
	s.client = client
	go s.refresh()
}
