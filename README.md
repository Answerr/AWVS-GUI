# AWVS GUI

一款基于 **Go + Fyne** 开发的 [Acunetix Web Vulnerability Scanner (AWVS)](https://www.acunetix.com/) 桌面 GUI 客户端，为安全测试人员提供可视化操作界面，告别命令行，提升渗透测试效率。

> 作者：信益安 | 版本：V1.0 | 协议：MIT

---

## 截图预览
<img width="1644" height="1168" alt="image" src="https://github.com/user-attachments/assets/b4ef1bcf-ea04-4903-8e05-5d57aa408dae" />


<img width="1642" height="1174" alt="image" src="https://github.com/user-attachments/assets/034ed443-1f6e-421e-b2a0-e3a50dcc477c" />

<img width="1632" height="1153" alt="image" src="https://github.com/user-attachments/assets/98dad6af-780c-4bbf-9e89-aa3ec1ae5138" />


---

## 功能特性

### 系统配置
- 配置 AWVS 服务地址（默认 `https://localhost:3443`）及 API Key
- 支持 HTTP 代理设置，便于流量抓包分析
- 一键测试连接，配置自动持久化至本地

### 扫描目标管理
- **单个添加**：支持 `domain.com` / `http://...` / `https://...` 三种格式
- **TXT 批量导入**：逐行解析目标文件，支持中途取消
- **测绘引擎子域名发现**：添加主域名时自动调用 Fofa / Shodan / Hunter / Quake / ZoomEye 发现子域名，智能去重后批量导入 AWVS
- **多选批量操作**：全选、扫描选中、扫描全部、删除选中、一键清空（5 并发加速删除）
- **6 种扫描配置**：完整扫描、高危漏洞、SQL 注入、弱口令检测、XSS 漏洞、仅爬取

### 扫描任务监控
- 实时展示任务状态（扫描中 / 已完成 / 已终止等）与进度百分比
- 漏洞统计分级显示（严重 / 高危 / 中危 / 低危 / 信息）
- 支持多选批量终止或删除扫描记录
- 点击 URL 列直接弹出该目标漏洞详情

### 漏洞列表
- 汇总展示所有目标漏洞，支持按严重程度排序（高危优先 / 低危优先）
- **内置 100+ 条漏洞名称中文翻译**，覆盖 XSS、SQL 注入、SSRF、Log4Shell 等常见漏洞
- 点击漏洞名称弹出详情窗口，展示漏洞描述、攻击详情及原始 HTTP 请求

### 测绘引擎配置
支持配置以下 5 个网络空间测绘引擎的 API Key：

| 引擎 | 说明 |
|------|------|
| [Fofa](https://fofa.info/) |  |
| [Shodan](https://www.shodan.io/) | |
| [Hunter 鹰图](https://hunter.qianxin.com/) |  |
| [Quake 360](https://quake.360.net/) | |
| [ZoomEye](https://www.zoomeye.org/) | |

---

## 技术栈

| 技术 | 版本 | 用途 |
|------|------|------|
| Go | 1.21+ | 主开发语言 |
| [Fyne v2](https://fyne.io/) | v2.7.3 | 跨平台桌面 GUI 框架 |
| fyne.io/systray | v1.12.0 | 系统托盘支持 |
| sqweek/dialog | latest | 原生文件选择对话框 |

---

## 安装与使用

### 前置要求

- 已在本地或远程部署 **Acunetix Web Vulnerability Scanner（AWVS）**
- Go **1.21+** 编译环境（从源码构建时需要）

### 从源码构建

```bash
# 克隆仓库
git clone https://github.com/your-username/awvs-gui.git
cd awvs-gui/awvs

# 编译
go build -o awvs-gui.exe .
```

### 直接运行

从 [Releases](https://github.com/your-username/awvs-gui/releases) 页面下载对应平台的预编译二进制文件，直接运行即可。

---

## 快速上手

1. **配置连接**  
   打开【系统配置】标签页，填写 AWVS 服务地址和 API Key，点击「保存并应用」，测试连接成功后即可使用。

   > **获取 API Key**：登录 AWVS → 右上角用户头像 → Profile → API Key → 生成并复制

2. **添加扫描目标**  
   进入【扫描目标】，单个输入目标 URL，或点击「批量导入」选择 TXT 文件（每行一个目标）。

3. **启动扫描**  
   勾选目标，选择扫描配置，点击「扫描选中」或「扫描全部」。

4. **查看结果**  
   进入【扫描任务】查看实时进度；进入【漏洞列表】查看全部漏洞详情（支持中文翻译）。

---

## 配置文件

配置自动保存于：`~/.awvs-client/config.json`

```json
{
  "base_url": "https://localhost:3443",
  "api_key": "your-api-key",
  "proxy_host": "",
  "proxy_port": "",
  "fofa_email": "",
  "fofa_key": "",
  "shodan_key": "",
  "hunter_key": "",
  "quake_key": "",
  "zoomeye_key": ""
}
```
欢迎关注公众号获取更多

<img width="426" height="428" alt="image" src="https://github.com/user-attachments/assets/a301f182-20ae-46cf-b441-03f683a9764a" />

---

## 免责声明

本工具仅限用于**已获得明确授权**的安全测试场景。未经授权对他人系统进行扫描或渗透测试属于违法行为，使用者需自行承担一切法律责任，作者不承担任何连带责任。

---

## 开源协议

[MIT License](LICENSE)
