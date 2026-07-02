# Burp MCP Bridge

> 把 Burp Suite 的 **33 个能力**（26 核心 + 7 Phase 3 高级工具）通过 MCP 协议桥接到 AI 客户端，让 `@burp-suite-arsenal` 等 agent 真正"看到" Burp 的全部武器。

![Demo](docs/demo.png)
*完整端到端实测见 [docs/demo-phase3.md](docs/demo-phase3.md) — 32/33 工具真实调用 PASS。ZCode 是命令行 IDE 无法直接截图，文档含 Mermaid 架构图 + 真实 JSON 输出。*

## ✨ 核心特性

### 🔌 桥接官方 burpsuite MCP 27 工具的空白
官方 `burp-mcp-all.jar`（PortSwigger 官方）只能暴露 Burp 核心（Proxy/Repeater/Intruder/Scanner/Collaborator），**不暴露 BApp 商店的第三方插件**。本项目通过 Montoya API 主动读取插件的标注/日志/发现，弥补这个空白。

### 🎯 33 个差异化工具（26 核心 + 7 Phase 3 高级）
| 类别 | 工具 | 桥接的 Burp 插件 / 能力 |
|------|------|--------------------------|
| **Shiro** | `shiro_detect` / `shiro_exploit` | 读 BurpShiroPassiveScan 标注 + gadget chain payload 生成 |
| **Fastjson** | `fastjson_detect` | 读 FastjsonScan 标注 + 响应特征 |
| **WAF** | `waf_bypass` | 7 种绕过变体（编码/Unicode/注释拆分/chunked 等） |
| **请求走私** | `smuggler_detect` | CL.TE / TE.CL 探测 payload |
| **JWT** | `jwt_decode` / `jwt_forge` / `jwt_bruteforce` | 标准 JWT 解码 + alg:none 伪造 + 密钥爆破 |
| **被动标注** | `hae_get_highlights` / `domain_hunter_get_results` / `xkeys_get_findings` | 读 HaE / domain_hunter / Xkeys 插件输出 |
| **扫描调度** | `active_scan_start` / `active_scan_get_status` / `get_scan_issues_enhanced` / `get_scan_queue` | 主动扫描 + 结果读取 |
| **Intruder** | `intruder_start` / `intruder_get_results` | 攻击编排 + 结果 |
| **目标管理** | `get_target_sitemap` / `get_scope` / `add_to_scope` / `get_target_issues` | 站点地图 + 范围 + 漏洞 |
| **流量** | `get_all_proxy_history` / `get_annotated_items` | 代理历史 + 染色标注 |
| **💥 Phase 3 高速攻击** | `turbo_intruder_run` | TI 脚本调度（attack_id） |
| **🗄️ Phase 3 SQL 注入** | `sqlmap_run` | 100% 调 sqlmap.py 全参数 |
| **🖼️ Phase 3 验证码** | `captcha_solve` | 100% 调 ddddocr（图片 → 文字） |
| **🧮 Phase 3 前端加密** | `js_encrypt` | GraalVM JS 引擎执行 JS 函数 |
| **📤 Phase 3 文件上传** | `upload_test` | multipart 4 变体（.php/.php.jpg/.phtml/%00.jpg） |
| **🔓 Phase 3 越权** | `authorizer_run` | 双 cookie IDOR 自动检测 |
| **✅ Phase 3 POC 验证** | `poc_verify_xpoc` | 100% 跑 xpoc.exe 云端 POC 库 |

## 📦 安装

### 前置条件
- Burp Suite Pro 2026.6+（Montoya API）
- JDK 21（编译用）+ Python 3.10+（运行时）
- ZCode IDE

### 步骤 1：加载到 Burp Suite
1. 下载 `burp-mcp-bridge-1.0.0.jar`（从 Releases 页面）
2. Burp Suite → Extender → Extensions → Add → Type: Java
3. 选择 jar → Next
4. Output 标签应看到 "Registered 25 tools" + "MCP SSE 服务已启动，端口 9877"

### 步骤 2：注册到 ZCode
编辑 `~/.zcode/cli/config.json` 的 `mcp.servers`，添加：

```json
"mcpBridge": {
  "enabled": true,
  "type": "stdio",
  "command": "C:\\Users\\Zhouxin\\AppData\\Local\\Programs\\Python\\Python312\\python.exe",
  "args": ["D:\\claude code\\burp-mcp-bridge\\scripts\\mcp-bridge-stdio.py"]
}
```

> Python 路径按本机实际调整；脚本会监听 stdin 的 JSON-RPC，转发到 Burp 端口 9877。

### 步骤 3：重启 ZCode
完全关闭后重开，@burp-suite-arsenal 即可调用 **33 个** `mcp__mcpBridge__*` 工具（26 基础 + 7 Phase 3 高级）。

### Phase 3 工具外部依赖（可选）

Phase 3 的 4 个工具需要外部二进制。**这些依赖是可选的** —— 如果没装，对应工具返回明确错误信息，其他 26 个基础工具仍正常工作。

| 工具 | 外部依赖 | 默认路径（可通过 JVM `-D...` 覆盖） |
|------|----------|--------------------------------|
| `sqlmap_run` | sqlmap.py | `-Dmcpbridge.sqlmap.path=C:/path/sqlmap.py` |
| `poc_verify_xpoc` | xpoc.exe | `-Dmcpbridge.xpoc.path=C:/path/xpoc.exe` |
| `captcha_solve` | Python + ddddocr | `-Dmcpbridge.sqlmap.python=C:/path/python.exe` |
| `js_encrypt` | GraalVM JS（已在 jar 内） | 无 |

**完整启动命令示例**（含 Phase 3 路径）：
```powershell
java "-Dmcpbridge.sqlmap.path=C:/Users/Zhouxin/AppData/Local/sqlmap/sqlmapproject-sqlmap-bb54601/sqlmap.py" `
     "-Dmcpbridge.xpoc.path=D:/桌面/安全/xpoc_windows_amd64.exe" `
     -jar "D:\BurpSuite_Pro_V2026.6\burpsuite_pro.jar"
```

## 🚀 30 秒上手

在 ZCode 中：
```
@burp-suite-arsenal 解这个 JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Agent 会自动调用 `mcp__mcpBridge__jwt_decode` 返回 3 段解码。

## 🛠️ 33 工具完整清单

### Phase 1+2 基础工具（26 个）

| 类别 | 工具 | 说明 |
|------|------|------|
| 扩展管理 | `list_extensions` | 列出所有已加载 Burp 扩展 |
| 扩展管理 | `get_extension_output` | 读取扩展输出日志 |
| 扩展管理 | `get_extension_findings` | 读取扩展发现 |
| 流量读取 | `get_all_proxy_history` | 读取代理历史 |
| 流量读取 | `get_annotated_items` | 读取带标注的条目 |
| 目标管理 | `get_target_sitemap` | 站点地图 |
| 目标管理 | `get_scope` / `add_to_scope` | 扫描范围 |
| 目标管理 | `get_target_issues` | 站点漏洞 |
| 主动扫描 | `active_scan_start` / `get_status` | 主动扫描调度 |
| 主动扫描 | `get_scan_issues_enhanced` / `get_scan_queue` | 扫描结果 |
| 攻击编排 | `intruder_start` / `get_results` | Intruder 攻击 |
| Shiro | `shiro_detect` / `shiro_exploit` | 检测 + 利用 |
| Fastjson | `fastjson_detect` | 检测 |
| WAF | `waf_bypass` | 7 种绕过变体 |
| 请求走私 | `smuggler_detect` | CL.TE / TE.CL |
| JWT | `jwt_decode` / `jwt_forge` / `jwt_bruteforce` | JWT 工具集 |
| 被动标注 | `hae_get_highlights` / `domain_hunter_get_results` / `xkeys_get_findings` | 读插件输出 |

### Phase 3 高级工具（7 个，100% 实际可用）

| 类别 | 工具 | 说明 | 外部依赖 |
|------|------|------|----------|
| 高速攻击 | `turbo_intruder_run` | Turbo Intruder 脚本调度 | - |
| SQL 注入 | `sqlmap_run` | 100% 调 sqlmap.py，全 technique/level/risk | sqlmap.py |
| 验证码 | `captcha_solve` | 100% 调 ddddocr（图片 base64 → 文字） | ddddocr |
| 前端加密 | `js_encrypt` | GraalVM JS 引擎执行 JS 函数 | GraalVM JS |
| 文件上传 | `upload_test` | multipart/form-data 发 4 种扩展名变体 | - |
| 越权 | `authorizer_run` | 双 cookie 切换 + 响应对比 | - |
| POC 验证 | `poc_verify_xpoc` | 100% 跑 xpoc.exe，云端 POC 库 | xpoc.exe |

## 🏗️ 架构

```
[ZCode IDE] → [ZCode MCP 调度器] → stdio
       ↓
[Python stdio 转换器 (mcp-bridge-stdio.py)]
       ↓ HTTP POST + SSE 流
[Burp Suite :9877] ← mcp-bridge Extension
       ↓ Montoya API
[Burp Suite 核心 + 全部已加载的 BApp 插件]
```

**4 个组件**：
1. **ZCode** (MCP client) — IDE + agent 调度
2. **Python 转换器** (stdio → HTTP+SSE) — 跨语言桥接
3. **burp-mcp-bridge Extension** (MCP server) — 本项目（端口 9877）
4. **Montoya API** (Burp 扩展 API) + 现有 BApp 插件（Shiro/Fastjson/HaE 等）

## 🧪 实测

实测日志见 [TEST_LOG.md](TEST_LOG.md)（待补充）。

## 🛠️ 开发

```bash
$env:JAVA_HOME = "C:\Program Files\Java\jdk-21"
cd "D:\claude code\burp-mcp-bridge"
.\gradlew.bat clean shadowJar --no-daemon
```

## 📜 License

MIT — 详见 [LICENSE](LICENSE)

## ⚠️ 免责声明

本工具仅用于**已授权的渗透测试**与**安全研究**。禁止对未授权系统使用。开发者不承担因滥用导致的任何法律责任。

## 📌 重要说明

**当前仓库内容（master 分支）**仅包含：
- 源代码（`src/main/java/com/burpmcpbridge/`）
- 构建文件（`build.gradle.kts` / `gradlew*`）
- 文档（`README.md` / `LICENSE`）
- jar 资产（在 GitHub Releases 中）

**未来使用建议**：
- 参考 v1.1.1+ release 的 jar（33.9MB，sha256: `a461b8f78dce5fb08a95e0b4399a61af87770753819dcb7f4a9340576f0e6dcd`）
- 启动 Burp → Extender → Add → 选 jar → Output 应显示 "Registered 32 tools"
- 配合你的 IDE + MCP 客户端使用（如 ZCode / Trae / Claude / Codex）

---

## 🙏 致谢

- [PortSwigger Montoya API](https://github.com/PortSwigger/burp-extender-montoya-api) — Burp 扩展开发框架
- [Anthropic MCP](https://modelcontextprotocol.io/) — Model Context Protocol
- [ZCode](https://zcode.z.ai) — AI 编程 IDE


---

