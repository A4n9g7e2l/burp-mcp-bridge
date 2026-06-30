package com.burpmcpbridge;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.burpmcpbridge.mcp.McpSseServer;
import com.burpmcpbridge.mcp.ToolRegistry;
import com.burpmcpbridge.tools.ExtensionTools;
import com.burpmcpbridge.tools.IntruderTools;
import com.burpmcpbridge.tools.JwtTools;
import com.burpmcpbridge.tools.PluginAnnotationTools;
import com.burpmcpbridge.tools.PluginBridgeTools;
import com.burpmcpbridge.tools.ScannerTools;
import com.burpmcpbridge.tools.TargetTools;
import com.burpmcpbridge.ui.McpBridgeTab;

public class BurpMcpBridgeExtension implements BurpExtension {

    public static final String EXTENSION_NAME = "MCP Bridge";
    public static final String VERSION = "1.0.0";

    private MontoyaApi api;
    private McpSseServer mcpServer;
    private ToolRegistry toolRegistry;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        Logging logging = api.logging();

        logging.logToOutput("========================================");
        logging.logToOutput("  MCP Bridge v" + VERSION + " - 正在初始化...");
        logging.logToOutput("  将 Burp 扩展能力桥接给 AI (MCP 协议)");
        logging.logToOutput("========================================");

        toolRegistry = new ToolRegistry();

        new ExtensionTools(api, toolRegistry).register();
        new IntruderTools(api, toolRegistry).register();
        new ScannerTools(api, toolRegistry).register();
        new TargetTools(api, toolRegistry).register();

        new PluginBridgeTools(api, toolRegistry).register();
        new JwtTools(api, toolRegistry).register();
        new PluginAnnotationTools(api, toolRegistry).register();

        McpBridgeTab tab = new McpBridgeTab(api, toolRegistry, this);
        api.userInterface().registerSuiteTab("MCP Bridge", tab);

        logging.logToOutput("[MCP Bridge] 已注册 " + toolRegistry.getToolCount() + " 个工具");
        logging.logToOutput("[MCP Bridge] UI 标签已创建，2 秒后自动启动服务");

        // Auto-start MCP server on default port 9877 (in background thread to avoid blocking Burp init)
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                startServer(9877);
            } catch (Exception e) {
                logging.logToError("[MCP Bridge] 自动启动失败: " + e.getMessage());
            }
        }, "mcp-bridge-autostart").start();
    }

    public void startServer(int port) {
        if (mcpServer != null && mcpServer.isRunning()) {
            api.logging().logToError("[MCP Bridge] 服务已在端口 " + mcpServer.getPort() + " 运行中");
            return;
        }
        try {
            mcpServer = new McpSseServer(port, toolRegistry, api);
            // daemon=true: non-blocking, so callers don't freeze Burp UI
            mcpServer.start(300, true);
            api.logging().logToOutput("[MCP Bridge] MCP SSE 服务已启动，端口 " + port);
            api.logging().logToOutput("[MCP Bridge] SSE 端点: http://127.0.0.1:" + port + "/sse");
            api.logging().logToOutput("[MCP Bridge] 消息端点: http://127.0.0.1:" + port + "/message");
        } catch (Exception e) {
            api.logging().logToError("[MCP Bridge] 服务启动失败: " + e.getMessage());
        }
    }

    public void stopServer() {
        if (mcpServer != null) {
            mcpServer.stop();
            api.logging().logToOutput("[MCP Bridge] MCP SSE 服务已停止");
        }
    }

    public boolean isServerRunning() {
        return mcpServer != null && mcpServer.isRunning();
    }

    public int getServerPort() {
        return mcpServer != null ? mcpServer.getPort() : -1;
    }
}