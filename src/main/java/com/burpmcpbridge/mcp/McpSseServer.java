package com.burpmcpbridge.mcp;

import burp.api.montoya.MontoyaApi;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import fi.iki.elonen.NanoHTTPD;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class McpSseServer extends NanoHTTPD {

    private final ToolRegistry toolRegistry;
    private final MontoyaApi api;
    private final Map<String, SSESession> sessions = new ConcurrentHashMap<>();
    private final AtomicInteger sessionIdCounter = new AtomicInteger(0);

    public McpSseServer(int port, ToolRegistry toolRegistry, MontoyaApi api) {
        super(port);
        this.toolRegistry = toolRegistry;
        this.api = api;
    }

    @Override
    public Response serve(IHTTPSession session) {
        String uri = session.getUri();
        Method method = session.getMethod();

        if ("/sse".equals(uri) && Method.GET.equals(method)) {
            return handleSSEConnection(session);
        }
        if ("/sse".equals(uri) && Method.POST.equals(method)) {
            // Some MCP clients (mcp-proxy-all.jar / mcp-proxy.jar) send POST requests
            // directly to /sse for both handshake probe AND message delivery.
            // Route to handleClientMessage if there's a body, otherwise return 200.
            api.logging().logToOutput("[MCP Bridge] POST /sse from " + session.getRemoteIpAddress());
            try {
                int contentLength = Integer.parseInt(session.getHeaders().getOrDefault("content-length", "0"));
                if (contentLength > 0) {
                    return handleClientMessage(session);
                }
            } catch (Exception e) {
                api.logging().logToError("[MCP Bridge] POST /sse probe error: " + e.getMessage());
            }
            return newFixedLengthResponse(Response.Status.OK, "text/plain", "SSE endpoint ready. Use GET to connect.\n");
        }
        if ("/message".equals(uri) && Method.POST.equals(method)) {
            return handleClientMessage(session);
        }
        if ("/health".equals(uri) && Method.GET.equals(method)) {
            JsonObject health = new JsonObject();
            health.addProperty("status", "running");
            health.addProperty("server", McpProtocol.SERVER_NAME);
            health.addProperty("version", McpProtocol.SERVER_VERSION);
            health.addProperty("tools", toolRegistry.getToolCount());
            health.addProperty("sessions", sessions.size());
            return newFixedLengthResponse(Response.Status.OK, McpProtocol.CONTENT_TYPE_JSON, health.toString());
        }
        if ("/".equals(uri) && Method.GET.equals(method)) {
            // Some MCP clients (e.g., mcp-proxy.jar) GET the base URL directly
            // expecting an SSE stream. Alias root to the same /sse handler.
            return handleSSEConnection(session);
        }
        if ("/.well-known/oauth-authorization-server".equals(uri) && Method.GET.equals(method)) {
            return handleOAuthDiscovery();
        }
        if ("/oauth/register".equals(uri) && Method.POST.equals(method)) {
            return handleOAuthRegister(session);
        }
        if ("/oauth/token".equals(uri) && Method.POST.equals(method)) {
            return handleOAuthToken(session);
        }
        return newFixedLengthResponse(Response.Status.NOT_FOUND, "text/plain", "Not Found");
    }

    private Response handleOAuthDiscovery() {
        String port = String.valueOf(getListeningPort());
        String base = "http://127.0.0.1:" + port;
        JsonObject metadata = new JsonObject();
        metadata.addProperty("issuer", base);
        metadata.addProperty("authorization_endpoint", base + "/oauth/authorize");
        metadata.addProperty("token_endpoint", base + "/oauth/token");
        metadata.addProperty("registration_endpoint", base + "/oauth/register");
        com.google.gson.JsonArray responseTypes = new com.google.gson.JsonArray();
        responseTypes.add("code");
        metadata.add("response_types_supported", responseTypes);
        com.google.gson.JsonArray grantTypes = new com.google.gson.JsonArray();
        grantTypes.add("authorization_code");
        metadata.add("grant_types_supported", grantTypes);
        com.google.gson.JsonArray codeMethods = new com.google.gson.JsonArray();
        codeMethods.add("S256");
        metadata.add("code_challenge_methods_supported", codeMethods);
        return newFixedLengthResponse(Response.Status.OK, McpProtocol.CONTENT_TYPE_JSON, metadata.toString());
    }

    private Response handleOAuthRegister(IHTTPSession session) {
        JsonObject response = new JsonObject();
        response.addProperty("client_id", "burp-mcp-bridge-client");
        response.addProperty("client_secret", "");
        response.addProperty("client_id_issued_at", System.currentTimeMillis() / 1000);
        response.addProperty("client_secret_expires_at", 0);
        com.google.gson.JsonArray redirects = new com.google.gson.JsonArray();
        response.add("redirect_uris", redirects);
        com.google.gson.JsonArray grantTypes = new com.google.gson.JsonArray();
        grantTypes.add("authorization_code");
        grantTypes.add("client_credentials");
        response.add("grant_types", grantTypes);
        response.addProperty("token_endpoint_auth_method", "none");
        response.addProperty("scope", "mcp");
        return newFixedLengthResponse(Response.Status.OK, McpProtocol.CONTENT_TYPE_JSON, response.toString());
    }

    private Response handleOAuthToken(IHTTPSession session) {
        // Issue a local opaque token (no real auth needed for in-process use)
        JsonObject response = new JsonObject();
        response.addProperty("access_token", "burp-mcp-bridge-token");
        response.addProperty("token_type", "Bearer");
        response.addProperty("expires_in", 86400);
        response.addProperty("scope", "mcp");
        return newFixedLengthResponse(Response.Status.OK, McpProtocol.CONTENT_TYPE_JSON, response.toString());
    }

    private Response handleSSEConnection(IHTTPSession session) {
        String sessionId = "sess_" + sessionIdCounter.incrementAndGet();
        SSESession sseSession = new SSESession(sessionId);
        sessions.put(sessionId, sseSession);

        api.logging().logToOutput("[MCP Bridge] 新的 SSE 连接: " + sessionId);

        Response response = newChunkedResponse(Response.Status.OK, McpProtocol.CONTENT_TYPE_SSE, sseSession.getInputStream());
        String endpointUrl = "/message?sessionId=" + sessionId;
        response.addHeader("Cache-Control", "no-cache");
        response.addHeader("Connection", "keep-alive");
        response.addHeader("X-Accel-Buffering", "no");

        new Thread(() -> {
            try { Thread.sleep(100); } catch (InterruptedException ignored) {}
            sseSession.sendEvent("endpoint", endpointUrl);
            api.logging().logToOutput("[MCP Bridge] SSE endpoint 事件已发送: " + endpointUrl);
        }, "sse-endpoint-" + sessionId).start();

        return response;
    }

    private Response handleClientMessage(IHTTPSession session) {
        String sessionId = session.getParms().get("sessionId");
        if (sessionId == null || !sessions.containsKey(sessionId)) {
            return newFixedLengthResponse(Response.Status.BAD_REQUEST, "text/plain", "Invalid session");
        }

        String body = readBody(session);
        if (body == null || body.isEmpty()) {
            return newFixedLengthResponse(Response.Status.BAD_REQUEST, "text/plain", "Empty body");
        }

        api.logging().logToOutput("[MCP Bridge] 来自 " + sessionId + " 的消息: " + truncate(body, 200));

        try {
            JsonObject request = JsonParser.parseString(body).getAsJsonObject();
            JsonObject response = processJsonRpc(request);

            if (response != null) {
                SSESession sseSession = sessions.get(sessionId);
                sseSession.sendEvent("message", response.toString());
            }

            return newFixedLengthResponse(Response.Status.ACCEPTED, "text/plain", "Accepted");
        } catch (Exception e) {
            api.logging().logToError("[MCP Bridge] JSON-RPC 错误: " + e.getMessage());
            JsonObject errorResp = buildError(null, -32700, "Parse error: " + e.getMessage());
            SSESession sseSession = sessions.get(sessionId);
            if (sseSession != null) {
                sseSession.sendEvent("message", errorResp.toString());
            }
            return newFixedLengthResponse(Response.Status.INTERNAL_ERROR, "text/plain", "Error");
        }
    }

    private JsonObject processJsonRpc(JsonObject request) {
        String method = request.has("method") ? request.get("method").getAsString() : null;
        Object id = request.has("id") ? (request.get("id").isJsonPrimitive() && request.get("id").getAsJsonPrimitive().isNumber() ? request.get("id").getAsNumber() : request.get("id").getAsString()) : null;

        if (method == null) {
            return buildError(id, -32600, "Invalid Request: missing method");
        }

        JsonObject params = request.has("params") ? request.getAsJsonObject("params") : new JsonObject();

        switch (method) {
            case McpProtocol.METHOD_INITIALIZE:
                return handleInitialize(id, params);
            case McpProtocol.METHOD_INITIALIZED:
                return null;
            case McpProtocol.METHOD_PING:
                return buildResult(id, new JsonObject());
            case McpProtocol.METHOD_TOOLS_LIST:
                return handleToolsList(id);
            case McpProtocol.METHOD_TOOLS_CALL:
                return handleToolsCall(id, params);
            default:
                return buildError(id, -32601, "Method not found: " + method);
        }
    }

    private JsonObject handleInitialize(Object id, JsonObject params) {
        JsonObject result = new JsonObject();
        JsonObject serverInfo = new JsonObject();
        serverInfo.addProperty("name", McpProtocol.SERVER_NAME);
        serverInfo.addProperty("version", McpProtocol.SERVER_VERSION);

        JsonObject capabilities = new JsonObject();
        JsonObject toolsCap = new JsonObject();
        toolsCap.addProperty("listChanged", false);
        capabilities.add("tools", toolsCap);

        result.addProperty("protocolVersion", McpProtocol.PROTOCOL_VERSION);
        result.add("capabilities", capabilities);
        result.add("serverInfo", serverInfo);

        api.logging().logToOutput("[MCP Bridge] 客户端已初始化，协议: " + McpProtocol.PROTOCOL_VERSION);
        return buildResult(id, result);
    }

    private JsonObject handleToolsList(Object id) {
        JsonObject result = new JsonObject();
        result.add("tools", toolRegistry.listTools());
        return buildResult(id, result);
    }

    private JsonObject handleToolsCall(Object id, JsonObject params) {
        String toolName = params.has("name") ? params.get("name").getAsString() : null;
        JsonObject arguments = params.has("arguments") ? params.getAsJsonObject("arguments") : new JsonObject();

        if (toolName == null) {
            return buildError(id, -32602, "Invalid params: missing tool name");
        }

        api.logging().logToOutput("[MCP Bridge] 工具调用: " + toolName);

        JsonObject toolResult = toolRegistry.callTool(toolName, arguments);

        JsonObject content = new JsonObject();
        if (toolResult.has("error")) {
            content.addProperty("type", "text");
            content.addProperty("text", "Error: " + toolResult.get("error").getAsString());
            JsonArray contentArr = new JsonArray();
            contentArr.add(content);
            JsonObject result = new JsonObject();
            result.add("content", contentArr);
            result.addProperty("isError", true);
            return buildResult(id, result);
        }

        content.addProperty("type", "text");
        content.addProperty("text", toolResult.toString());
        JsonArray contentArr = new JsonArray();
        contentArr.add(content);
        JsonObject result = new JsonObject();
        result.add("content", contentArr);
        result.addProperty("isError", false);
        return buildResult(id, result);
    }

    private JsonObject buildResult(Object id, JsonObject result) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        if (id instanceof Number) {
            response.addProperty("id", ((Number) id).intValue());
        } else if (id instanceof String) {
            response.addProperty("id", (String) id);
        }
        response.add("result", result);
        return response;
    }

    private JsonObject buildError(Object id, int code, String message) {
        JsonObject response = new JsonObject();
        response.addProperty("jsonrpc", "2.0");
        if (id instanceof Number) {
            response.addProperty("id", ((Number) id).intValue());
        } else if (id instanceof String) {
            response.addProperty("id", (String) id);
        }
        JsonObject error = new JsonObject();
        error.addProperty("code", code);
        error.addProperty("message", message);
        response.add("error", error);
        return response;
    }

    private String readBody(IHTTPSession session) {
        try {
            int contentLength = Integer.parseInt(session.getHeaders().getOrDefault("content-length", "0"));
            if (contentLength > 0) {
                byte[] buffer = new byte[contentLength];
                session.getInputStream().read(buffer, 0, contentLength);
                return new String(buffer);
            }
        } catch (Exception e) {
            api.logging().logToError("[MCP Bridge] 读取请求体错误: " + e.getMessage());
        }
        return "";
    }

    private String truncate(String s, int maxLen) {
        return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
    }

    public boolean isRunning() {
        return super.isAlive();
    }

    public int getPort() {
        return getListeningPort();
    }

    @Override
    public void stop() {
        for (SSESession session : sessions.values()) {
            session.close();
        }
        sessions.clear();
        super.stop();
        api.logging().logToOutput("[MCP Bridge] 服务已停止，所有会话已关闭");
    }
}