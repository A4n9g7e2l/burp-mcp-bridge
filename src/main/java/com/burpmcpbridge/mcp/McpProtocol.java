package com.burpmcpbridge.mcp;

public final class McpProtocol {

    public static final String PROTOCOL_VERSION = "2024-11-05";
    public static final String SERVER_NAME = "burp-mcp-bridge";
    public static final String SERVER_VERSION = "1.0.0";

    public static final String METHOD_INITIALIZE = "initialize";
    public static final String METHOD_INITIALIZED = "notifications/initialized";
    public static final String METHOD_TOOLS_LIST = "tools/list";
    public static final String METHOD_TOOLS_CALL = "tools/call";
    public static final String METHOD_PING = "ping";

    public static final String CONTENT_TYPE_JSON = "application/json";
    public static final String CONTENT_TYPE_SSE = "text/event-stream";

    private McpProtocol() {}
}
