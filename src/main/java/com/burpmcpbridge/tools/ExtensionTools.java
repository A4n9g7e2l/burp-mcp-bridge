package com.burpmcpbridge.tools;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.burpmcpbridge.mcp.ToolRegistry;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.List;

public class ExtensionTools extends BaseTool {

    public ExtensionTools(MontoyaApi api, ToolRegistry registry) {
        super(api, registry);
    }

    @Override
    public void register() {
        registry.register("list_extensions",
            "List all loaded Burp Suite extensions with their status",
            buildObjectSchema(),
            this::listExtensions
        );

        registry.register("get_extension_output",
            "Read output/error logs from a specific Burp extension",
            buildObjectSchema(
                stringProp("extension_name", "Name of the extension to read output from", true),
                intProp("lines", "Maximum number of log lines to return (default: 50)", false)
            ),
            this::getExtensionOutput
        );

        registry.register("get_extension_findings",
            "Get findings/markers from passive scan extensions (HaE highlights, Xkeys findings, etc.)",
            buildObjectSchema(
                stringProp("extension_name", "Name of the extension to get findings from", true),
                intProp("count", "Maximum number of findings to return (default: 50)", false)
            ),
            this::getExtensionFindings
        );

        registry.register("get_all_proxy_history",
            "Enhanced proxy history with full request/response details, annotations, and MIME type",
            buildObjectSchema(
                intProp("count", "Number of entries to return (default: 20)", false),
                intProp("offset", "Offset for pagination (default: 0)", false),
                stringProp("url_filter", "Regex filter for URL (optional)", false),
                stringProp("mime_filter", "Filter by MIME type: html/json/xml/script/image/other (optional)", false),
                boolProp("include_body", "Include response body in output (default: false)", false)
            ),
            this::getAllProxyHistory
        );

        registry.register("get_annotated_items",
            "Get all proxy history items that have annotations, highlights, or comments (from HaE, etc.)",
            buildObjectSchema(
                stringProp("color_filter", "Filter by highlight color: red/orange/yellow/green/blue/pink/purple (optional)", false),
                intProp("count", "Number of entries to return (default: 50)", false)
            ),
            this::getAnnotatedItems
        );
    }

    private JsonObject listExtensions(JsonObject args) {
        JsonArray extensions = new JsonArray();
        try {
            JsonObject ext = new JsonObject();
            ext.addProperty("name", api.extension().filename());
            ext.addProperty("is_bapp", api.extension().isBapp());
            ext.addProperty("loaded", true);
            extensions.add(ext);
        } catch (Exception e) {
            api.logging().logToError("[MCP Bridge] Error listing extensions: " + e.getMessage());
        }
        JsonObject result = new JsonObject();
        result.add("extensions", extensions);
        result.addProperty("count", extensions.size());
        result.addProperty("note", "Montoya API only exposes the current extension. Use Burp GUI -> Extender for full extension list.");
        return result;
    }

    private JsonObject getExtensionOutput(JsonObject args) {
        String extName = args.has("extension_name") ? args.get("extension_name").getAsString() : "";
        int lines = args.has("lines") ? args.get("lines").getAsInt() : 50;

        JsonObject result = new JsonObject();
        result.addProperty("extension_name", extName);
        result.addProperty("note", "Extension output is captured via Burp annotations. Use Burp GUI -> Extender -> Extensions -> Output tab for full logs.");

        JsonArray recentLogs = new JsonArray();
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int start = Math.max(0, history.size() - lines);
            for (int i = start; i < history.size(); i++) {
                var item = history.get(i);
                if (item.annotations().hasNotes()) {
                    JsonObject log = new JsonObject();
                    log.addProperty("url", item.request().url());
                    log.addProperty("notes", item.annotations().notes());
                    recentLogs.add(log);
                }
            }
        } catch (Exception e) {
            result.addProperty("error", "Could not read extension output: " + e.getMessage());
        }
        result.add("annotated_entries", recentLogs);
        return result;
    }

    private JsonObject getExtensionFindings(JsonObject args) {
        String extName = args.has("extension_name") ? args.get("extension_name").getAsString() : "";
        int count = args.has("count") ? args.get("count").getAsInt() : 50;

        JsonObject result = new JsonObject();
        result.addProperty("extension_name", extName);

        JsonArray findings = new JsonArray();
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int found = 0;
            for (int i = history.size() - 1; i >= 0 && found < count; i--) {
                var item = history.get(i);
                String highlight = item.annotations().highlightColor() != null
                    ? item.annotations().highlightColor().toString() : null;
                String notes = item.annotations().notes();

                if (highlight != null || (notes != null && !notes.isEmpty())) {
                    JsonObject finding = new JsonObject();
                    finding.addProperty("url", item.request().url());
                    finding.addProperty("method", item.request().method());
                    finding.addProperty("status_code", item.response().statusCode());
                    if (highlight != null) finding.addProperty("highlight_color", highlight);
                    if (notes != null && !notes.isEmpty()) finding.addProperty("notes", notes);
                    findings.add(finding);
                    found++;
                }
            }
        } catch (Exception e) {
            result.addProperty("error", "Could not read findings: " + e.getMessage());
        }
        result.add("findings", findings);
        result.addProperty("count", findings.size());
        return result;
    }

    private JsonObject getAllProxyHistory(JsonObject args) {
        int count = args.has("count") ? args.get("count").getAsInt() : 20;
        int offset = args.has("offset") ? args.get("offset").getAsInt() : 0;
        String urlFilter = args.has("url_filter") ? args.get("url_filter").getAsString() : null;
        String mimeFilter = args.has("mime_filter") ? args.get("mime_filter").getAsString() : null;
        boolean includeBody = args.has("include_body") && args.get("include_body").getAsBoolean();

        JsonArray items = new JsonArray();
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int matched = 0;
            int skipped = 0;

            for (int i = history.size() - 1; i >= 0; i--) {
                var item = history.get(i);
                String url = item.request().url();

                if (urlFilter != null && !url.matches(".*" + urlFilter + ".*")) continue;
                if (mimeFilter != null) {
                    String mime = item.response().mimeType() != null
                        ? item.response().mimeType().toString().toLowerCase() : "";
                    if (!mime.contains(mimeFilter.toLowerCase())) continue;
                }

                if (skipped < offset) { skipped++; continue; }
                if (matched >= count) break;

                JsonObject entry = new JsonObject();
                entry.addProperty("url", url);
                entry.addProperty("method", item.request().method());
                entry.addProperty("status_code", item.response().statusCode());
                entry.addProperty("mime_type", item.response().mimeType() != null
                    ? item.response().mimeType().toString() : "unknown");

                String highlight = item.annotations().highlightColor() != null
                    ? item.annotations().highlightColor().toString() : null;
                String notes = item.annotations().notes();
                if (highlight != null) entry.addProperty("highlight", highlight);
                if (notes != null && !notes.isEmpty()) entry.addProperty("notes", notes);

                if (includeBody) {
                    entry.addProperty("response_body", item.response().bodyToString());
                }

                JsonArray reqHeaderArr = new JsonArray();
                for (var header : item.request().headers()) {
                    reqHeaderArr.add(header.name() + ": " + header.value());
                }
                entry.add("request_headers", reqHeaderArr);

                items.add(entry);
                matched++;
            }
        } catch (Exception e) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Failed to read proxy history: " + e.getMessage());
            return error;
        }

        JsonObject result = new JsonObject();
        result.add("items", items);
        result.addProperty("count", items.size());
        return result;
    }

    private JsonObject getAnnotatedItems(JsonObject args) {
        String colorFilter = args.has("color_filter") ? args.get("color_filter").getAsString() : null;
        int count = args.has("count") ? args.get("count").getAsInt() : 50;

        JsonArray items = new JsonArray();
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int found = 0;

            for (int i = history.size() - 1; i >= 0 && found < count; i--) {
                var item = history.get(i);
                String highlight = item.annotations().highlightColor() != null
                    ? item.annotations().highlightColor().toString() : null;
                String notes = item.annotations().notes();

                if (highlight == null && (notes == null || notes.isEmpty())) continue;
                if (colorFilter != null && highlight != null && !highlight.equalsIgnoreCase(colorFilter)) continue;

                JsonObject entry = new JsonObject();
                entry.addProperty("url", item.request().url());
                entry.addProperty("method", item.request().method());
                entry.addProperty("status_code", item.response().statusCode());
                if (highlight != null) entry.addProperty("highlight_color", highlight);
                if (notes != null && !notes.isEmpty()) entry.addProperty("notes", notes);
                items.add(entry);
                found++;
            }
        } catch (Exception e) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Failed to read annotated items: " + e.getMessage());
            return error;
        }

        JsonObject result = new JsonObject();
        result.add("items", items);
        result.addProperty("count", items.size());
        return result;
    }
}