package com.burpmcpbridge.tools;

import burp.api.montoya.MontoyaApi;
import com.burpmcpbridge.mcp.ToolRegistry;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class TargetTools extends BaseTool {

    public TargetTools(MontoyaApi api, ToolRegistry registry) {
        super(api, registry);
    }

    @Override
    public void register() {
        registry.register("get_target_sitemap",
            "Get the target site map with URL, method, status code, and MIME type for all discovered URLs",
            buildObjectSchema(
                stringProp("url_filter", "Regex filter for URL (optional)", false),
                intProp("count", "Number of entries to return (default: 50)", false),
                intProp("offset", "Offset for pagination (default: 0)", false),
                boolProp("include_request", "Include request details (default: false)", false)
            ),
            this::getTargetSitemap
        );

        registry.register("get_scope",
            "Get the current target scope configuration",
            buildObjectSchema(),
            this::getScope
        );

        registry.register("add_to_scope",
            "Add a URL pattern to the target scope",
            buildObjectSchema(
                stringProp("url", "URL or URL pattern to add to scope", true)
            ),
            this::addToScope
        );

        registry.register("get_target_issues",
            "Get all issues for a specific target URL from the site map",
            buildObjectSchema(
                stringProp("url", "Target URL to get issues for", true),
                stringProp("severity_filter", "Filter by severity: high/medium/low/information (optional)", false)
            ),
            this::getTargetIssues
        );
    }

    private JsonObject getTargetSitemap(JsonObject args) {
        String urlFilter = args.has("url_filter") ? args.get("url_filter").getAsString() : null;
        int count = args.has("count") ? args.get("count").getAsInt() : 50;
        int offset = args.has("offset") ? args.get("offset").getAsInt() : 0;
        boolean includeRequest = args.has("include_request") && args.get("include_request").getAsBoolean();

        JsonArray items = new JsonArray();
        try {
            var siteMap = api.siteMap();
            int matched = 0;
            int skipped = 0;

            for (var item : siteMap.requestResponses()) {
                String url = item.request().url();

                if (urlFilter != null && !url.matches(".*" + urlFilter + ".*")) continue;

                if (skipped < offset) { skipped++; continue; }
                if (matched >= count) break;

                JsonObject entry = new JsonObject();
                entry.addProperty("url", url);
                entry.addProperty("method", item.request().method());
                if (item.hasResponse()) {
                    entry.addProperty("status_code", item.response().statusCode());
                    entry.addProperty("mime_type", item.response().mimeType() != null
                        ? item.response().mimeType().toString() : "unknown");
                }

                String highlight = item.annotations().highlightColor() != null
                    ? item.annotations().highlightColor().toString() : null;
                String notes = item.annotations().notes();
                if (highlight != null) entry.addProperty("highlight", highlight);
                if (notes != null && !notes.isEmpty()) entry.addProperty("notes", notes);

                if (includeRequest) {
                    entry.addProperty("request", item.request().toString());
                }

                items.add(entry);
                matched++;
            }
        } catch (Exception e) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Failed to get site map: " + e.getMessage());
            return error;
        }

        JsonObject result = new JsonObject();
        result.add("items", items);
        result.addProperty("count", items.size());
        return result;
    }

    private JsonObject getScope(JsonObject args) {
        JsonObject result = new JsonObject();
        try {
            var scope = api.scope();
            JsonArray inScope = new JsonArray();
            var history = api.proxy().history();
            for (var item : history) {
                String url = item.request().url();
                if (scope.isInScope(url)) {
                    inScope.add(url);
                }
            }
            result.add("in_scope_urls", inScope);
            result.addProperty("in_scope_count", inScope.size());
            result.addProperty("note", "Scope URLs derived from proxy history. Use add_to_scope to add URLs to scope.");
        } catch (Exception e) {
            result.addProperty("error", "Failed to get scope: " + e.getMessage());
        }
        return result;
    }

    private JsonObject addToScope(JsonObject args) {
        String url = args.has("url") ? args.get("url").getAsString() : "";
        JsonObject result = new JsonObject();
        try {
            api.scope().includeInScope(url);
            result.addProperty("status", "added_to_scope");
            result.addProperty("url", url);
        } catch (Exception e) {
            result.addProperty("error", "Failed to add to scope: " + e.getMessage());
        }
        return result;
    }

    private JsonObject getTargetIssues(JsonObject args) {
        String url = args.has("url") ? args.get("url").getAsString() : "";
        String severityFilter = args.has("severity_filter") ? args.get("severity_filter").getAsString() : null;

        JsonArray issuesArr = new JsonArray();
        try {
            var issues = api.siteMap().issues();
            for (var issue : issues) {
                if (!issue.baseUrl().startsWith(url)) continue;
                if (severityFilter != null && !issue.severity().toString().toLowerCase().contains(severityFilter.toLowerCase())) continue;

                JsonObject issueObj = new JsonObject();
                issueObj.addProperty("name", issue.name());
                issueObj.addProperty("severity", issue.severity().toString());
                issueObj.addProperty("confidence", issue.confidence().toString());
                issueObj.addProperty("url", issue.baseUrl());
                issuesArr.add(issueObj);
            }
        } catch (Exception e) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Failed to get target issues: " + e.getMessage());
            return error;
        }

        JsonObject result = new JsonObject();
        result.add("issues", issuesArr);
        result.addProperty("count", issuesArr.size());
        return result;
    }
}