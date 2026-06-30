package com.burpmcpbridge.tools;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.CrawlConfiguration;
import com.burpmcpbridge.mcp.ToolRegistry;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class ScannerTools extends BaseTool {

    public ScannerTools(MontoyaApi api, ToolRegistry registry) {
        super(api, registry);
    }

    @Override
    public void register() {
        registry.register("active_scan_start",
            "Start an active scan on a specific URL or request",
            buildObjectSchema(
                stringProp("url", "Target URL to scan", true),
                stringProp("request", "Full HTTP request to scan (optional, auto-generated if not provided)", false),
                boolProp("crawl_and_audit", "Crawl and audit mode (default: true)", false)
            ),
            this::startActiveScan
        );

        registry.register("active_scan_get_status",
            "Get status of running active scans",
            buildObjectSchema(),
            this::getActiveScanStatus
        );

        registry.register("get_scan_issues_enhanced",
            "Enhanced scan issues with severity, confidence, URL, and remediation details",
            buildObjectSchema(
                stringProp("severity_filter", "Filter by severity: high/medium/low/information (optional)", false),
                stringProp("url_filter", "Regex filter for URL (optional)", false),
                intProp("count", "Number of issues to return (default: 50)", false),
                intProp("offset", "Offset for pagination (default: 0)", false)
            ),
            this::getScanIssuesEnhanced
        );

        registry.register("get_scan_queue",
            "Get current scan queue status with progress information",
            buildObjectSchema(),
            this::getScanQueue
        );
    }

    private JsonObject startActiveScan(JsonObject args) {
        String url = args.has("url") ? args.get("url").getAsString() : "";
        boolean crawlAndAudit = !args.has("crawl_and_audit") || args.get("crawl_and_audit").getAsBoolean();

        JsonObject result = new JsonObject();
        try {
            if (crawlAndAudit) {
                CrawlConfiguration crawlConfig = CrawlConfiguration.crawlConfiguration(url);
                api.scanner().startCrawl(crawlConfig);
                result.addProperty("status", "crawl_started");
            } else {
                AuditConfiguration auditConfig = AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS);
                api.scanner().startAudit(auditConfig);
                result.addProperty("status", "audit_started");
            }

            result.addProperty("url", url);
            result.addProperty("crawl_and_audit", crawlAndAudit);
            result.addProperty("note", "Scan initiated. Use get_scan_issues_enhanced or get_scan_queue to check progress.");
        } catch (Exception e) {
            result.addProperty("error", "Failed to start active scan: " + e.getMessage());
        }
        return result;
    }

    private JsonObject getActiveScanStatus(JsonObject args) {
        JsonObject result = new JsonObject();
        try {
            var issues = api.siteMap().issues();
            result.addProperty("total_issues", issues.size());
            result.addProperty("note", "Use get_scan_issues_enhanced for detailed issue information with filtering");
        } catch (Exception e) {
            result.addProperty("error", "Failed to get scan status: " + e.getMessage());
        }
        return result;
    }

    private JsonObject getScanIssuesEnhanced(JsonObject args) {
        String severityFilter = args.has("severity_filter") ? args.get("severity_filter").getAsString() : null;
        String urlFilter = args.has("url_filter") ? args.get("url_filter").getAsString() : null;
        int count = args.has("count") ? args.get("count").getAsInt() : 50;
        int offset = args.has("offset") ? args.get("offset").getAsInt() : 0;

        JsonArray issuesArr = new JsonArray();
        try {
            var issues = api.siteMap().issues();
            int matched = 0;
            int skipped = 0;

            for (var issue : issues) {
                String severity = issue.severity().toString().toLowerCase();
                String url = issue.baseUrl();

                if (severityFilter != null && !severity.contains(severityFilter.toLowerCase())) continue;
                if (urlFilter != null && !url.matches(".*" + urlFilter + ".*")) continue;

                if (skipped < offset) { skipped++; continue; }
                if (matched >= count) break;

                JsonObject issueObj = new JsonObject();
                issueObj.addProperty("name", issue.name());
                issueObj.addProperty("severity", issue.severity().toString());
                issueObj.addProperty("confidence", issue.confidence().toString());
                issueObj.addProperty("url", url);
                issueObj.addProperty("host", issue.httpService().host());
                issueObj.addProperty("port", issue.httpService().port());
                issueObj.addProperty("protocol", issue.httpService().secure() ? "https" : "http");

                String remediation = issue.remediation();
                if (remediation != null && !remediation.isEmpty()) issueObj.addProperty("remediation", remediation);

                issuesArr.add(issueObj);
                matched++;
            }
        } catch (Exception e) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Failed to get scan issues: " + e.getMessage());
            return error;
        }

        JsonObject result = new JsonObject();
        result.add("issues", issuesArr);
        result.addProperty("count", issuesArr.size());
        return result;
    }

    private JsonObject getScanQueue(JsonObject args) {
        JsonObject result = new JsonObject();
        try {
            var issues = api.siteMap().issues();
            int inProgress = 0;
            int completed = issues.size();
            result.addProperty("total_issues", completed);
            result.addProperty("note", "Use get_scan_issues_enhanced for detailed issue information with filtering");
        } catch (Exception e) {
            result.addProperty("error", "Failed to get scan status: " + e.getMessage());
        }
        return result;
    }
}