package com.burpmcpbridge.tools;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.burpmcpbridge.mcp.ToolRegistry;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.List;

public class PluginAnnotationTools extends BaseTool {

    public PluginAnnotationTools(MontoyaApi api, ToolRegistry registry) {
        super(api, registry);
    }

    @Override
    public void register() {
        registry.register("hae_get_highlights",
            "Read HaE (Highlight and Extract) plugin results from proxy history annotations. Returns highlighted items with color coding and extracted data.",
            buildObjectSchema(
                stringProp("color_filter", "Filter by highlight color: red/orange/yellow/green/blue/pink/purple (optional)", false),
                stringProp("keyword_filter", "Filter by keyword in notes (optional)", false),
                intProp("count", "Maximum results to return (default: 100)", false),
                boolProp("include_headers", "Include request headers in output (default: false)", false),
                boolProp("include_response_headers", "Include response headers in output (default: false)", false)
            ),
            this::haeGetHighlights
        );

        registry.register("domain_hunter_get_results",
            "Read domain_hunter plugin results from proxy history. Collects discovered subdomains and related domains from annotations.",
            buildObjectSchema(
                stringProp("parent_domain", "Filter by parent domain (optional)", false),
                intProp("count", "Maximum results to return (default: 100)", false)
            ),
            this::domainHunterGetResults
        );

        registry.register("xkeys_get_findings",
            "Read Xkeys plugin findings from proxy history. Extracts API keys, tokens, and sensitive strings discovered by Xkeys.",
            buildObjectSchema(
                stringProp("key_type_filter", "Filter by key type: api_key, token, secret, password, private_key (optional)", false),
                intProp("count", "Maximum findings to return (default: 100)", false),
                boolProp("include_context", "Include surrounding context of the finding (default: false)", false)
            ),
            this::xkeysGetFindings
        );
    }

    private JsonObject haeGetHighlights(JsonObject args) {
        String colorFilter = args.has("color_filter") ? args.get("color_filter").getAsString() : null;
        String keywordFilter = args.has("keyword_filter") ? args.get("keyword_filter").getAsString() : null;
        int count = args.has("count") ? args.get("count").getAsInt() : 100;
        boolean includeHeaders = args.has("include_headers") && args.get("include_headers").getAsBoolean();
        boolean includeRespHeaders = args.has("include_response_headers") && args.get("include_response_headers").getAsBoolean();

        JsonArray highlights = new JsonArray();
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int found = 0;

            for (int i = history.size() - 1; i >= 0 && found < count; i++) {
                var item = history.get(i);
                String highlightColor = item.annotations().highlightColor() != null
                    ? item.annotations().highlightColor().toString() : null;
                String notes = item.annotations().notes();

                if (highlightColor == null && (notes == null || notes.isEmpty())) continue;
                if (colorFilter != null && highlightColor != null && !highlightColor.equalsIgnoreCase(colorFilter)) continue;
                if (keywordFilter != null && notes != null && !notes.toLowerCase().contains(keywordFilter.toLowerCase())) continue;

                JsonObject entry = new JsonObject();
                entry.addProperty("url", item.request().url());
                entry.addProperty("method", item.request().method());
                if (item.hasResponse()) {
                    entry.addProperty("status_code", item.response().statusCode());
                }
                if (highlightColor != null) {
                    entry.addProperty("highlight_color", highlightColor);
                    entry.addProperty("color_meaning", interpretHaEColor(highlightColor));
                }
                if (notes != null && !notes.isEmpty()) {
                    entry.addProperty("notes", notes);
                    extractKeyFindingsFromNotes(notes, entry);
                }

                if (includeHeaders) {
                    JsonArray reqHeaders = new JsonArray();
                    for (var h : item.request().headers()) {
                        reqHeaders.add(h.name() + ": " + h.value());
                    }
                    entry.add("request_headers", reqHeaders);
                }
                if (includeRespHeaders && item.hasResponse()) {
                    JsonArray respHeaders = new JsonArray();
                    for (var h : item.response().headers()) {
                        respHeaders.add(h.name() + ": " + h.value());
                    }
                    entry.add("response_headers", respHeaders);
                }

                highlights.add(entry);
                found++;
            }
        } catch (Exception e) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Failed to read HaE highlights: " + e.getMessage());
            return error;
        }

        JsonObject result = new JsonObject();
        result.add("highlights", highlights);
        result.addProperty("count", highlights.size());
        result.addProperty("source", "Proxy history annotations (HaE plugin markers)");
        return result;
    }

    private JsonObject domainHunterGetResults(JsonObject args) {
        String parentDomain = args.has("parent_domain") ? args.get("parent_domain").getAsString() : null;
        int count = args.has("count") ? args.get("count").getAsInt() : 100;

        JsonArray domains = new JsonArray();
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int found = 0;

            for (int i = history.size() - 1; i >= 0 && found < count; i++) {
                var item = history.get(i);
                String notes = item.annotations().notes();
                String highlightColor = item.annotations().highlightColor() != null
                    ? item.annotations().highlightColor().toString() : null;

                if ((notes == null || notes.isEmpty()) && highlightColor == null) continue;

                boolean isDomainRelated = false;
                if (notes != null) {
                    String notesLower = notes.toLowerCase();
                    if (notesLower.contains("domain") || notesLower.contains("subdomain")
                        || notesLower.contains("subdomain") || notesLower.contains("dns")
                        || notesLower.contains("host") || notesLower.contains("cname")) {
                        isDomainRelated = true;
                    }
                }

                String url = item.request().url();
                String host = extractHostFromUrl(url);

                if (parentDomain != null && !host.endsWith(parentDomain)) continue;

                if (isDomainRelated || (highlightColor != null)) {
                    JsonObject domainEntry = new JsonObject();
                    domainEntry.addProperty("url", url);
                    domainEntry.addProperty("host", host);
                    domainEntry.addProperty("method", item.request().method());
                    if (item.hasResponse()) {
                        domainEntry.addProperty("status_code", item.response().statusCode());
                    }
                    if (notes != null && !notes.isEmpty()) {
                        domainEntry.addProperty("notes", notes);
                    }
                    if (highlightColor != null) {
                        domainEntry.addProperty("highlight_color", highlightColor);
                    }
                    domains.add(domainEntry);
                    found++;
                }
            }
        } catch (Exception e) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Failed to read domain_hunter results: " + e.getMessage());
            return error;
        }

        JsonObject result = new JsonObject();
        result.add("domains", domains);
        result.addProperty("count", domains.size());
        result.addProperty("note", "Results derived from proxy history annotations. Install domain_hunter plugin for comprehensive subdomain discovery.");
        return result;
    }

    private JsonObject xkeysGetFindings(JsonObject args) {
        String keyTypeFilter = args.has("key_type_filter") ? args.get("key_type_filter").getAsString() : null;
        int count = args.has("count") ? args.get("count").getAsInt() : 100;
        boolean includeContext = args.has("include_context") && args.get("include_context").getAsBoolean();

        JsonArray findings = new JsonArray();
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int found = 0;

            for (int i = history.size() - 1; i >= 0 && found < count; i++) {
                var item = history.get(i);
                String notes = item.annotations().notes();
                String highlightColor = item.annotations().highlightColor() != null
                    ? item.annotations().highlightColor().toString() : null;

                if ((notes == null || notes.isEmpty()) && highlightColor == null) continue;

                boolean isKeyFinding = false;
                String keyType = "unknown";

                if (notes != null) {
                    String notesLower = notes.toLowerCase();
                    if (notesLower.contains("api_key") || notesLower.contains("apikey") || notesLower.contains("api key")) {
                        isKeyFinding = true;
                        keyType = "api_key";
                    } else if (notesLower.contains("token") || notesLower.contains("bearer") || notesLower.contains("jwt")) {
                        isKeyFinding = true;
                        keyType = "token";
                    } else if (notesLower.contains("secret") || notesLower.contains("private_key") || notesLower.contains("private key")) {
                        isKeyFinding = true;
                        keyType = "secret";
                    } else if (notesLower.contains("password") || notesLower.contains("passwd") || notesLower.contains("pwd")) {
                        isKeyFinding = true;
                        keyType = "password";
                    } else if (notesLower.contains("key") || notesLower.contains("credential")) {
                        isKeyFinding = true;
                        keyType = "api_key";
                    } else if (highlightColor != null) {
                        isKeyFinding = true;
                    }
                } else if (highlightColor != null) {
                    isKeyFinding = true;
                }

                if (!isKeyFinding) continue;
                if (keyTypeFilter != null && !keyType.equals(keyTypeFilter)) continue;

                JsonObject finding = new JsonObject();
                finding.addProperty("url", item.request().url());
                finding.addProperty("method", item.request().method());
                if (item.hasResponse()) {
                    finding.addProperty("status_code", item.response().statusCode());
                }
                finding.addProperty("key_type", keyType);
                if (notes != null && !notes.isEmpty()) {
                    finding.addProperty("notes", notes);
                }
                if (highlightColor != null) {
                    finding.addProperty("highlight_color", highlightColor);
                }

                if (includeContext) {
                    String reqBody = item.request().bodyToString();
                    if (!reqBody.isEmpty()) {
                        finding.addProperty("request_body_preview", reqBody.length() > 300
                            ? reqBody.substring(0, 300) + "..." : reqBody);
                    }
                    if (item.hasResponse()) {
                        String respBody = item.response().bodyToString();
                        finding.addProperty("response_body_preview", respBody.length() > 300
                            ? respBody.substring(0, 300) + "..." : respBody);
                    }
                }

                findings.add(finding);
                found++;
            }
        } catch (Exception e) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Failed to read Xkeys findings: " + e.getMessage());
            return error;
        }

        JsonObject result = new JsonObject();
        result.add("findings", findings);
        result.addProperty("count", findings.size());
        result.addProperty("note", "Results derived from proxy history annotations. Install Xkeys plugin for API key extraction.");
        return result;
    }

    private String interpretHaEColor(String color) {
        switch (color.toLowerCase()) {
            case "red": return "Critical finding (credentials, secrets, PII)";
            case "orange": return "High severity (tokens, API keys, internal IPs)";
            case "yellow": return "Medium severity (emails, phone numbers, IDs)";
            case "green": return "Low severity (comments, debug info)";
            case "blue": return "Informational (headers, technologies)";
            case "pink": return "Sensitive paths, upload points";
            case "purple": return "Custom markers";
            default: return "Unknown color meaning";
        }
    }

    private void extractKeyFindingsFromNotes(String notes, JsonObject entry) {
        String[] sensitivePatterns = {
            "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
            "private_key", "access_key", "secret_key", "authorization",
            "cookie", "session", "jwt", "bearer", "credential"
        };

        String notesLower = notes.toLowerCase();
        JsonArray detectedTypes = new JsonArray();
        for (String pattern : sensitivePatterns) {
            if (notesLower.contains(pattern)) {
                detectedTypes.add(pattern);
            }
        }
        if (detectedTypes.size() > 0) {
            entry.add("detected_sensitive_types", detectedTypes);
        }
    }

    private String extractHostFromUrl(String url) {
        try {
            String stripped = url;
            if (stripped.startsWith("https://")) stripped = stripped.substring(8);
            else if (stripped.startsWith("http://")) stripped = stripped.substring(7);
            int slashIdx = stripped.indexOf("/");
            if (slashIdx > 0) stripped = stripped.substring(0, slashIdx);
            int colonIdx = stripped.lastIndexOf(":");
            if (colonIdx > 0) stripped = stripped.substring(0, colonIdx);
            return stripped;
        } catch (Exception e) {
            return url;
        }
    }
}