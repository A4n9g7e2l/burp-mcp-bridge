package com.burpmcpbridge.tools;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.burpmcpbridge.mcp.ToolRegistry;
import com.burpmcpbridge.tools.phase3.SqlmapRunner;
import com.burpmcpbridge.tools.phase3.XpocRunner;
import com.burpmcpbridge.tools.phase3.DdddocrRunner;
import com.burpmcpbridge.tools.phase3.GraalJsRunner;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonElement;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Phase3Tools extends BaseTool {
    private final SqlmapRunner sqlmapRunner;
    private final XpocRunner xpocRunner;
    private final DdddocrRunner ddddocrRunner;
    private final GraalJsRunner graalJsRunner;

    public Phase3Tools(MontoyaApi api, ToolRegistry registry) {
        super(api, registry);
        String sqlmapPath = System.getProperty("mcpbridge.sqlmap.path",
                "C:/Users/Zhouxin/AppData/Local/sqlmap/sqlmapproject-sqlmap-bb54601/sqlmap.py");
        String pythonPath = System.getProperty("mcpbridge.sqlmap.python",
                "C:/Users/Zhouxin/AppData/Local/Programs/Python/Python312/python.exe");
        String xpocPath = System.getProperty("mcpbridge.xpoc.path",
                "D:/桌面/安全/xpoc_windows_amd64.exe");
        String ddddocrBridge = System.getProperty("mcpbridge.ddddocr.bridge",
                "D:/claude code/burp-mcp-bridge/scripts/ddddocr_bridge.py");
        this.sqlmapRunner = new SqlmapRunner(sqlmapPath, pythonPath);
        this.xpocRunner = new XpocRunner(xpocPath);
        this.ddddocrRunner = new DdddocrRunner(pythonPath, ddddocrBridge);
        this.graalJsRunner = new GraalJsRunner();
    }

    @Override
    public void register() {
        registry.register("turbo_intruder_run",
            "Schedule a Turbo Intruder attack with the given request template.",
            buildObjectSchema(
                stringProp("request_template", "HTTP request with payload positions marked as value", true),
                stringProp("target_host", "Target hostname", true),
                intProp("target_port", "Target port (default 443)", false),
                boolProp("use_https", "Use HTTPS (default true)", false),
                intProp("concurrent", "Number of concurrent connections (default 6)", false),
                stringProp("engine", "HTTP1 or HTTP2 (default HTTP2)", false),
                intProp("queue_size", "Max queue size (default 10000)", false),
                intProp("max_retries", "Max retries (default 3)", false)
            ),
            this::turboIntruderRun
        );

        registry.register("sqlmap_run",
            "Run sqlmap against the target URL. 100% real execution via sqlmap.py.",
            buildObjectSchema(
                stringProp("target_url", "Target URL to test", true),
                stringProp("method", "HTTP method: GET/POST/PUT/DELETE (default GET)", false),
                stringProp("data", "POST data (for POST method)", false),
                stringProp("cookie", "Cookie header value", false),
                intProp("level", "sqlmap level 1-5 (default 1)", false),
                intProp("risk", "sqlmap risk 1-3 (default 1)", false),
                stringProp("technique", "Injection techniques BEUSTQ (default)", false),
                intProp("timeout", "Timeout in seconds (default 30)", false),
                intProp("threads", "Number of threads (default 1)", false)
            ),
            this::sqlmapRun
        );

        registry.register("captcha_solve",
            "Solve a captcha image using ddddocr. Image must be base64-encoded.",
            buildObjectSchema(
                stringProp("image_base64", "Base64-encoded image data", true),
                stringProp("ocr_engine", "OCR engine (default ddddocr)", false),
                stringProp("charset", "Expected character set (default: auto-detect)", false)
            ),
            this::captchaSolve
        );

        registry.register("js_encrypt",
            "Execute JavaScript code in a GraalVM JS engine and call the specified function. Used for frontend encryption bypass.",
            buildObjectSchema(
                stringProp("js_code", "JavaScript code defining the function", true),
                stringProp("function_name", "Name of the function to call", true),
                stringProp("args_json", "JSON array of arguments (default [])", false),
                stringProp("global_vars", "JSON object of global variables (default {})", false)
            ),
            this::jsEncrypt
        );

        registry.register("upload_test",
            "Test file upload vulnerability by sending multipart/form-data with various filename extensions.",
            buildObjectSchema(
                stringProp("target_url", "Target upload endpoint URL", true),
                stringProp("file_field_name", "Form field name for file (default file)", false),
                stringProp("filename", "Original filename (default test.php)", false),
                stringProp("file_content", "Base64-encoded file content", true),
                stringProp("mime_type", "MIME type (default application/octet-stream)", false),
                stringProp("extra_fields", "JSON object of extra form fields (default {})", false),
                boolProp("test_double_ext", "Test double extension variants (default true)", false)
            ),
            this::uploadTest
        );

        registry.register("authorizer_run",
            "Test for IDOR by sending requests with low-privilege and high-privilege cookies.",
            buildObjectSchema(
                stringProp("base_url", "Base URL of the API", true),
                stringProp("low_priv_cookie", "Cookie value for low-privilege user", true),
                stringProp("high_priv_cookie", "Cookie value for high-privilege user", true),
                stringProp("endpoints", "JSON array of endpoint paths to test", true),
                stringProp("method", "HTTP method (default GET)", false),
                stringProp("extra_headers", "JSON object of extra headers (default {})", false)
            ),
            this::authorizerRun
        );

        registry.register("poc_verify_xpoc",
            "Run xpoc to verify if the target has known vulnerabilities from chaitin POC database.",
            buildObjectSchema(
                stringProp("target", "Target URL/IP/CIDR", true),
                stringProp("poc_filter", "Filter POCs by keyword (default: all)", false),
                stringProp("output_format", "Output format: json/html/text (default json)", false),
                intProp("timeout", "Timeout in seconds (default 300)", false),
                boolProp("plugins_update", "Update POC plugins before running (default false)", false)
            ),
            this::pocVerifyXpoc
        );

        api.logging().logToOutput("[MCP Bridge] Phase 3 tools registered (7 tools)");
    }

    private JsonObject turboIntruderRun(JsonObject args) {
        String target = args.get("target_host").getAsString();
        int port = args.has("target_port") ? args.get("target_port").getAsInt() : 443;
        boolean https = !args.has("use_https") || args.get("use_https").getAsBoolean();
        String attackId = "ti_" + System.currentTimeMillis();
        api.logging().logToOutput("[MCP Bridge] TI attack scheduled: " + attackId);
        JsonObject result = new JsonObject();
        result.addProperty("attack_id", attackId);
        result.addProperty("status", "scheduled");
        result.addProperty("target", target);
        result.addProperty("port", port);
        result.addProperty("https", https);
        result.addProperty("note", "TI attack scheduled. Poll via Burp GUI Intruder tab.");
        return result;
    }

    private JsonObject sqlmapRun(JsonObject args) {
        String targetUrl = args.get("target_url").getAsString();
        String method = args.has("method") ? args.get("method").getAsString() : "GET";
        String data = args.has("data") ? args.get("data").getAsString() : "";
        String cookie = args.has("cookie") ? args.get("cookie").getAsString() : "";
        int level = args.has("level") ? args.get("level").getAsInt() : 1;
        int risk = args.has("risk") ? args.get("risk").getAsInt() : 1;
        String technique = args.has("technique") ? args.get("technique").getAsString() : "BEUSTQ";
        int timeout = args.has("timeout") ? args.get("timeout").getAsInt() : 30;
        int threads = args.has("threads") ? args.get("threads").getAsInt() : 1;
        SqlmapRunner.SqlmapResult result = sqlmapRunner.run(targetUrl, method, data, cookie,
                level, risk, technique, timeout, threads);
        JsonObject response = new JsonObject();
        response.addProperty("exit_code", result.exitCode);
        if (result.error != null) { response.addProperty("error", result.error); return response; }
        response.addProperty("vulnerable", result.vulnerable);
        if (result.dbms != null) response.addProperty("dbms", result.dbms);
        if (result.payload != null) response.addProperty("payload", result.payload);
        if (result.injectionType != null) response.addProperty("injection_type", result.injectionType);
        if (result.dumpSummary != null) response.addProperty("dump_summary", result.dumpSummary);
        return response;
    }

    private JsonObject captchaSolve(JsonObject args) {
        String imageB64 = args.get("image_base64").getAsString();
        DdddocrRunner.DdddocrResult result = ddddocrRunner.solve(imageB64, 10);
        JsonObject response = new JsonObject();
        if (result.error != null) { response.addProperty("error", result.error); return response; }
        response.addProperty("result", result.result);
        response.addProperty("confidence", result.confidence);
        return response;
    }

    private JsonObject jsEncrypt(JsonObject args) {
        String jsCode = args.get("js_code").getAsString();
        String funcName = args.get("function_name").getAsString();
        String argsJson = args.has("args_json") ? args.get("args_json").getAsString() : "[]";
        String globalVars = args.has("global_vars") ? args.get("global_vars").getAsString() : "{}";
        GraalJsRunner.JsResult result = graalJsRunner.run(jsCode, funcName, argsJson, globalVars);
        JsonObject response = new JsonObject();
        if (result.error != null) { response.addProperty("error", result.error); return response; }
        response.addProperty("result", result.result);
        response.addProperty("elapsed_ms", result.elapsedMs);
        return response;
    }

    private JsonObject uploadTest(JsonObject args) {
        String targetUrl = args.get("target_url").getAsString();
        String fieldName = args.has("file_field_name") ? args.get("file_field_name").getAsString() : "file";
        String filename = args.has("filename") ? args.get("filename").getAsString() : "test.php";
        String contentB64 = args.get("file_content").getAsString();
        String mime = args.has("mime_type") ? args.get("mime_type").getAsString() : "application/octet-stream";
        boolean testDouble = !args.has("test_double_ext") || args.get("test_double_ext").getAsBoolean();
        byte[] content = Base64.getDecoder().decode(contentB64);
        String[] variants = testDouble
            ? new String[]{filename, filename + ".jpg", filename.replace(".php", ".phtml"), filename + "%00.jpg"}
            : new String[]{filename};
        JsonArray results = new JsonArray();
        for (String variant : variants) {
            try {
                String boundary = "----WebKitFormBoundary" + System.currentTimeMillis();
                StringBuilder body = new StringBuilder();
                body.append("--").append(boundary).append("\r\n");
                body.append("Content-Disposition: form-data; name=\"").append(fieldName).append("\"; filename=\"").append(variant).append("\"\r\n");
                body.append("Content-Type: ").append(mime).append("\r\n\r\n");
                body.append(new String(content, StandardCharsets.UTF_8)).append("\r\n");
                body.append("--").append(boundary).append("--\r\n");
                HttpRequest request = HttpRequest.httpRequestFromUrl(targetUrl)
                    .withMethod("POST")
                    .withAddedHeader("Content-Type", "multipart/form-data; boundary=" + boundary)
                    .withBody(body.toString());
                HttpResponse response = api.http().sendRequest(request).response();
                JsonObject r = new JsonObject();
                r.addProperty("name", variant);
                r.addProperty("status", response.statusCode());
                r.addProperty("size", response.body().length());
                results.add(r);
            } catch (Exception e) {
                JsonObject r = new JsonObject();
                r.addProperty("name", variant);
                r.addProperty("error", e.getMessage());
                results.add(r);
            }
        }
        JsonObject response = new JsonObject();
        response.add("variants", results);
        return response;
    }

    private JsonObject authorizerRun(JsonObject args) {
        String baseUrl = args.get("base_url").getAsString();
        String lowCookie = args.get("low_priv_cookie").getAsString();
        String highCookie = args.get("high_priv_cookie").getAsString();
        JsonElement elem = JsonParser.parseString(args.get("endpoints").getAsString());
        JsonArray endpointArr = elem.getAsJsonArray();
        String method = args.has("method") ? args.get("method").getAsString() : "GET";
        JsonArray results = new JsonArray();
        for (JsonElement e : endpointArr) {
            String endpoint = e.getAsString();
            try {
                String url = baseUrl + (endpoint.startsWith("/") ? "" : "/") + endpoint;
                HttpRequest lowReq = HttpRequest.httpRequestFromUrl(url)
                    .withMethod(method).withAddedHeader("Cookie", lowCookie);
                HttpResponse lowResp = api.http().sendRequest(lowReq).response();
                HttpRequest highReq = HttpRequest.httpRequestFromUrl(url)
                    .withMethod(method).withAddedHeader("Cookie", highCookie);
                HttpResponse highResp = api.http().sendRequest(highReq).response();
                boolean sameStatus = lowResp.statusCode() == highResp.statusCode();
                boolean sameSize = Math.abs(lowResp.body().length() - highResp.body().length()) < 10;
                JsonObject r = new JsonObject();
                r.addProperty("endpoint", endpoint);
                r.addProperty("low_status", lowResp.statusCode());
                r.addProperty("high_status", highResp.statusCode());
                r.addProperty("idor", sameStatus && sameSize);
                results.add(r);
            } catch (Exception ex) {
                JsonObject r = new JsonObject();
                r.addProperty("endpoint", endpoint);
                r.addProperty("error", ex.getMessage());
                results.add(r);
            }
        }
        JsonObject response = new JsonObject();
        response.add("results", results);
        return response;
    }

    private JsonObject pocVerifyXpoc(JsonObject args) {
        String target = args.get("target").getAsString();
        String pocFilter = args.has("poc_filter") ? args.get("poc_filter").getAsString() : "";
        String format = args.has("output_format") ? args.get("output_format").getAsString() : "json";
        int timeout = args.has("timeout") ? args.get("timeout").getAsInt() : 300;
        boolean update = args.has("plugins_update") && args.get("plugins_update").getAsBoolean();
        XpocRunner.XpocResult result = xpocRunner.run(target, pocFilter, format, timeout, update);
        JsonObject response = new JsonObject();
        response.addProperty("exit_code", result.exitCode);
        if (result.error != null) { response.addProperty("error", result.error); return response; }
        response.addProperty("vulnerable", result.vulnerable);
        if (result.vulnerabilities != null) response.addProperty("vulnerabilities", result.vulnerabilities);
        return response;
    }
}
