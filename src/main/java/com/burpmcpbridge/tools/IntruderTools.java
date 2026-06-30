package com.burpmcpbridge.tools;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.burpmcpbridge.mcp.ToolRegistry;
import com.google.gson.JsonObject;

public class IntruderTools extends BaseTool {

    public IntruderTools(MontoyaApi api, ToolRegistry registry) {
        super(api, registry);
    }

    @Override
    public void register() {
        registry.register("intruder_start",
            "Start an Intruder attack with a request template and payload positions marked with SS",
            buildObjectSchema(
                stringProp("request_template", "HTTP request with payload positions marked as SSvalueSS", true),
                stringProp("target_host", "Target hostname", true),
                intProp("target_port", "Target port (default: 443)", false),
                boolProp("use_https", "Use HTTPS (default: true)", false),
                stringProp("payloads", "Comma-separated list of payloads", true),
                stringProp("attack_name", "Name for this attack tab", false)
            ),
            this::startIntruder
        );

        registry.register("intruder_get_results",
            "Get results from a running or completed Intruder attack",
            buildObjectSchema(
                stringProp("attack_name", "Name of the attack (optional, gets latest if omitted)", false),
                intProp("count", "Number of results to return (default: 50)", false),
                intProp("offset", "Offset for pagination (default: 0)", false)
            ),
            this::getIntruderResults
        );
    }

    private JsonObject startIntruder(JsonObject args) {
        String requestTemplate = args.has("request_template") ? args.get("request_template").getAsString() : "";
        String targetHost = args.has("target_host") ? args.get("target_host").getAsString() : "";
        int targetPort = args.has("target_port") ? args.get("target_port").getAsInt() : 443;
        boolean useHttps = !args.has("use_https") || args.get("use_https").getAsBoolean();
        String payloadsStr = args.has("payloads") ? args.get("payloads").getAsString() : "";
        String attackName = args.has("attack_name") ? args.get("attack_name").getAsString() : "MCP Bridge Attack";

        JsonObject result = new JsonObject();
        try {
            HttpRequest baseRequest = HttpRequest.httpRequest(requestTemplate);
            String[] payloads = payloadsStr.split(",");
            api.intruder().sendToIntruder(baseRequest);

            result.addProperty("status", "sent_to_intruder");
            result.addProperty("attack_name", attackName);
            result.addProperty("payload_count", payloads.length);
            result.addProperty("note", "Request sent to Intruder. Configure payload positions and start attack in Burp GUI -> Intruder tab.");
        } catch (Exception e) {
            result.addProperty("error", "Failed to start Intruder: " + e.getMessage());
        }
        return result;
    }

    private JsonObject getIntruderResults(JsonObject args) {
        String attackName = args.has("attack_name") ? args.get("attack_name").getAsString() : null;
        int count = args.has("count") ? args.get("count").getAsInt() : 50;
        int offset = args.has("offset") ? args.get("offset").getAsInt() : 0;

        JsonObject result = new JsonObject();
        result.addProperty("note", "Intruder results are available in Burp GUI -> Intruder tab -> Results. Use get_scan_issues_enhanced for vulnerability findings.");
        result.addProperty("attack_name", attackName != null ? attackName : "latest");
        result.addProperty("count_requested", count);
        result.addProperty("offset", offset);
        return result;
    }
}
