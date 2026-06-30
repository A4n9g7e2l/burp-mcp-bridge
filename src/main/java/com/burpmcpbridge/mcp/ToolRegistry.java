package com.burpmcpbridge.mcp;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

public class ToolRegistry {

    private final Map<String, ToolDefinition> tools = new LinkedHashMap<>();

    public static class ToolDefinition {
        public final String name;
        public final String description;
        public final JsonObject inputSchema;
        public final Function<JsonObject, JsonObject> handler;

        public ToolDefinition(String name, String description,
                              JsonObject inputSchema, Function<JsonObject, JsonObject> handler) {
            this.name = name;
            this.description = description;
            this.inputSchema = inputSchema;
            this.handler = handler;
        }
    }

    public void register(String name, String description,
                         JsonObject inputSchema, Function<JsonObject, JsonObject> handler) {
        tools.put(name, new ToolDefinition(name, description, inputSchema, handler));
    }

    public ToolDefinition getTool(String name) {
        return tools.get(name);
    }

    public JsonArray listTools() {
        JsonArray arr = new JsonArray();
        for (ToolDefinition def : tools.values()) {
            JsonObject tool = new JsonObject();
            tool.addProperty("name", def.name);
            tool.addProperty("description", def.description);
            tool.add("inputSchema", def.inputSchema);
            arr.add(tool);
        }
        return arr;
    }

    public int getToolCount() {
        return tools.size();
    }

    public JsonObject callTool(String name, JsonObject arguments) {
        ToolDefinition def = tools.get(name);
        if (def == null) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Tool not found: " + name);
            return error;
        }
        try {
            return def.handler.apply(arguments != null ? arguments : new JsonObject());
        } catch (Exception e) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Tool execution failed: " + e.getMessage());
            return error;
        }
    }
}
