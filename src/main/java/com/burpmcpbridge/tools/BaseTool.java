package com.burpmcpbridge.tools;

import burp.api.montoya.MontoyaApi;
import com.burpmcpbridge.mcp.ToolRegistry;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;

public abstract class BaseTool {

    protected final MontoyaApi api;
    protected final ToolRegistry registry;

    public BaseTool(MontoyaApi api, ToolRegistry registry) {
        this.api = api;
        this.registry = registry;
    }

    public abstract void register();

    protected JsonObject buildObjectSchema(JsonObject... properties) {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject props = new JsonObject();
        JsonArray required = new JsonArray();
        for (JsonObject prop : properties) {
            String name = prop.get("_name").getAsString();
            prop.remove("_name");
            props.add(name, prop);
            if (prop.has("_required") && prop.get("_required").getAsBoolean()) {
                required.add(name);
            }
            prop.remove("_required");
        }
        schema.add("properties", props);
        if (required.size() > 0) {
            schema.add("required", required);
        }
        return schema;
    }

    protected JsonObject stringProp(String name, String description, boolean required) {
        JsonObject prop = new JsonObject();
        prop.addProperty("_name", name);
        prop.addProperty("type", "string");
        prop.addProperty("description", description);
        prop.addProperty("_required", required);
        return prop;
    }

    protected JsonObject intProp(String name, String description, boolean required) {
        JsonObject prop = new JsonObject();
        prop.addProperty("_name", name);
        prop.addProperty("type", "integer");
        prop.addProperty("description", description);
        prop.addProperty("_required", required);
        return prop;
    }

    protected JsonObject boolProp(String name, String description, boolean required) {
        JsonObject prop = new JsonObject();
        prop.addProperty("_name", name);
        prop.addProperty("type", "boolean");
        prop.addProperty("description", description);
        prop.addProperty("_required", required);
        return prop;
    }
}
