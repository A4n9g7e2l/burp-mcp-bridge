package com.burpmcpbridge.tools.phase3;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

public class GraalJsRunner {

    public JsResult run(String jsCode, String functionName, String argsJson, String globalVarsJson) {
        try {
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("graal.js");
            if (engine == null) return JsResult.error("GraalVM JS engine not found on classpath");
            if (globalVarsJson != null && !globalVarsJson.isEmpty()) {
                engine.eval("var globals = " + globalVarsJson + "; for (var k in globals) { this[k] = globals[k]; }");
            }
            long start = System.currentTimeMillis();
            engine.eval(jsCode);
            String argsJs = (argsJson == null || argsJson.isEmpty()) ? "[]" : argsJson;
            Object result = engine.eval(functionName + ".apply(null, " + argsJs + ")");
            long elapsed = System.currentTimeMillis() - start;
            return new JsResult(result != null ? result.toString() : null, elapsed, null);
        } catch (Exception e) { return JsResult.error("Exception: " + e.getMessage()); }
    }

    public static class JsResult {
        public final String result; public final long elapsedMs; public final String error;
        private JsResult(String result, long elapsedMs, String error) {
            this.result = result; this.elapsedMs = elapsedMs; this.error = error;
        }
        public static JsResult error(String msg) { return new JsResult(null, 0, msg); }
    }
}
