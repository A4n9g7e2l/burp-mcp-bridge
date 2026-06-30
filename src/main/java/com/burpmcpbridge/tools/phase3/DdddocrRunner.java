package com.burpmcpbridge.tools.phase3;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class DdddocrRunner {
    private final String pythonPath;
    private final String bridgeScript;
    public DdddocrRunner(String pythonPath, String bridgeScript) {
        this.pythonPath = pythonPath;
        this.bridgeScript = bridgeScript;
    }

    public DdddocrResult solve(String imageBase64, int timeout) {
        if (!new File(pythonPath).exists()) return DdddocrResult.error("python not found: " + pythonPath);
        if (!new File(bridgeScript).exists()) return DdddocrResult.error("ddddocr_bridge.py not found: " + bridgeScript);
        try {
            ProcessBuilder pb = new ProcessBuilder(pythonPath, bridgeScript);
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            try (OutputStream stdin = proc.getOutputStream()) {
                stdin.write(imageBase64.getBytes(StandardCharsets.UTF_8));
                stdin.flush();
            }
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line; while ((line = reader.readLine()) != null) output.append(line);
            }
            boolean exited = proc.waitFor(timeout, TimeUnit.SECONDS);
            if (!exited) { proc.destroyForcibly(); return DdddocrResult.error("ddddocr timeout after " + timeout + "s"); }
            String json = output.toString().trim();
            String result = extractJsonField(json, "result");
            String error = extractJsonField(json, "error");
            if (error != null) return DdddocrResult.error(error);
            return new DdddocrResult(result, 0.85, null);
        } catch (Exception e) { return DdddocrResult.error("Exception: " + e.getMessage()); }
    }

    private static String extractJsonField(String json, String field) {
        String pattern = "\"" + field + "\":";
        int idx = json.indexOf(pattern);
        if (idx < 0) return null;
        int start = json.indexOf('"', idx + pattern.length());
        if (start < 0) return null;
        int end = json.indexOf('"', start + 1);
        if (end < 0) return null;
        return json.substring(start + 1, end);
    }

    public static class DdddocrResult {
        public final String result; public final double confidence; public final String error;
        private DdddocrResult(String result, double confidence, String error) {
            this.result = result; this.confidence = confidence; this.error = error;
        }
        public static DdddocrResult error(String msg) { return new DdddocrResult(null, 0.0, msg); }
    }
}
