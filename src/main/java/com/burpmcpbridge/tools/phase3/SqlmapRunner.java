package com.burpmcpbridge.tools.phase3;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class SqlmapRunner {
    private final String sqlmapPath;
    private final String pythonPath;

    public SqlmapRunner(String sqlmapPath, String pythonPath) {
        this.sqlmapPath = sqlmapPath;
        this.pythonPath = pythonPath;
    }

    public SqlmapResult run(String targetUrl, String method, String data, String cookie,
                             int level, int risk, String technique, int timeout, int threads) {
        if (!new File(sqlmapPath).exists()) return SqlmapResult.error("sqlmap not found: " + sqlmapPath);
        if (!new File(pythonPath).exists()) return SqlmapResult.error("python not found: " + pythonPath);
        try {
            List<String> cmd = new ArrayList<>();
            cmd.add(pythonPath); cmd.add(sqlmapPath);
            cmd.add("-u"); cmd.add(targetUrl);
            cmd.add("--batch");
            cmd.add("--level"); cmd.add(String.valueOf(level));
            cmd.add("--risk"); cmd.add(String.valueOf(risk));
            cmd.add("--technique"); cmd.add(technique);
            cmd.add("--timeout"); cmd.add(String.valueOf(timeout));
            cmd.add("--threads"); cmd.add(String.valueOf(threads));
            if ("POST".equalsIgnoreCase(method) && data != null && !data.isEmpty()) {
                cmd.add("--data"); cmd.add(data);
            }
            if (cookie != null && !cookie.isEmpty()) {
                cmd.add("--cookie"); cmd.add(cookie);
            }
            cmd.add("--output-dir"); cmd.add(System.getProperty("java.io.tmpdir") + "/sqlmap-out");
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line; while ((line = reader.readLine()) != null) output.append(line).append("\n");
            }
            boolean exited = proc.waitFor(timeout + 30, TimeUnit.SECONDS);
            if (!exited) { proc.destroyForcibly(); return SqlmapResult.error("sqlmap timeout after " + timeout + "s"); }
            int exitCode = proc.exitValue();
            return SqlmapResult.fromOutput(output.toString(), exitCode);
        } catch (Exception e) { return SqlmapResult.error("Exception: " + e.getMessage()); }
    }

    public static class SqlmapResult {
        public final int exitCode; public final boolean vulnerable;
        public final String dbms; public final String payload;
        public final String injectionType; public final String dumpSummary;
        public final String error;
        private SqlmapResult(int exitCode, boolean vulnerable, String dbms, String payload,
                              String injectionType, String dumpSummary, String error) {
            this.exitCode = exitCode; this.vulnerable = vulnerable;
            this.dbms = dbms; this.payload = payload;
            this.injectionType = injectionType; this.dumpSummary = dumpSummary;
            this.error = error;
        }
        public static SqlmapResult error(String msg) { return new SqlmapResult(-1, false, null, null, null, null, msg); }
        public static SqlmapResult fromOutput(String output, int exitCode) {
            boolean vuln = output.contains("is vulnerable") || output.contains("injectable");
            String dbms = extractLine(output, "back-end DBMS:");
            String payload = extractLine(output, "Payload:");
            String injType = extractLine(output, "Type:") != null ? extractLine(output, "Type:") : extractLine(output, "injection:");
            String dump = extractSection(output, "available databases");
            return new SqlmapResult(exitCode, vuln, dbms, payload, injType, dump, null);
        }
        private static String extractLine(String output, String prefix) {
            for (String line : output.split("\n")) if (line.contains(prefix)) return line.trim();
            return null;
        }
        private static String extractSection(String output, String marker) {
            int idx = output.indexOf(marker);
            if (idx < 0) return null;
            return output.substring(idx, Math.min(idx + 500, output.length())).trim();
        }
    }
}
