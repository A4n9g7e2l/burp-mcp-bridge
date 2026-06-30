package com.burpmcpbridge.tools.phase3;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class XpocRunner {
    private final String xpocPath;
    public XpocRunner(String xpocPath) { this.xpocPath = xpocPath; }

    public XpocResult run(String target, String pocFilter, String outputFormat, int timeout, boolean pluginsUpdate) {
        if (!new File(xpocPath).exists()) return XpocResult.error("xpoc not found: " + xpocPath);
        try {
            List<String> cmd = new ArrayList<>();
            cmd.add(xpocPath);
            cmd.add("-t"); cmd.add(target);
            cmd.add("-fmt"); cmd.add(outputFormat);
            cmd.add("-o"); cmd.add(System.getProperty("java.io.tmpdir") + "/xpoc-out.html");
            if (pocFilter != null && !pocFilter.isEmpty()) { cmd.add("-poc"); cmd.add(pocFilter); }
            if (pluginsUpdate) cmd.add("pull");
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line; while ((line = reader.readLine()) != null) output.append(line).append("\n");
            }
            boolean exited = proc.waitFor(timeout, TimeUnit.SECONDS);
            if (!exited) { proc.destroyForcibly(); return XpocResult.error("xpoc timeout after " + timeout + "s"); }
            int exitCode = proc.exitValue();
            return XpocResult.fromOutput(output.toString(), exitCode);
        } catch (Exception e) { return XpocResult.error("Exception: " + e.getMessage()); }
    }

    public static class XpocResult {
        public final int exitCode; public final boolean vulnerable;
        public final String vulnerabilities; public final String error;
        private XpocResult(int exitCode, boolean vulnerable, String vulnerabilities, String error) {
            this.exitCode = exitCode; this.vulnerable = vulnerable;
            this.vulnerabilities = vulnerabilities; this.error = error;
        }
        public static XpocResult error(String msg) { return new XpocResult(-1, false, null, msg); }
        public static XpocResult fromOutput(String output, int exitCode) {
            boolean vuln = output.contains("[VULNERABLE]") || output.contains("vulnerability found");
            int idx = Math.max(output.indexOf("[VULNERABLE]"), output.indexOf("vulnerability found"));
            String vulnSection = idx > 0 ? output.substring(idx, Math.min(idx + 1000, output.length())).trim() : null;
            return new XpocResult(exitCode, vuln, vulnSection, null);
        }
    }
}
