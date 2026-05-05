package com.nicouema.authorization.rbac.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Externalized configuration for JWT token generation and validation.
 *
 * <pre>
 * rbac.jwt.secret=your-256-bit-or-longer-secret
 * rbac.jwt.expiration-ms=86400000   # 24 h
 * </pre>
 */
@ConfigurationProperties(prefix = "rbac.jwt")
public class JwtProperties {

    /**
     * HMAC-SHA256 signing secret.
     * <strong>Must be at least 32 characters (256 bits) long.</strong>
     * Override this in production with a securely generated value.
     */
    private String secret = "rbac-default-secret-key-change-me-in-production!!";

    /** Token validity duration in milliseconds. Defaults to 24 hours. */
    private long expirationMs = 86_400_000L;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public long getExpirationMs() {
        return expirationMs;
    }

    public void setExpirationMs(long expirationMs) {
        this.expirationMs = expirationMs;
    }
}
