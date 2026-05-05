package com.nicouema.authorization.rbac.service;

import com.nicouema.authorization.rbac.config.JwtProperties;
import com.nicouema.authorization.rbac.model.RbacUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtServiceImpl implements JwtService {

    private final JwtProperties properties;

    public JwtServiceImpl(JwtProperties properties) {
        this.properties = properties;
    }

    // ------------------------------------------------------------------ generate

    @Override
    public String generateToken(RbacUser user) {
        Map<String, Object> extraClaims = new HashMap<>();
        // getAuthorities() returns Collection<? extends GrantedAuthority> — map to plain strings
        extraClaims.put("authorities", user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        return Jwts.builder()
                .claims(extraClaims)
                .subject(user.getEmail())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + properties.getExpirationMs()))
                .signWith(secretKey())
                .compact();
    }

    // ------------------------------------------------------------------ parse

    @Override
    public String extractEmail(String token) {
        return parseClaims(token).getSubject();
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<String> extractAuthorities(String token) {
        Object raw = parseClaims(token).get("authorities");
        if (raw instanceof List<?> list) {
            return list.stream().map(Object::toString).collect(Collectors.toList());
        }
        return List.of();
    }

    @Override
    public boolean isTokenValid(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // ------------------------------------------------------------------ helpers

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey secretKey() {
        return Keys.hmacShaKeyFor(properties.getSecret().getBytes(StandardCharsets.UTF_8));
    }
}
