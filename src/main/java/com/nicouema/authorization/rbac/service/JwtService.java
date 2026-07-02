package com.nicouema.authorization.rbac.service;

import com.nicouema.authorization.rbac.model.RbacUser;

import java.util.List;

/** JWT token operations. */
public interface JwtService {

    /** Generate a signed JWT for {@code user}, embedding their id and authorities as claims. */
    String generateToken(RbacUser user);

    /** Extract the subject (user id) from a token without validating expiry. */
    String extractSubject(String token);

    /** Extract the {@code authorities} claim from a token. */
    List<String> extractAuthorities(String token);

    /** Returns {@code true} if the token signature is valid and the token has not expired. */
    boolean isTokenValid(String token);
}
