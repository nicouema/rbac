package com.nicouema.authorization.rbac.service;

import com.nicouema.authorization.rbac.model.RbacUser;

/**
 * Strategy for loading a {@link RbacUser} from the subject (email) embedded in a JWT.
 *
 * <p>Implement this interface as a Spring bean in the consuming project so that
 * {@link com.nicouema.authorization.rbac.filter.JwtAuthenticationFilter} can set the
 * project's own user object as the {@code SecurityContext} principal.
 * Controllers can then inject it directly:</p>
 *
 * <pre>{@code
 * @GetMapping("/me")
 * @AuthenticationRequired
 * public ResponseEntity<?> me(@AuthenticationPrincipal AppUser user) { ... }
 * }</pre>
 *
 * <p>If no bean of this type is registered, the filter falls back to
 * {@link com.nicouema.authorization.rbac.model.RbacPrincipal} (token claims only,
 * no database call).</p>
 */
@FunctionalInterface
public interface RbacUserDetailsService {

    /**
     * Load a {@link RbacUser} by the email address extracted from the JWT subject.
     *
     * @param email the JWT subject value
     * @return the user for that email — must not be {@code null}
     * @throws com.nicouema.authorization.rbac.exception.UnauthorizedException
     *         (or any {@link RuntimeException}) if the user cannot be found
     */
    RbacUser loadUserByEmail(String email);
}

