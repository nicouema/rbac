package com.nicouema.authorization.rbac.model;

import java.util.Collections;
import java.util.List;

/**
 * Immutable principal stored in the {@code SecurityContext} after JWT validation.
 *
 * <p>Used when no {@link com.nicouema.authorization.rbac.service.RbacUserDetailsService}
 * bean is present — built purely from JWT claims with no database call.</p>
 *
 * <pre>{@code
 * @GetMapping("/me")
 * public ResponseEntity<?> me(@AuthenticationPrincipal RbacPrincipal principal) {
 *     String email          = principal.getEmail();
 *     List<String> roles    = principal.getAuthorities();
 * }
 * }</pre>
 */
public final class RbacPrincipal {

    private final String email;
    private final List<String> authorities;

    private RbacPrincipal(String email, List<String> authorities) {
        this.email = email;
        this.authorities = authorities;
    }

    public static RbacPrincipal of(String email, List<String> authorities) {
        return new RbacPrincipal(email, Collections.unmodifiableList(authorities));
    }

    /** The JWT subject — typically the user's e-mail address. */
    public String getEmail() {
        return email;
    }

    /** Authority names embedded in the token at the time it was issued. */
    public List<String> getAuthorities() {
        return authorities;
    }

    @Override
    public String toString() {
        return email;
    }
}

