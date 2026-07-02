package com.nicouema.authorization.rbac.service;

import com.nicouema.authorization.rbac.model.RbacUser;

/**
 * Strategy for loading a {@link RbacUser} from the subject (id) embedded in a JWT.
 *
 * <p>Register a {@code @Bean} implementing this interface in the consuming project
 * so that {@link com.nicouema.authorization.rbac.filter.JwtAuthenticationFilter} can
 * store the project's own user object as the {@code SecurityContext} principal.
 * Controllers can then inject it with {@code @AuthenticationPrincipal}:</p>
 *
 * <pre>{@code
 * // In consuming project configuration:
 * @Bean
 * public RbacUserDetails rbacUserDetails(AppUserRepository repo) {
 *     return id -> repo.findById(id).orElseThrow();
 * }
 *
 * // In any controller:
 * @GetMapping("/me")
 * @AuthenticationRequired
 * public ResponseEntity<?> me(@AuthenticationPrincipal AppUser user) { ... }
 * }</pre>
 *
 * <p>If no bean of this type is registered the filter falls back to
 * {@link com.nicouema.authorization.rbac.model.RbacPrincipal} (token claims only,
 * no database call — use {@code @AuthenticationPrincipal RbacPrincipal} then).</p>
 */
@FunctionalInterface
public interface RbacUserDetails {

    /**
     * Load a {@link RbacUser} by the identifier extracted from the JWT subject.
     *
     * @param id the JWT subject value (typically a user UUID or numeric id)
     * @return the user for that id — must not be {@code null}
     * @throws RuntimeException if the user cannot be found
     */
    RbacUser getUserById(String id);
}

