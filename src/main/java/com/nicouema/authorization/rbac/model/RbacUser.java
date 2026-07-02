package com.nicouema.authorization.rbac.model;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * Minimal abstraction over a user that the RBAC security layer needs.
 *
 * <p>Implement this interface on whatever user entity or record your project uses
 * and pass it to {@link com.nicouema.authorization.rbac.service.JwtService#generateToken}
 * to obtain a signed JWT that carries the user's identity and authorities.</p>
 *
 * <pre>{@code
 * // Example — JPA entity in the consuming project
 * @Entity
 * public class AppUser implements RbacUser {
 *     private String id;
 *     private List<GrantedAuthority> roles;
 *
 *     @Override public String getId()                                           { return id; }
 *     @Override public Collection<? extends GrantedAuthority> getAuthorities() { return roles; }
 *     // ... remaining UserDetails methods
 * }
 * }</pre>
 *
 * <p>When a {@link com.nicouema.authorization.rbac.service.RbacUserDetails} bean is
 * present, {@link com.nicouema.authorization.rbac.filter.JwtAuthenticationFilter} calls
 * {@code getUserById(getId())} to load the concrete implementation and stores it as the
 * {@code SecurityContext} principal so that controllers can inject it directly:</p>
 * <pre>{@code
 * @GetMapping("/me")
 * @AuthenticationRequired
 * public ResponseEntity<?> me(@AuthenticationPrincipal AppUser user) { ... }
 * }</pre>
 */
public interface RbacUser extends UserDetails {

    /**
     * The unique identifier embedded as the JWT subject.
     * Typically a UUID or numeric primary key — intentionally not tied to email.
     */
    String getId();

    /**
     * The authority names granted to this user (e.g. {@code "USER_READ"}).
     * These are embedded as the {@code authorities} claim in the JWT and matched
     * against {@link com.nicouema.authorization.rbac.annotation.AuthorizationRequired#allowedAuthorities()}.
     */
    @Override
    Collection<? extends GrantedAuthority> getAuthorities();
}
