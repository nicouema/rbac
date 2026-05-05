package com.nicouema.authorization.rbac.model;

import org.springframework.security.core.userdetails.UserDetails;

/**
 * Minimal abstraction over a user that the RBAC security layer needs.
 *
 * <p>Extend {@link UserDetails} in the consuming project's user entity and implement
 * this interface to integrate with the library:</p>
 *
 * <pre>{@code
 * @Entity
 * public class AppUser implements RbacUser {
 *     private String email;
 *
 *     @Override public String getEmail()   { return email; }
 *     @Override public String getUsername() { return email; } // used by Spring Security
 *
 *     @Override
 *     public Collection<? extends GrantedAuthority> getAuthorities() {
 *         return roles.stream().map(SimpleGrantedAuthority::new).toList();
 *     }
 *     // ... other UserDetails methods
 * }
 * }</pre>
 *
 * <p>Then register a {@link com.nicouema.authorization.rbac.service.RbacUserDetailsService}
 * bean so the JWT filter can load this object and set it as the
 * {@code @AuthenticationPrincipal} in every request.</p>
 */
public interface RbacUser extends UserDetails {

    /**
     * The unique identifier embedded as the JWT subject.
     * Typically the same value returned by {@link #getUsername()}.
     */
    String getEmail();
}
