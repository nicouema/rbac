package com.nicouema.authorization.rbac.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.stream.Collectors;


/**
 * Lightweight {@link RbacUser} built purely from JWT claims — no database call.
 *
 * <p>Used as the {@code SecurityContext} principal when the consuming project does
 * <em>not</em> register a
 * {@link com.nicouema.authorization.rbac.service.RbacUserDetailsService} bean.
 * In controllers use:</p>
 * <pre>{@code
 * @AuthenticationRequired
 * public ResponseEntity<?> me(@AuthenticationPrincipal RbacPrincipal principal) {
 *     String id          = principal.getId();
 *     List<String> roles = principal.getAuthorityNames();
 * }
 * }</pre>
 */
@RequiredArgsConstructor
@Getter
@Setter
public final class RbacPrincipal implements RbacUser {

    private final String username;
    private final List<SimpleGrantedAuthority> authorities;

    /** Convenience method: authority names as plain strings. */
    public List<String> getAuthorityNames() {
        return authorities.stream()
                .map(SimpleGrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    }

    @Override public String getId()      { return username; }


    @Override
    public @Nullable String getPassword() {
        return null;
    }

}
