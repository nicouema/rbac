package com.nicouema.authorization.rbac.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.util.AntPathMatcher;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Per-request {@link AuthorizationManager} that enforces the
 * {@code @AuthenticationRequired} / {@code @AuthorizationRequired} annotations
 * by consulting {@link EndpointsConfiguration} at request time (lazily — the
 * endpoints index is populated by a {@code ContextRefreshedEvent} so it is always
 * ready by the time real traffic arrives).
 *
 * <h3>Decision matrix</h3>
 * <ul>
 *   <li>Path not protected → {@code GRANT}</li>
 *   <li>Path protected + unauthenticated → {@code DENY} →
 *       {@link RbacAuthenticationEntryPoint} → 401</li>
 *   <li>Path requires authority + authenticated + authority match → {@code GRANT}</li>
 *   <li>Path requires authority + authenticated + no match → {@code DENY} →
 *       {@link RbacAccessDeniedHandler} → 403</li>
 *   <li>Path requires authentication only + authenticated → {@code GRANT}</li>
 * </ul>
 */
public class RbacAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final EndpointsConfiguration endpointsConfiguration;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public RbacAuthorizationManager(EndpointsConfiguration endpointsConfiguration) {
        this.endpointsConfiguration = endpointsConfiguration;
    }

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authenticationSupplier,
                                         RequestAuthorizationContext context) {
        HttpServletRequest request = context.getRequest();
        String path = request.getRequestURI();

        // CORS preflight requests never carry credentials — grant unconditionally
        // so the browser's OPTIONS probe isn't rejected before the real request is sent.
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return new AuthorizationDecision(true);
        }

        // Resolve required authorities for this path (may be empty = auth-only)
        Set<String> requiredAuthorities = findRequiredAuthorities(path);
        boolean needsAuthentication = !requiredAuthorities.isEmpty() || isAuthenticationRequired(path);

        if (!needsAuthentication) {
            return new AuthorizationDecision(true);
        }

        Authentication auth = authenticationSupplier.get();
        boolean isAuthenticated = auth != null
                && auth.isAuthenticated()
                && !(auth instanceof AnonymousAuthenticationToken);

        if (!isAuthenticated) {
            // Spring Security: unauthenticated denial → AuthenticationEntryPoint (401)
            return new AuthorizationDecision(false);
        }

        if (!requiredAuthorities.isEmpty()) {
            Set<String> userAuthorities = new HashSet<>();
            for (GrantedAuthority ga : auth.getAuthorities()) {
                userAuthorities.add(ga.getAuthority());
            }
            boolean hasAny = requiredAuthorities.stream().anyMatch(userAuthorities::contains);
            // false → Spring Security: authenticated denial → AccessDeniedHandler (403)
            return new AuthorizationDecision(hasAny);
        }

        // Authentication-only requirement satisfied
        return new AuthorizationDecision(true);
    }

    // -------------------------------------------------------------------------

    /** Returns the set of authorities that are allowed to access {@code path}. */
    private Set<String> findRequiredAuthorities(String path) {
        Map<String, String[]> authzMap = endpointsConfiguration.getAuthorizationRequired();
        if (authzMap == null || authzMap.isEmpty()) return Set.of();

        Set<String> matched = new HashSet<>();
        authzMap.forEach((authority, patterns) -> {
            if (Arrays.stream(patterns).anyMatch(p -> pathMatcher.match(p, path))) {
                matched.add(authority);
            }
        });
        return matched;
    }

    private boolean isAuthenticationRequired(String path) {
        String[] patterns = endpointsConfiguration.getAuthenticationRequired();
        if (patterns == null) return false;
        return Arrays.stream(patterns).anyMatch(p -> pathMatcher.match(p, path));
    }
}

