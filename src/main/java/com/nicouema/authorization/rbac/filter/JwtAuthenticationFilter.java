package com.nicouema.authorization.rbac.filter;

import com.nicouema.authorization.rbac.model.RbacPrincipal;
import com.nicouema.authorization.rbac.model.RbacUser;
import com.nicouema.authorization.rbac.service.JwtService;
import com.nicouema.authorization.rbac.service.RbacUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Reads the {@code Authorization: Bearer <token>} header on every request.
 *
 * <h3>Principal resolution</h3>
 * <ul>
 *   <li>If the consuming project registers a
 *       {@link RbacUserDetailsService} bean, the filter loads the project's own
 *       {@link RbacUser} implementation and sets it as the principal.
 *       Controllers can then inject it with
 *       {@code @AuthenticationPrincipal AppUser user}.</li>
 *   <li>If no {@link RbacUserDetailsService} is present, the filter falls back to a
 *       {@link RbacPrincipal} built from the JWT claims alone (no DB call).
 *       Use {@code @AuthenticationPrincipal RbacPrincipal p} in that case.</li>
 * </ul>
 *
 * <p>The filter never blocks requests — enforcement is handled by
 * {@link com.nicouema.authorization.rbac.config.RbacHandlerInterceptor}.</p>
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;

    /** Optional — provided by the consuming project. {@code null} triggers fallback mode. */
    private final RbacUserDetailsService rbacUserDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService,
                                   RbacUserDetailsService rbacUserDetailsService) {
        this.jwtService = jwtService;
        this.rbacUserDetailsService = rbacUserDetailsService; // may be null — that is intentional
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)
                && SecurityContextHolder.getContext().getAuthentication() == null) {

            String token = authHeader.substring(BEARER_PREFIX.length());

            if (jwtService.isTokenValid(token)) {
                String email = jwtService.extractEmail(token);

                UsernamePasswordAuthenticationToken authentication;

                if (rbacUserDetailsService != null) {
                    // Load the project's own RbacUser — becomes @AuthenticationPrincipal
                    RbacUser user = rbacUserDetailsService.loadUserByEmail(email);
                    authentication = new UsernamePasswordAuthenticationToken(
                            user, null, user.getAuthorities());
                } else {
                    // Fallback: build principal purely from token claims (no DB call)
                    List<String> authorityNames = jwtService.extractAuthorities(token);
                    List<SimpleGrantedAuthority> grantedAuthorities = authorityNames.stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());
                    authentication = new UsernamePasswordAuthenticationToken(
                            RbacPrincipal.of(email, authorityNames), null, grantedAuthorities);
                }

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Spring Security 6+ recommended pattern: always create a fresh context
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authentication);
                SecurityContextHolder.setContext(context);
            }
        }

        filterChain.doFilter(request, response);
    }
}
