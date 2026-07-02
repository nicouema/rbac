package com.nicouema.authorization.rbac.filter;

import com.nicouema.authorization.rbac.exception.RbacAuthenticationEntryPoint;
import com.nicouema.authorization.rbac.model.RbacPrincipal;
import com.nicouema.authorization.rbac.model.RbacUser;
import com.nicouema.authorization.rbac.service.JwtService;
import com.nicouema.authorization.rbac.service.RbacUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
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
 *   <li>If the consuming project registers a {@link RbacUserDetails} {@code @Bean},
 *       the filter calls {@link RbacUserDetails#getUserById(String)} with the JWT subject
 *       and stores the returned {@link RbacUser} as the {@code SecurityContext} principal.
 *       Controllers can then inject it with
 *       {@code @AuthenticationPrincipal AppUser user}.</li>
 *   <li>If no {@link RbacUserDetails} bean is present, the filter falls back to
 *       {@link RbacPrincipal} (token claims only, no DB call).
 *       Use {@code @AuthenticationPrincipal RbacPrincipal p} in that case.</li>
 * </ul>
 *
 * <p>The filter never blocks requests — enforcement is handled by Spring Security's
 * {@code authorizeHttpRequests} DSL via
 * {@link com.nicouema.authorization.rbac.config.RbacAuthorizationManager}.</p>
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;

    /** Optional — provided by the consuming project. {@code null} triggers fallback mode. */
    private final RbacUserDetails rbacUserDetails;

    private final RbacAuthenticationEntryPoint authenticationEntryPoint;

    public JwtAuthenticationFilter(JwtService jwtService, RbacUserDetails rbacUserDetails, RbacAuthenticationEntryPoint authenticationEntryPoint) {
        this.jwtService = jwtService;
        this.rbacUserDetails = rbacUserDetails; // may be null — intentional
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)
                && SecurityContextHolder.getContext().getAuthentication() == null) {

            String token = authHeader.substring(BEARER_PREFIX.length());

            if (jwtService.isTokenValid(token)) {
                String subject = jwtService.extractSubject(token);

                UsernamePasswordAuthenticationToken authentication;

                if (rbacUserDetails != null) {
                    RbacUser rbacUser;
                    try {
                        rbacUser = rbacUserDetails.getUserById(subject);
                    } catch (AuthenticationException ex) {
                        SecurityContextHolder.clearContext();
                        authenticationEntryPoint.commence(request, response, ex);
                        return;
                    }
                    authentication = new UsernamePasswordAuthenticationToken(
                            rbacUser, null, rbacUser.getAuthorities());
                } else {
                    // Fallback: build principal purely from token claims (no DB call)
                    // Use @AuthenticationPrincipal RbacPrincipal in controllers
                    List<String> authorityNames = jwtService.extractAuthorities(token);
                    List<SimpleGrantedAuthority> grantedAuthorities = authorityNames.stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());
                    authentication = new UsernamePasswordAuthenticationToken(
                            new RbacPrincipal(subject, grantedAuthorities), null, grantedAuthorities);
                }

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Spring Security 7 recommended pattern: always create a fresh context
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authentication);
                SecurityContextHolder.setContext(context);
            }
        }

        filterChain.doFilter(request, response);
    }
}
