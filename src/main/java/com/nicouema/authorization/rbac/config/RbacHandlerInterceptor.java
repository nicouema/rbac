package com.nicouema.authorization.rbac.config;

import com.nicouema.authorization.rbac.annotation.AuthenticationRequired;
import com.nicouema.authorization.rbac.annotation.AuthorizationRequired;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Spring MVC interceptor that enforces {@link AuthenticationRequired} and
 * {@link AuthorizationRequired} annotations.
 *
 * <h3>Resolution order</h3>
 * <ol>
 *   <li>Method-level {@code @AuthorizationRequired} (most specific, overrides everything)</li>
 *   <li>Class-level {@code @AuthorizationRequired}</li>
 *   <li>Method-level {@code @AuthenticationRequired}</li>
 *   <li>Class-level {@code @AuthenticationRequired}</li>
 * </ol>
 *
 * <p>{@code @AuthorizationRequired} implicitly requires authentication: a 401 is
 * returned when there is no valid JWT, and a 403 when the authorities do not match.</p>
 */
public class RbacHandlerInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws IOException {

        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }

        // --- resolve effective @AuthorizationRequired (method overrides class) ---
        AuthorizationRequired authz = handlerMethod.getMethodAnnotation(AuthorizationRequired.class);
        if (authz == null) {
            authz = handlerMethod.getBeanType().getAnnotation(AuthorizationRequired.class);
        }

        // --- resolve effective @AuthenticationRequired ---
        boolean authRequired = authz != null; // @AuthorizationRequired implies authentication
        if (!authRequired) {
            AuthenticationRequired authAnnotation =
                    handlerMethod.getMethodAnnotation(AuthenticationRequired.class);
            if (authAnnotation == null) {
                authAnnotation = handlerMethod.getBeanType().getAnnotation(AuthenticationRequired.class);
            }
            authRequired = authAnnotation != null;
        }

        if (!authRequired) {
            return true;
        }

        // --- authentication check ---
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean isAuthenticated = authentication != null
                && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken);

        if (!isAuthenticated) {
            writeError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "Unauthorized", "Authentication required. Provide a valid Bearer token.");
            return false;
        }

        // --- authority check ---
        if (authz != null) {
            Set<String> userAuthorities = authentication.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());

            boolean hasRequiredAuthority = Arrays.stream(authz.allowedAuthorities())
                    .anyMatch(userAuthorities::contains);

            if (!hasRequiredAuthority) {
                writeError(response, HttpServletResponse.SC_FORBIDDEN,
                        "Forbidden", "Insufficient authorities. Required one of: "
                                + Arrays.toString(authz.allowedAuthorities()));
                return false;
            }
        }

        return true;
    }

    private void writeError(HttpServletResponse response, int status,
                            String error, String message) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(
                "{\"error\":\"" + error + "\",\"message\":\"" + message + "\"}");
    }
}

