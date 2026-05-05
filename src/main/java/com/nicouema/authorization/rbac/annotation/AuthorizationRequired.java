package com.nicouema.authorization.rbac.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a controller class or handler method as requiring the caller to hold at
 * least one of the listed authorities.
 *
 * <p>Implies {@link AuthenticationRequired}: the caller must also carry a valid JWT.
 * If placed on a class, all methods inherit the requirement unless the method
 * declares its own {@code @AuthorizationRequired} (method-level overrides class-level).</p>
 *
 * <p>When the caller lacks the required authority, the filter returns HTTP 403 Forbidden.
 * When the caller is not authenticated at all, HTTP 401 Unauthorized is returned.</p>
 *
 * <pre>{@code
 * // Endpoint accessible by ADMIN or MANAGER
 * @GetMapping("/reports")
 * @AuthorizationRequired(allowedAuthorities = {"ADMIN", "MANAGER"})
 * public List<Report> getReports() { ... }
 * }</pre>
 */
@Documented
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface AuthorizationRequired {

    /**
     * The set of authority names of which the caller must have at least one.
     * Authority names are matched against {@code GrantedAuthority#getAuthority()}.
     */
    String[] allowedAuthorities();
}

