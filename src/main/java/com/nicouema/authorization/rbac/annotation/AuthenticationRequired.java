package com.nicouema.authorization.rbac.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a controller class or handler method as requiring a valid JWT token.
 * If placed on a class, all methods in that controller inherit the requirement.
 * If placed on a method, only that endpoint requires authentication.
 *
 * <p>When authentication is missing or the token is invalid, the filter returns
 * HTTP 401 Unauthorized.</p>
 */
@Documented
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface AuthenticationRequired {
}

