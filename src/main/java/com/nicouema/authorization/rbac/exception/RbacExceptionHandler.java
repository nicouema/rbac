package com.nicouema.authorization.rbac.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Global exception handler that maps the library's security exceptions to
 * well-formed JSON error responses.
 *
 * <p>Consuming projects can throw these exceptions from anywhere in their
 * service or controller layer:</p>
 * <pre>{@code
 * throw new UnauthorizedException("Invalid credentials");  // → 401
 * throw new ForbiddenException("Admin access required");   // → 403
 * }</pre>
 *
 * <p>Both handlers are overridable: declare your own {@code @ExceptionHandler}
 * for either exception in a {@code @RestControllerAdvice} in the consuming project
 * and Spring MVC will prefer the more specific / closer handler automatically.</p>
 */
@RestControllerAdvice
public class RbacExceptionHandler {

    // ------------------------------------------------------------------
    // 401 Unauthorized
    // ------------------------------------------------------------------

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<Map<String, Object>> handleUnauthorized(
            UnauthorizedException ex, HttpServletRequest request) {

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(errorBody(HttpStatus.UNAUTHORIZED, ex.getMessage(), request.getRequestURI()));
    }

    // ------------------------------------------------------------------
    // 403 Forbidden
    // ------------------------------------------------------------------

    @ExceptionHandler(ForbiddenException.class)
    public ResponseEntity<Map<String, Object>> handleForbidden(
            ForbiddenException ex, HttpServletRequest request) {

        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(errorBody(HttpStatus.FORBIDDEN, ex.getMessage(), request.getRequestURI()));
    }

    // ------------------------------------------------------------------

    private static Map<String, Object> errorBody(HttpStatus status, String message, String path) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status",    status.value());
        body.put("error",     status.getReasonPhrase());
        body.put("message",   message);
        body.put("path",      path);
        return body;
    }
}

