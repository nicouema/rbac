package com.nicouema.authorization.rbac.config;

import com.nicouema.authorization.rbac.annotation.AuthenticationRequired;
import com.nicouema.authorization.rbac.annotation.AuthorizationRequired;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Scans all registered Spring MVC handler methods after the application context
 * is fully refreshed and builds two indexes used by:
 * <ul>
 *   <li>{@link com.nicouema.authorization.rbac.config.swagger.SwaggerSecurityConfiguration} —
 *       to mark the correct Swagger operations with the bearerAuth security scheme</li>
 * </ul>
 *
 * <h3>Indexes</h3>
 * <ul>
 *   <li>{@link #getAuthenticationRequired()} — URL patterns of endpoints annotated
 *       with {@code @AuthenticationRequired} or {@code @AuthorizationRequired}</li>
 *   <li>{@link #getAuthorizationRequired()} — map of {@code authority → URL patterns[]}
 *       for every endpoint annotated with {@code @AuthorizationRequired}</li>
 * </ul>
 */
@Slf4j
public class EndpointsConfiguration implements ApplicationListener<ContextRefreshedEvent> {

    /**
     * -- GETTER --
     * URL patterns of every endpoint that requires at least authentication.
     */
    @Getter
    private volatile String[] authenticationRequired = new String[0];
    /**
     * -- GETTER --
     *  Map of
     *  for endpoints that require
     *  a specific authority.
     */
    @Getter
    private volatile Map<String, String[]> authorizationRequired = Collections.emptyMap();
    private volatile boolean initialized = false;

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        // Guard against multiple fires (e.g. child contexts in Spring MVC)
        if (initialized) return;
        initialized = true;

        ApplicationContext context = event.getApplicationContext();

        try {
            // Collect handler methods from ALL RequestMappingHandlerMapping beans
            Map<RequestMappingInfo, org.springframework.web.method.HandlerMethod> allMethods = new HashMap<>();
            context.getBeansOfType(RequestMappingHandlerMapping.class)
                    .values()
                    .forEach(mapping -> allMethods.putAll(mapping.getHandlerMethods()));

            Set<String> authRequiredPaths = new HashSet<>();
            Map<String, Set<String>> authzMap = new HashMap<>();

            allMethods.forEach((info, handlerMethod) -> {
                boolean isAuthRequired =
                        handlerMethod.hasMethodAnnotation(AuthenticationRequired.class)
                        || handlerMethod.getBeanType().isAnnotationPresent(AuthenticationRequired.class);

                // Method-level annotation overrides class-level
                AuthorizationRequired authzAnnotation =
                        handlerMethod.getMethodAnnotation(AuthorizationRequired.class);
                if (authzAnnotation == null) {
                    authzAnnotation = handlerMethod.getBeanType()
                            .getAnnotation(AuthorizationRequired.class);
                }

                Set<String> paths = resolvePaths(info);
                if (paths.isEmpty()) return;

                if (isAuthRequired || authzAnnotation != null) {
                    authRequiredPaths.addAll(paths);
                }

                if (authzAnnotation != null) {
                    for (String authority : authzAnnotation.allowedAuthorities()) {
                        authzMap.computeIfAbsent(authority, k -> new HashSet<>()).addAll(paths);
                    }
                }
            });

            this.authenticationRequired = authRequiredPaths.toArray(new String[0]);
            this.authorizationRequired = authzMap.entrySet().stream()
                    .collect(Collectors.toMap(
                            Map.Entry::getKey,
                            e -> e.getValue().toArray(new String[0])
                    ));

            log.debug("RBAC EndpointsConfiguration: {} authentication-required path(s), {} authority mapping(s)",
                    this.authenticationRequired.length, this.authorizationRequired.size());

        } catch (Exception e) {
            log.warn("RBAC: failed to scan endpoints for security metadata — Swagger lock icons may be missing", e);
        }
    }

    // ------------------------------------------------------------------

    private static Set<String> resolvePaths(RequestMappingInfo info) {
        info.getPatternValues();
        Set<String> paths = new HashSet<>(info.getPatternValues());
        info.getDirectPaths();
        paths.addAll(info.getDirectPaths());
        return paths;
    }

}
