package com.nicouema.authorization.rbac.config.swagger;

import com.nicouema.authorization.rbac.config.EndpointsConfiguration;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.RequiredArgsConstructor;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Auto-configures the Swagger / OpenAPI UI to show the Bearer-token padlock on
 * every endpoint that is protected by
 * {@link com.nicouema.authorization.rbac.annotation.AuthenticationRequired} or
 * {@link com.nicouema.authorization.rbac.annotation.AuthorizationRequired}.
 *
 * <p>Activates only when {@code springdoc-openapi} is on the classpath
 * ({@code @ConditionalOnClass(OpenAPI.class)}) so the dependency remains optional.</p>
 */
@Configuration
@ConditionalOnClass(OpenAPI.class)
@RequiredArgsConstructor
public class SwaggerSecurityConfiguration {

    private static final String BEARER_SCHEME_NAME = "bearerAuth";

    private final ApplicationContext applicationContext;

    @Bean
    @ConditionalOnMissingBean(name = "securityRequirementCustomizer")
    public OpenApiCustomizer securityRequirementCustomizer() {
        return openApi -> {
            // Resolved lazily at customization time to avoid circular dependency
            EndpointsConfiguration endpointsConfiguration =
                    applicationContext.getBean(EndpointsConfiguration.class);

            // Safely add the security scheme to existing components — never replace them
            if (openApi.getComponents() == null) {
                openApi.setComponents(new Components());
            }
            openApi.getComponents().addSecuritySchemes(BEARER_SCHEME_NAME,
                    new SecurityScheme()
                            .name(BEARER_SCHEME_NAME)
                            .type(SecurityScheme.Type.HTTP)
                            .scheme("bearer")
                            .bearerFormat("JWT")
                            .description("Paste your JWT token (without 'Bearer ' prefix)"));

            Set<String> protectedPaths = new HashSet<>();

            String[] authPaths = endpointsConfiguration.getAuthenticationRequired();
            if (authPaths != null) {
                protectedPaths.addAll(Arrays.asList(authPaths));
            }

            endpointsConfiguration.getAuthorizationRequired()
                    .values()
                    .forEach(paths -> protectedPaths.addAll(Arrays.asList(paths)));

            if (protectedPaths.isEmpty() || openApi.getPaths() == null) {
                return;
            }

            SecurityRequirement securityRequirement = new SecurityRequirement().addList(BEARER_SCHEME_NAME);

            openApi.getPaths().forEach((path, pathItem) -> {
                if (!isProtected(path, protectedPaths)) return;
                pathItem.readOperations().forEach(operation ->
                        addSecurityIfAbsent(operation, securityRequirement));
            });
        };
    }

    private boolean isProtected(String path, Set<String> protectedPaths) {
        return protectedPaths.stream().anyMatch(protected_ -> {
            if (protected_.endsWith("/**")) {
                String prefix = protected_.substring(0, protected_.length() - 3);
                return path.equals(prefix) || path.startsWith(prefix + "/");
            }
            return protected_.equals(path);
        });
    }

    private void addSecurityIfAbsent(Operation operation, SecurityRequirement requirement) {
        if (operation == null) return;
        if (operation.getSecurity() == null || !operation.getSecurity().contains(requirement)) {
            operation.addSecurityItem(requirement);
        }
    }
}

