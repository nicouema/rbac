package com.nicouema.authorization.rbac.config;

import com.nicouema.authorization.rbac.config.swagger.SwaggerSecurityConfiguration;
import com.nicouema.authorization.rbac.exception.RbacAuthenticationEntryPoint;
import com.nicouema.authorization.rbac.exception.RbacExceptionHandler;
import com.nicouema.authorization.rbac.filter.JwtAuthenticationFilter;
import com.nicouema.authorization.rbac.service.JwtService;
import com.nicouema.authorization.rbac.service.JwtServiceImpl;
import com.nicouema.authorization.rbac.service.RbacUserDetails;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

/**
 * Single auto-configuration entry point for the RBAC security library.
 *
 * <p>All library beans are declared here as explicit {@code @Bean} methods so that
 * they are registered regardless of whether the consuming project's component-scan
 * covers the library's packages.</p>
 *
 * <p>Registered via
 * {@code META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}.</p>
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(JwtProperties.class)
@Import({
        SecurityConfig.class,
        SwaggerSecurityConfiguration.class   // conditional on OpenAPI class — safe if springdoc absent
})
public class RbacAutoConfiguration {

    /** Core JWT operations — can be overridden by the consuming project. */
    @Bean
    public JwtService jwtService(JwtProperties jwtProperties) {
        return new JwtServiceImpl(jwtProperties);
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtService jwtService,
                                                           ObjectProvider<RbacUserDetails> rbacUserDetails,
                                                           RbacAuthenticationEntryPoint entryPoint) {
        return new JwtAuthenticationFilter(jwtService, rbacUserDetails.getIfAvailable(), entryPoint);
    }

    /** Scans handler mappings after context refresh to feed the Swagger security metadata. */
    @Bean
    public EndpointsConfiguration endpointsConfiguration() {
        return new EndpointsConfiguration();
    }

    /**
     * Global {@code @RestControllerAdvice} that maps {@link com.nicouema.authorization.rbac.exception.UnauthorizedException}
     * and {@link com.nicouema.authorization.rbac.exception.ForbiddenException} to JSON 401 / 403
     * responses. Skipped when the consuming project declares its own bean of the same type.
     */
    @Bean
    @ConditionalOnMissingBean(RbacExceptionHandler.class)
    public RbacExceptionHandler rbacExceptionHandler() {
        return new RbacExceptionHandler();
    }
}

