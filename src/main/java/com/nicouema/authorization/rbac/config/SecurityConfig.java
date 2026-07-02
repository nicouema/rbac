package com.nicouema.authorization.rbac.config;

import com.nicouema.authorization.rbac.exception.RbacAccessDeniedHandler;
import com.nicouema.authorization.rbac.exception.RbacAuthenticationEntryPoint;
import com.nicouema.authorization.rbac.filter.JwtAuthenticationFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Security auto-configuration for the RBAC library.
 *
 * <h3>Enforcement model</h3>
 * <p>{@link RbacAuthorizationManager} is plugged into Spring Security's native
 * {@code authorizeHttpRequests} DSL. At request time it consults {@link EndpointsConfiguration}
 * and routes denials appropriately:</p>
 * <ul>
 *   <li>Unauthenticated → {@link RbacAuthenticationEntryPoint} → 401</li>
 *   <li>Authenticated, wrong authority → {@link RbacAccessDeniedHandler} → 403</li>
 * </ul>
 *
 * <p>Both the filter chain and the {@code UserDetailsService} are guarded with
 * {@code @ConditionalOnMissingBean} so consuming projects can override either.</p>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // ------------------------------------------------------------------
    // Exception-handling beans
    // ------------------------------------------------------------------

    @Bean
    @ConditionalOnMissingBean(RbacAuthenticationEntryPoint.class)
    public RbacAuthenticationEntryPoint rbacAuthenticationEntryPoint() {
        return new RbacAuthenticationEntryPoint();
    }

    @Bean
    @ConditionalOnMissingBean(RbacAccessDeniedHandler.class)
    public RbacAccessDeniedHandler rbacAccessDeniedHandler() {
        return new RbacAccessDeniedHandler();
    }

    // ------------------------------------------------------------------
    // Main security filter chain
    // ------------------------------------------------------------------

    /**
     * Default {@link SecurityFilterChain}. Skipped when the consuming project
     * declares its own, giving full chain control while {@link JwtAuthenticationFilter}
     * remains available as a standalone bean.
     */
    @Bean(name = "rbacSecurityFilterChain")
    @Primary
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthenticationFilter jwtFilter,
            EndpointsConfiguration endpointsConfiguration,
            RbacAuthenticationEntryPoint authEntryPoint,
            RbacAccessDeniedHandler accessDeniedHandler) {

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(configureCors()))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().access(new RbacAuthorizationManager(endpointsConfiguration)))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler));

        return http.build();
    }

    private CorsConfigurationSource configureCors() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setExposedHeaders(List.of("Content-Disposition"));
        configuration.setAllowedOriginPatterns(List.of(
                "*",
                "http://localhost:3000",
                "http://localhost:3001"

        ));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(List.of("Authorization",
                "Content-Type",
                "ngrok-skip-browser-warning",
                "Access-Control-Allow-Origin"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(86400L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    // ------------------------------------------------------------------
    // Default UserDetailsService (suppresses Spring Security startup warning)
    // ------------------------------------------------------------------

    @Bean(name = "rbacDefaultUserDetailsService")
    @Primary
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager();
    }
}