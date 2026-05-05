package com.nicouema.authorization.rbac.config;

import com.nicouema.authorization.rbac.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Minimal Spring Security configuration for the RBAC library.
 *
 * <p>Responsibilities:</p>
 * <ul>
 *   <li>Register {@link JwtAuthenticationFilter} so the {@code SecurityContext} is
 *       populated when a valid Bearer token is present.</li>
 *   <li>Disable CSRF and enforce stateless sessions (JWT design).</li>
 *   <li>Permit all requests by default — actual enforcement is performed by
 *       {@link RbacHandlerInterceptor} based on the {@code @AuthenticationRequired} /
 *       {@code @AuthorizationRequired} annotations.</li>
 * </ul>
 *
 * <p>The consuming project is responsible for providing a {@code PasswordEncoder}
 * bean if it needs one.</p>
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
