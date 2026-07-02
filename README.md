# rbac — Spring Boot Security Starter

A zero-boilerplate, drop-in Spring Boot auto-configuration that adds **JWT authentication** and **role-based access control (RBAC)** to any Spring MVC project.

---

## Table of Contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Configuration](#configuration)
6. [Annotations](#annotations)
7. [Integrating your User entity](#integrating-your-user-entity)
8. [Generating a JWT](#generating-a-jwt)
9. [Injecting the authenticated user](#injecting-the-authenticated-user)
10. [Swagger / OpenAPI integration](#swagger--openapi-integration)
11. [Overriding the security filter chain](#overriding-the-security-filter-chain)
12. [Architecture overview](#architecture-overview)

---

## Features

- ✅ JWT validation on every request via `Authorization: Bearer <token>`
- ✅ `@AuthenticationRequired` — require a valid token on a controller or single endpoint
- ✅ `@AuthorizationRequired(allowedAuthorities = {...})` — require one of the listed authorities
- ✅ Annotations work at **class level** (all methods inherit) or **method level** (overrides class)
- ✅ `@AuthenticationPrincipal` injection of your own domain `User` entity
- ✅ Automatic Swagger `bearerAuth` 🔒 on protected operations (when springdoc is on classpath)
- ✅ All beans are `@ConditionalOnMissingBean` — every piece is overridable

---

## Requirements

| Dependency | Version |
|---|---|
| Java | 17+ |
| Spring Boot | 4.x |
| Spring Security | 7.x (transitive via Boot) |

---

## Installation

### Maven

Add the GitHub Packages repository and the dependency to your `pom.xml`:

```xml
<!-- GitHub Packages repository -->
<repositories>
  <repository>
    <id>github</id>
    <url>https://maven.pkg.github.com/nicouema/repo</url>
  </repository>
</repositories>

<dependencies>
  <dependency>
    <groupId>com.nicouema.authorization</groupId>
    <artifactId>rbac</artifactId>
    <version>0.0.1-SNAPSHOT</version>
  </dependency>
</dependencies>
```

> **GitHub Packages authentication** — add your token to `~/.m2/settings.xml`:
> ```xml
> <server>
>   <id>github</id>
>   <username>YOUR_GITHUB_USERNAME</username>
>   <password>YOUR_GITHUB_TOKEN</password>
> </server>
> ```

---

## Quick Start

The library auto-configures itself. The only required step is setting your JWT secret in `application.properties`:

```properties
rbac.jwt.secret=my-super-secret-key-at-least-32-chars!!
rbac.jwt.expiration-ms=86400000
```

Then annotate your controllers and you're done:

```java
@RestController
@RequestMapping("/users")
@AuthenticationRequired           // all endpoints in this controller require a valid JWT
public class UserController {

    @GetMapping("/me")
    public ResponseEntity<AppUser> me(@AuthenticationPrincipal AppUser user) {
        return ResponseEntity.ok(user);
    }

    @DeleteMapping("/{id}")
    @AuthorizationRequired(allowedAuthorities = {"ADMIN"})   // overrides class-level annotation
    public ResponseEntity<Void> delete(@PathVariable String id) { ... }
}
```

---

## Configuration

All properties are under the `rbac.jwt.*` namespace:

| Property | Default | Description |
|---|---|---|
| `rbac.jwt.secret` | `rbac-default-secret-key-change-me-in-production!!` | HMAC-SHA256 signing secret — **must be ≥ 32 characters**. Always override in production. |
| `rbac.jwt.expiration-ms` | `86400000` (24 h) | Token validity in milliseconds. |

---

## Annotations

### `@AuthenticationRequired`

Requires the caller to present a valid, non-expired JWT token.

| Where | Effect |
|---|---|
| Class | All methods in the controller require a token |
| Method | Only that endpoint requires a token |

```java
@RestController
@AuthenticationRequired          // class-level: all endpoints protected
public class ProfileController {

    @GetMapping("/profile")
    public Profile getProfile(@AuthenticationPrincipal AppUser user) { ... }

    @GetMapping("/public-info")
    // inherits @AuthenticationRequired from the class
    public Info getInfo() { ... }
}
```

**No token / invalid token → `401 Unauthorized`**

---

### `@AuthorizationRequired(allowedAuthorities = String[])`

Requires the caller to be authenticated **and** hold at least one of the listed authorities.  
Method-level always overrides class-level.

```java
@RestController
@RequestMapping("/admin")
@AuthorizationRequired(allowedAuthorities = {"ADMIN"})   // class-level default
public class AdminController {

    @GetMapping("/users")
    public List<User> listUsers() { ... }                 // requires ADMIN

    @GetMapping("/reports")
    @AuthorizationRequired(allowedAuthorities = {"ADMIN", "MANAGER"})  // overrides
    public List<Report> reports() { ... }                 // requires ADMIN or MANAGER
}
```

| Situation | Response |
|---|---|
| No token / invalid token | `401 Unauthorized` |
| Valid token, missing authority | `403 Forbidden` |
| Valid token, authority matched | `200 OK` |

---

## Integrating your User entity

### 1 — Implement `RbacUser`

Your user entity (JPA, MongoDB, record — any type) must implement `RbacUser`:

```java
import com.nicouema.authorization.rbac.model.RbacUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Entity
public class AppUser implements RbacUser {

    @Id
    private String id;          // embedded as the JWT subject
    private String email;

    @ElementCollection(fetch = FetchType.EAGER)
    private List<String> authorities;

    // --- RbacUser ---

    @Override
    public String getId() { return id; }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    // --- UserDetails (required by Spring Security) ---

    @Override public String getUsername()              { return email; }
    @Override public String getPassword()              { return null; }   // not used — JWT only
    @Override public boolean isAccountNonExpired()     { return true; }
    @Override public boolean isAccountNonLocked()      { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled()               { return true; }
}
```

### 2 — Register a `RbacUserDetails` bean

This tells the library how to load your user from the JWT subject:

```java
import com.nicouema.authorization.rbac.service.RbacUserDetails;

@Configuration
public class SecurityBeansConfig {

    @Bean
    public RbacUserDetails rbacUserDetails(AppUserRepository repo) {
        // The `id` parameter is the value of getId() that was embedded in the JWT
        return id -> repo.findById(id)
                         .orElseThrow(() -> new UsernameNotFoundException("User not found: " + id));
    }
}
```

That's it. The filter will call `getUserById(subject)` on every authenticated request and store the returned `AppUser` as the `SecurityContext` principal.

---

## Generating a JWT

Inject `JwtService` wherever you handle login and call `generateToken(user)`:

```java
import com.nicouema.authorization.rbac.service.JwtService;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AppUserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequest req) {
        AppUser user = userRepo.findByEmail(req.getEmail())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));

        if (!passwordEncoder.matches(req.getPassword(), user.getPasswordHash())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        String token = jwtService.generateToken(user);
        return ResponseEntity.ok(Map.of("token", token));
    }
}
```

The generated token embeds:
- **subject** — `user.getId()`
- **authorities** — `user.getAuthorities()` mapped to their string names
- **exp** — current time + `rbac.jwt.expiration-ms`

---

## Injecting the authenticated user

### With `RbacUserDetails` bean (recommended — full entity)

```java
@GetMapping("/me")
@AuthenticationRequired
public ResponseEntity<AppUser> me(@AuthenticationPrincipal AppUser user) {
    // `user` is the object returned by RbacUserDetails.getUserById(...)
    return ResponseEntity.ok(user);
}
```

### Without `RbacUserDetails` bean (token claims only — no DB call)

```java
import com.nicouema.authorization.rbac.model.RbacPrincipal;

@GetMapping("/me")
@AuthenticationRequired
public ResponseEntity<Map<String, Object>> me(@AuthenticationPrincipal RbacPrincipal principal) {
    return ResponseEntity.ok(Map.of(
            "id", principal.getUsername(),
            "authorities", principal.getAuthorityNames()
    ));
}
```

---

## Swagger / OpenAPI integration

Add `springdoc-openapi-starter-webmvc-ui` to your project:

```xml
<dependency>
    <groupId>org.springdoc</groupId>
    <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
    <version>2.8.8</version>
</dependency>
```

The library will automatically:
1. Register a `bearerAuth` HTTP security scheme
2. Stamp the 🔒 padlock on every operation covered by `@AuthenticationRequired` or `@AuthorizationRequired`

No extra configuration needed. Browse to `http://localhost:8080/swagger-ui.html`, click **Authorize**, and paste your JWT.

---

## Overriding the security filter chain

The default `SecurityFilterChain` is annotated with `@ConditionalOnMissingBean(SecurityFilterChain.class)`. If you need a custom chain, declare your own and the library's chain is skipped. Add `JwtAuthenticationFilter` manually to keep JWT support:

```java
import com.nicouema.authorization.rbac.filter.JwtAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class CustomSecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/**").permitAll()
                .anyRequest().authenticated())
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
```

Similarly, the `RbacAuthenticationEntryPoint` and `RbacAccessDeniedHandler` beans are both `@ConditionalOnMissingBean` — declare your own to customise the 401 / 403 response body.

---

## Architecture overview

```
Incoming request
      │
      ▼
JwtAuthenticationFilter          (reads Bearer token → populates SecurityContext)
      │
      ▼
Spring Security AuthorizationFilter
      │
      └─► RbacAuthorizationManager  (reads @AuthenticationRequired / @AuthorizationRequired
              │                       annotations via EndpointsConfiguration)
              │
              ├── public path ──────────────────────────────────────► Controller
              │
              ├── authenticated, authority OK ──────────────────────► Controller
              │       └── @AuthenticationPrincipal AppUser            (your entity)
              │
              ├── not authenticated ────────────────────────────────► RbacAuthenticationEntryPoint → 401
              │
              └── authenticated, wrong authority ───────────────────► RbacAccessDeniedHandler → 403
```

### Beans provided by the library

| Bean | Overridable? | Description |
|---|---|---|
| `JwtService` | ✅ `@ConditionalOnMissingBean` | Signs and validates JWT tokens |
| `JwtAuthenticationFilter` | ✅ `@ConditionalOnMissingBean` | Reads Bearer header, populates `SecurityContext` |
| `EndpointsConfiguration` | ✅ `@ConditionalOnMissingBean` | Scans handler mappings for annotation metadata |
| `SecurityFilterChain` (`rbacSecurityFilterChain`) | ✅ `@ConditionalOnMissingBean` | Default filter chain |
| `RbacAuthenticationEntryPoint` | ✅ `@ConditionalOnMissingBean` | 401 JSON response handler |
| `RbacAccessDeniedHandler` | ✅ `@ConditionalOnMissingBean` | 403 JSON response handler |
| `UserDetailsService` (`rbacDefaultUserDetailsService`) | ✅ `@ConditionalOnMissingBean` | No-op in-memory default (suppresses Spring Security warning) |

### Beans required from the consuming project

| Bean | Required? | Description |
|---|---|---|
| `RbacUserDetails` | ⚡ Optional (fallback to `RbacPrincipal`) | Strategy to load your `RbacUser` from the JWT subject |
| `PasswordEncoder` | ⚡ Optional (only if login endpoint needed) | For password hashing in your auth controller |

