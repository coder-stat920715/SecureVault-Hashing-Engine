package com.vault.hashing.config;

import com.vault.hashing.auth.JwtAuthenticationFilter;
import com.vault.hashing.auth.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

/**
 * Stateless API security. The JWT filter is created here (not as a {@code @Component}) so Spring Boot does not
 * additionally register it as a plain servlet filter outside the security chain.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtService jwtService,
                                                   VaultProperties properties) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // stateless bearer-token API, no cookies/sessions
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .headers(h -> h.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(
                            antMatcher("/api/auth/register"),
                            antMatcher("/api/auth/login"),
                            // Webhooks are authenticated by their HMAC signature, not by a JWT.
                            antMatcher("/api/webhooks/**"),
                            antMatcher("/error")).permitAll();
                    if (properties.getDev().isH2ConsoleEnabled()) {
                        auth.requestMatchers(antMatcher("/h2-console/**")).permitAll();
                    }
                    auth.anyRequest().authenticated();
                })
                .addFilterBefore(new JwtAuthenticationFilter(jwtService), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
