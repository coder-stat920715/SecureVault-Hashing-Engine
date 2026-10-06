package com.vault.hashing.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

@Configuration
public class AppConfig {

    /** Injectable clock so time-dependent code (audit timestamps) is testable. */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
