package com.vault.hashing.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** Strongly-typed, validated configuration for every module (prefix {@code vault}). */
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "vault")
public class VaultProperties {

    @Valid
    private Jwt jwt = new Jwt();
    @Valid
    private Password password = new Password();
    @Valid
    private Storage storage = new Storage();
    @Valid
    private Webhook webhook = new Webhook();
    @Valid
    private Cluster cluster = new Cluster();
    @Valid
    private Dev dev = new Dev();

    @Getter
    @Setter
    public static class Jwt {
        @NotBlank
        private String secret;
        @NotBlank
        private String issuer = "securevault";
        @NotNull
        private Duration ttl = Duration.ofHours(1);
    }

    @Getter
    @Setter
    public static class Password {
        public enum Algorithm { ARGON2, BCRYPT }

        @NotNull
        private Algorithm algorithm = Algorithm.ARGON2;
        @Min(8)
        private int saltLength = 16;
        @Min(16)
        private int hashLength = 32;
        @Min(1)
        private int parallelism = 1;
        @Min(8192)
        private int memoryKib = 19456;
        @Min(1)
        private int iterations = 2;
        @Min(10)
        @Max(16)
        private int bcryptStrength = 12;
    }

    @Getter
    @Setter
    public static class Storage {
        @NotBlank
        private String rootDir = "./data/storage";
    }

    @Getter
    @Setter
    public static class Webhook {
        @NotBlank
        private String secret;
    }

    @Getter
    @Setter
    public static class Cluster {
        public enum HashFunction { MD5, MURMUR3 }

        @Min(1)
        @Max(10_000)
        private int virtualNodes = 100;
        @NotNull
        private HashFunction hashFunction = HashFunction.MD5;
        @NotEmpty
        private List<String> initialNodes = new ArrayList<>(List.of("worker-a", "worker-b", "worker-c"));
    }

    @Getter
    @Setter
    public static class Dev {
        private boolean h2ConsoleEnabled = false;
    }
}
