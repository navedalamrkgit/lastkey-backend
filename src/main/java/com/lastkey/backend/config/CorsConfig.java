package com.lastkey.backend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration =
                new CorsConfiguration();

        /*
         * setAllowedOriginPatterns use kiya hai because
         * Vercel har deployment ke liye naya URL generate
         * kar sakta hai.
         *
         * Example:
         * https://lastkey-frontend-abc123-naved-khan.vercel.app
         */
        configuration.setAllowedOriginPatterns(
                List.of(
                        "http://localhost:5173",
                        "http://127.0.0.1:5173",
                        "https://lastkey-frontend-mvfp7f27e-naved-khan.vercel.app"
                )
        );

        configuration.setAllowedMethods(
                List.of(
                        "GET",
                        "POST",
                        "PUT",
                        "PATCH",
                        "DELETE",
                        "OPTIONS"
                )
        );

        configuration.setAllowedHeaders(
                List.of(
                        "Authorization",
                        "Content-Type",
                        "Accept",
                        "Origin",
                        "X-Requested-With",
                        "Cache-Control"
                )
        );

        configuration.setExposedHeaders(
                List.of(
                        "Authorization",
                        "Content-Disposition",
                        "Location"
                )
        );

        /*
         * Cookies ya authenticated browser requests ko
         * support karne ke liye.
         */
        configuration.setAllowCredentials(true);

        /*
         * Browser preflight response ko 1 hour tak cache
         * kar sakta hai.
         */
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration(
                "/**",
                configuration
        );

        return source;
    }
}