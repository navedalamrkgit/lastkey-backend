package com.lastkey.backend.security.jwt;

import com.lastkey.backend.security.service.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter
        extends OncePerRequestFilter {

    private final JwtService jwtService;

    private final CustomUserDetailsService
            customUserDetailsService;

    public JwtAuthenticationFilter(
            JwtService jwtService,
            CustomUserDetailsService customUserDetailsService
    ) {
        this.jwtService = jwtService;

        this.customUserDetailsService =
                customUserDetailsService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        /*
         * CORS preflight request ke saath access token
         * nahi aata. Isliye OPTIONS request ko direct
         * filter chain me continue karte hain.
         */
        if (HttpMethodConstants.OPTIONS.equalsIgnoreCase(
                request.getMethod()
        )) {
            filterChain.doFilter(request, response);
            return;
        }

        String authorizationHeader =
                request.getHeader("Authorization");

        /*
         * Login, registration aur other public requests
         * ke paas Bearer token nahi hoga.
         *
         * Missing token par 403 return nahi karna.
         * Request ko Spring Security tak continue karna hai.
         */
        if (authorizationHeader == null
                || !authorizationHeader.startsWith(
                        "Bearer "
                )) {

            filterChain.doFilter(request, response);
            return;
        }

        String jwtToken =
                authorizationHeader.substring(7);

        if (jwtToken.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        String userEmail;

        try {
            userEmail =
                    jwtService.extractUsername(jwtToken);

        } catch (Exception exception) {

            /*
             * Invalid or expired token ki condition me
             * authentication set nahi hogi.
             *
             * Protected endpoint par Spring Security
             * CustomAuthenticationEntryPoint se 401 return karega.
             */
            filterChain.doFilter(request, response);
            return;
        }

        if (userEmail != null
                && SecurityContextHolder
                .getContext()
                .getAuthentication() == null) {

            try {
                UserDetails userDetails =
                        customUserDetailsService
                                .loadUserByUsername(
                                        userEmail
                                );

                if (jwtService.isTokenValid(
                        jwtToken,
                        userDetails
                )) {

                    UsernamePasswordAuthenticationToken
                            authenticationToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                    authenticationToken.setDetails(
                            new WebAuthenticationDetailsSource()
                                    .buildDetails(request)
                    );

                    SecurityContextHolder
                            .getContext()
                            .setAuthentication(
                                    authenticationToken
                            );
                }

            } catch (Exception exception) {

                /*
                 * User not found, disabled account or token
                 * validation failure ke case me authentication
                 * set nahi hogi.
                 */
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }

    /*
     * Extra import avoid karne ke liye simple constant class.
     */
    private static final class HttpMethodConstants {

        private static final String OPTIONS = "OPTIONS";

        private HttpMethodConstants() {
        }
    }
}