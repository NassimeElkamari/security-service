package com.example.securityservice.web;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class API {

    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final UserDetailsService userDetailsService;

    public API(AuthenticationManager authenticationManager,
               JwtEncoder jwtEncoder,
               JwtDecoder jwtDecoder,
               UserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestParam String username,
                                     @RequestParam String password) {

        Map<String, String> ID_token = new HashMap<>();
        Instant instant = Instant.now();

        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        String scope = authenticate.getAuthorities()
                .stream()
                .map(auth -> auth.getAuthority())
                .collect(Collectors.joining(" "));

        JwtClaimsSet jwtClaimsSet_access = JwtClaimsSet.builder()
                .subject(authenticate.getName())
                .issuer("Security-Service")
                .issuedAt(instant)
                .expiresAt(instant.plus(2, ChronoUnit.HOURS))
                .claim("scope", scope)
                .build();

        String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_access)).getTokenValue();

        JwtClaimsSet jwtClaimsSet_refresh = JwtClaimsSet.builder()
                .subject(authenticate.getName())
                .issuer("Security-Service")
                .issuedAt(instant)
                .expiresAt(instant.plus(15, ChronoUnit.HOURS))
                .build();

        String refreshToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_refresh)).getTokenValue();

        ID_token.put("access_token", accessToken);
        ID_token.put("refresh_token", refreshToken);

        return ID_token;
    }

    @PostMapping("/refresh")
    public Map<String, String> refresh(@RequestParam("refresh_token") String refresh_token) {
        Map<String, String> ID_token = new HashMap<>();
        Instant instant = Instant.now();

        if (refresh_token == null) {
            ID_token.put("Error", "Refresh token is null" + HttpStatus.UNAUTHORIZED);
            return ID_token;
        }

        Jwt decoded = jwtDecoder.decode(refresh_token);
        String username = decoded.getSubject();

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        String scope = userDetails.getAuthorities()
                .stream()
                .map(auth -> auth.getAuthority())
                .collect(Collectors.joining(" "));

        JwtClaimsSet jwtClaimsSet_access = JwtClaimsSet.builder()
                .subject(userDetails.getUsername())
                .issuer("Security-Service")
                .issuedAt(instant)
                .expiresAt(instant.plus(2, ChronoUnit.HOURS))
                .claim("scope", scope)
                .build();

        String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet_access)).getTokenValue();

        ID_token.put("access_token", accessToken);
        ID_token.put("refresh_token", refresh_token);

        return ID_token;
    }
}
