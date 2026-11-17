
package com.example.jwt.controller;

import com.example.jwt.service.JwtService;
import io.jsonwebtoken.Claims;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class JwtController {

    private final JwtService jwtService;

    public JwtController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(
            @RequestHeader("Authorization") String header) {

        Map<String, Object> response = new HashMap<>();

        if (header == null || !header.startsWith("Bearer ")) {
            response.put("valid", false);
            response.put("message", "Invalid Authorization header");

            return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(response);
        }

        String token = header.substring(7);

        if (jwtService.validateToken(token)) {

            Claims claims = jwtService.extractClaims(token);

            response.put("valid", true);
            response.put("username", claims.getSubject());
            response.put("issuer", claims.getIssuer());
            response.put("expiration", claims.getExpiration());
            response.put("claims", claims);

            return ResponseEntity.ok(response);

        } else {
            response.put("valid", false);
            response.put("message", "Invalid or expired token");

            return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(response);
        }
    }
}
