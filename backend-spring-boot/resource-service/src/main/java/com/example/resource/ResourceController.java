package com.example.resource;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

    @GetMapping("/api/data")
    public String getProtectedData(@AuthenticationPrincipal Jwt jwt) {
        return "Hello " + jwt.getSubject() + "! Verified via RSA Public Key.";
    }
}
