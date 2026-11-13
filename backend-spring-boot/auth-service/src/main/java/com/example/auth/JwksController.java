package com.example.auth;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Exposes RFC 7517 JSON Web Key Set (JWKS) containing the RSA Public Key.
 * Enables dynamic discovery and non-disruptive key rotation for microservices.
 */
@RestController
public class JwksController {

    private final JWKSet jwkSet;

    public JwksController(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> getJwks() {
        return this.jwkSet.toJSONObject(true); // Excludes private key parameters, only exposes public keys (n, e, kid, use, alg)
    }
}
