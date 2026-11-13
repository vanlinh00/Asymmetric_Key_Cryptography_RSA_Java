package com.example.auth;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

@Configuration
public class RsaKeyConfig {

    @Value("${rsa.private-key}")
    private RSAPrivateKey privateKey; // Spring Boot 3.4 auto-converts PEM to RSAPrivateKey

    @Bean
    public RSAKey rsaJwk() throws Exception {
        // Derive public exponent/modulus from private key for JWK construction
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        java.security.spec.RSAPrivateCrtKeySpec privSpec =
                keyFactory.getKeySpec(privateKey, java.security.spec.RSAPrivateCrtKeySpec.class);
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(
                new RSAPublicKeySpec(privSpec.getModulus(), privSpec.getPublicExponent())
        );

        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID("auth-service-key-1")
                .build();
    }

    @Bean
    public JWKSet jwkSet(RSAKey rsaJwk) {
        return new JWKSet(rsaJwk);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSet jwkSet) {
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(jwkSet));
    }
}
