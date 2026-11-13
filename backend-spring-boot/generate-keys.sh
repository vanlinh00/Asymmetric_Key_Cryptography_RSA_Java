#!/usr/bin/env bash
set -e

# ==============================================================================
# Generate 2048-bit RSA Key Pair in PKCS#8 and X.509 PEM format
# For Asymmetric Spring Security Microservices
# ==============================================================================

echo "Creating certs directory..."
mkdir -p certs
mkdir -p auth-service/src/main/resources/certs
mkdir -p resource-service/src/main/resources/certs

# 1. Generate the Private Key (for Auth Service)
# Output is PKCS#8 encoded RSA private key
echo "1. Generating 2048-bit RSA Private Key..."
openssl genpkey -algorithm RSA -out certs/private.pem -pkeyopt rsa_keygen_bits:2048

# 2. Extract the Public Key (for Resource Service)
# Output is X.509 SPKI SubjectPublicKeyInfo PEM format
echo "2. Extracting RSA Public Key..."
openssl rsa -pubout -in certs/private.pem -out certs/public.pem

# Copy into respective Spring Boot service classpath
cp certs/private.pem auth-service/src/main/resources/certs/private.pem
cp certs/public.pem resource-service/src/main/resources/certs/public.pem

echo "Key generation complete!"
echo "Auth Service holds:      certs/private.pem"
echo "Resource Service holds:  certs/public.pem"
