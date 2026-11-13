# Asymmetric Microservice Architecture with Spring Boot 3.4 & RSA JWT

In an asymmetric microservice architecture, the **Auth Service (Producer)** signs JSON Web Tokens (JWTs) using its **Private Key**, and the **Resource Service (Consumer)** verifies those tokens independently using the **Public Key**—eliminating the need for network calls to validate every request.

---

## Architecture Flow

```
+--------------------------+                         +------------------------------+
|   Auth Service (8081)    |                         |   Resource Service (8082)    |
|   PRODUCER               |                         |   CONSUMER                   |
|                          |                         |                              |
|  [ Private Key: RS256 ]  |                         |  [ Public Key: X.509 SPKI ]  |
+------------+-------------+                         +--------------+---------------+
             |                                                      ^
             | 1. POST /token?username=bob                          | 2. GET /api/data
             |    Signs JWT with RSA Private Key                    |    Authorization: Bearer <token>
             v                                                      |    Offline Verification! Zero network call!
      [ Signed JWT ] -----------------------------------------------+
```

---

## 1. Key Generation

```bash
# 1. Generate the Private Key (for Auth Service)
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048

# 2. Extract the Public Key (for Resource Service)
openssl rsa -pubout -in private.pem -out public.pem
```

---

## 2. Testing with cURL

### Request a signed JWT from Producer (Port 8081):
```bash
TOKEN=$(curl -s -X POST "http://localhost:8081/token?username=bob")
echo $TOKEN
```

### Send the JWT to Consumer (Port 8082):
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8082/api/data
# Output: Hello bob! Verified via RSA Public Key.
```

---

## 3. Dynamic Key Rotation via JWKS Endpoint

Expose RFC 7517 JWKS on the Auth Service:
`GET http://localhost:8081/.well-known/jwks.json`

Configure Resource Service `application.yml`:
```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: http://localhost:8081/.well-known/jwks.json
```
Resource Server caches keys and checks `kid` automatically upon rotation.
