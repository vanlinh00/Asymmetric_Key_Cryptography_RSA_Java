/**
 * Cryptographic service for Asymmetric RSA 2048-bit JWT generation and verification.
 * Implements PKCS#8 Private Key signing and SPKI Public Key offline verification.
 */
import crypto from 'node:crypto';
import * as jose from 'jose';

export interface KeyPairRecord {
  kid: string;
  privateKeyPem: string;
  publicKeyPem: string;
  jwk: jose.JWK;
  createdAt: number;
  fingerprint: string;
  algorithm: 'RS256';
}

export interface TokenClaims {
  iss: string;
  sub: string;
  scope: string;
  iat: number;
  exp: number;
  jti: string;
}

export interface VerificationResult {
  valid: boolean;
  claims?: TokenClaims;
  header?: {
    alg: string;
    typ: string;
    kid?: string;
  };
  kidMatched?: string;
  latencyMicroseconds: number;
  networkCallsMade: 0;
  verificationMethod: string;
  error?: string;
  errorType?: 'INVALID_SIGNATURE' | 'EXPIRED' | 'MALFORMED' | 'UNKNOWN_KEY' | 'MISSING_TOKEN';
}

class CryptoManager {
  private activeKeyId: string = '';
  private keys: Map<string, KeyPairRecord> = new Map();
  private verificationsCount = 0;
  private totalLatencyUs = 0;

  constructor() {
    this.generateNewKeyPair('rsa-key-1');
  }

  /**
   * Generates a 2048-bit RSA key pair in PKCS#8 and X.509 SPKI PEM formats.
   * Matches `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`
   */
  public generateNewKeyPair(customKid?: string): KeyPairRecord {
    const kid = customKid || `rsa-key-${Date.now().toString(36)}`;
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    // Derive JWK format for RFC 7517 JWKS endpoint
    const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' }) as jose.JWK;
    jwk.kid = kid;
    jwk.use = 'sig';
    jwk.alg = 'RS256';

    // Calculate SHA-256 fingerprint of the public key
    const fingerprint = crypto
      .createHash('sha256')
      .update(publicKey)
      .digest('hex')
      .slice(0, 16);

    const record: KeyPairRecord = {
      kid,
      privateKeyPem: privateKey,
      publicKeyPem: publicKey,
      jwk,
      createdAt: Date.now(),
      fingerprint,
      algorithm: 'RS256',
    };

    this.keys.set(kid, record);
    this.activeKeyId = kid;
    return record;
  }

  public getActiveKeyPair(): KeyPairRecord {
    const active = this.keys.get(this.activeKeyId);
    if (!active) {
      return this.generateNewKeyPair();
    }
    return active;
  }

  public getKeyById(kid: string): KeyPairRecord | undefined {
    return this.keys.get(kid);
  }

  public getAllKeys(): KeyPairRecord[] {
    return Array.from(this.keys.values());
  }

  public getJwks(): { keys: jose.JWK[] } {
    return {
      keys: Array.from(this.keys.values()).map((k) => k.jwk),
    };
  }

  /**
   * Signs a JWT using the active RSA 2048-bit Private Key (RS256).
   * Producer (Auth Service) logic.
   */
  public async signToken(
    username: string = 'alice',
    scope: string = 'ROLE_USER',
    expiresInSeconds: number = 3600,
    customIssuer: string = 'auth-service'
  ): Promise<{ token: string; kid: string; claims: TokenClaims }> {
    const activeKey = this.getActiveKeyPair();
    const privateKeyObj = await jose.importPKCS8(activeKey.privateKeyPem, 'RS256');

    const now = Math.floor(Date.now() / 1000);
    const jti = crypto.randomUUID();

    const claims: TokenClaims = {
      iss: customIssuer,
      sub: username,
      scope,
      iat: now,
      exp: now + expiresInSeconds,
      jti,
    };

    const token = await new jose.SignJWT({
      scope: claims.scope,
      jti: claims.jti,
    })
      .setProtectedHeader({
        alg: 'RS256',
        typ: 'JWT',
        kid: activeKey.kid,
      })
      .setIssuer(claims.iss)
      .setSubject(claims.sub)
      .setIssuedAt(claims.iat)
      .setExpirationTime(claims.exp)
      .sign(privateKeyObj);

    return { token, kid: activeKey.kid, claims };
  }

  /**
   * Independently verifies a JWT using the RSA Public Key.
   * Consumer (Resource Service) logic. Zero network calls!
   */
  public async verifyToken(token: string): Promise<VerificationResult> {
    const start = performance.now();
    this.verificationsCount++;

    if (!token || typeof token !== 'string') {
      const latencyUs = Math.round((performance.now() - start) * 1000);
      return {
        valid: false,
        latencyMicroseconds: latencyUs,
        networkCallsMade: 0,
        verificationMethod: 'Local RSA 2048-bit Public Key Verification',
        error: 'Authorization token was not provided',
        errorType: 'MISSING_TOKEN',
      };
    }

    try {
      // Decode unverified header to locate 'kid'
      const decodedHeader = jose.decodeProtectedHeader(token);
      const kid = decodedHeader.kid;

      let publicKeyPem: string | undefined;

      if (kid && this.keys.has(kid)) {
        publicKeyPem = this.keys.get(kid)?.publicKeyPem;
      } else {
        // Fallback to active key or single configured public key (e.g., public-key-location: classpath:certs/public.pem)
        publicKeyPem = this.getActiveKeyPair().publicKeyPem;
      }

      if (!publicKeyPem) {
        throw new Error(`Public key with kid "${kid}" not found in local keystore`);
      }

      const publicKeyObj = await jose.importSPKI(publicKeyPem, 'RS256');

      const { payload, protectedHeader } = await jose.jwtVerify(token, publicKeyObj, {
        issuer: 'auth-service',
      });

      const latencyUs = Math.round((performance.now() - start) * 1000);
      this.totalLatencyUs += latencyUs;

      return {
        valid: true,
        claims: {
          iss: payload.iss as string,
          sub: payload.sub as string,
          scope: (payload.scope as string) || 'ROLE_USER',
          iat: payload.iat as number,
          exp: payload.exp as number,
          jti: (payload.jti as string) || '',
        },
        header: {
          alg: protectedHeader.alg,
          typ: protectedHeader.typ || 'JWT',
          kid: protectedHeader.kid,
        },
        kidMatched: kid,
        latencyMicroseconds: latencyUs,
        networkCallsMade: 0,
        verificationMethod: 'Local RSA 2048-bit Public Key Verification (Zero Network Overhead)',
      };
    } catch (err: any) {
      const latencyUs = Math.round((performance.now() - start) * 1000);
      let errorType: VerificationResult['errorType'] = 'INVALID_SIGNATURE';

      if (err.code === 'ERR_JWT_EXPIRED') {
        errorType = 'EXPIRED';
      } else if (err.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
        errorType = 'INVALID_SIGNATURE';
      } else if (err.code === 'ERR_JWS_INVALID') {
        errorType = 'MALFORMED';
      }

      return {
        valid: false,
        latencyMicroseconds: latencyUs,
        networkCallsMade: 0,
        verificationMethod: 'Local RSA 2048-bit Public Key Verification',
        error: err.message || 'Signature verification failed',
        errorType,
      };
    }
  }

  public getMetrics() {
    const avgLatency = this.verificationsCount > 0
      ? (this.totalLatencyUs / this.verificationsCount / 1000).toFixed(3)
      : '0.000';

    return {
      totalVerifications: this.verificationsCount,
      networkCallsEliminated: this.verificationsCount,
      avgLocalLatencyMs: parseFloat(avgLatency),
      activeKeyId: this.activeKeyId,
      totalKeysInJwks: this.keys.size,
    };
  }
}

export const cryptoManager = new CryptoManager();
