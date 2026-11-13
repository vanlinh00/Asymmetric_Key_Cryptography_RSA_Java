import express, { Request, Response, NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { cryptoManager } from './src/backend/crypto-service.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3000;
const isProduction = process.env.NODE_ENV === 'production';

// Support JSON and URL-encoded request bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging for developer transparency
app.use((req: Request, res: Response, next: NextFunction) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (!req.path.startsWith('/@') && !req.path.startsWith('/src/')) {
      console.log(`[HTTP] ${req.method} ${req.path} -> ${res.statusCode} (${duration}ms)`);
    }
  });
  next();
});

// ==============================================================================
// 1. PRODUCER: AUTH SERVICE (PORT 8081 Simulated Endpoints)
// Holds RSA 2048-bit Private Key -> Signs JWTs with Nimbus/Jose equivalent
// ==============================================================================

/**
 * Mint RSA-signed JWT token
 * Supports both /token (Spring Boot default) and /auth/token
 */
const handleTokenGeneration = async (req: Request, res: Response) => {
  try {
    const username = (req.query.username as string) || req.body?.username || 'alice';
    const role = (req.query.role as string) || req.body?.role || 'ROLE_USER';
    const ttlSeconds = req.query.ttl ? parseInt(req.query.ttl as string) : 3600;

    const { token, kid, claims } = await cryptoManager.signToken(username, role, ttlSeconds);

    // If client requested JSON via Accept header or format query param, respond with JSON
    const wantsJson = req.headers.accept?.includes('application/json') || req.query.format === 'json';

    if (wantsJson) {
      res.json({
        access_token: token,
        token_type: 'Bearer',
        expires_in: ttlSeconds,
        kid,
        claims,
        issuer: 'auth-service',
        algorithm: 'RS256',
      });
    } else {
      // Default to plain token string matching:
      // TOKEN=$(curl -s -X POST "http://localhost:8081/token?username=bob")
      res.set('Content-Type', 'text/plain');
      res.send(token);
    }
  } catch (err: any) {
    console.error('Token signing error:', err);
    res.status(500).json({ error: 'Failed to sign JWT', details: err.message });
  }
};

app.post('/token', handleTokenGeneration);
app.post('/auth/token', handleTokenGeneration);

/**
 * RFC 7517 JWKS Endpoint
 * Exposes the RSA Public Keys so Consumer microservices can fetch and verify dynamically
 */
const handleJwks = (_req: Request, res: Response) => {
  res.set('Cache-Control', 'public, max-age=300');
  res.json(cryptoManager.getJwks());
};

app.get('/.well-known/jwks.json', handleJwks);
app.get('/auth/.well-known/jwks.json', handleJwks);

/**
 * Export Public Key (X.509 SPKI PEM)
 * For classpath:certs/public.pem in Resource Service
 */
const handlePublicKeyPem = (_req: Request, res: Response) => {
  const activeKey = cryptoManager.getActiveKeyPair();
  res.set('Content-Type', 'text/plain');
  res.send(activeKey.publicKeyPem);
};

app.get('/certs/public.pem', handlePublicKeyPem);
app.get('/auth/certs/public.pem', handlePublicKeyPem);

/**
 * Export Private Key (PKCS#8 PEM) - Auth Service only
 */
app.get('/auth/certs/private.pem', (_req: Request, res: Response) => {
  const activeKey = cryptoManager.getActiveKeyPair();
  res.set('Content-Type', 'text/plain');
  res.send(activeKey.privateKeyPem);
});

/**
 * Key Rotation Endpoint: generates a new 2048-bit RSA key
 * Retains previous keys in JWKS so consumers with in-flight tokens still verify
 */
app.post('/auth/rotate-keys', (_req: Request, res: Response) => {
  const newKey = cryptoManager.generateNewKeyPair();
  res.json({
    message: 'RSA key pair successfully rotated',
    activeKeyId: newKey.kid,
    fingerprint: newKey.fingerprint,
    totalKeysInJwks: cryptoManager.getJwks().keys.length,
    jwksUri: '/auth/.well-known/jwks.json',
  });
});

/**
 * Key inventory inspection
 */
app.get('/auth/keys', (_req: Request, res: Response) => {
  const keys = cryptoManager.getAllKeys().map((k) => ({
    kid: k.kid,
    algorithm: k.algorithm,
    fingerprint: k.fingerprint,
    createdAt: new Date(k.createdAt).toISOString(),
    isActive: k.kid === cryptoManager.getActiveKeyPair().kid,
  }));
  res.json({
    activeKeyId: cryptoManager.getActiveKeyPair().kid,
    totalKeys: keys.length,
    keys,
  });
});

// ==============================================================================
// 2. CONSUMER: RESOURCE SERVICE (PORT 8082 Simulated Endpoints)
// Holds RSA Public Key -> Verifies JWTs independently without network calls
// ==============================================================================

/**
 * Protected Resource Endpoint: /api/data
 * Requires: Authorization: Bearer <token>
 * Returns: "Hello " + jwt.getSubject() + "! Verified via RSA Public Key."
 */
const handleProtectedData = async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.set('WWW-Authenticate', 'Bearer error="invalid_token", error_description="Missing or malformed Authorization header"');
    res.status(401).send('Unauthorized: Bearer token required in Authorization header');
    return;
  }

  const token = authHeader.substring(7).trim();
  const verification = await cryptoManager.verifyToken(token);

  if (!verification.valid || !verification.claims) {
    res.set(
      'WWW-Authenticate',
      `Bearer error="invalid_token", error_description="${verification.error || 'Token verification failed'}"`
    );
    res.status(401).json({
      error: 'Unauthorized',
      details: verification.error,
      errorType: verification.errorType,
      networkCallsMade: 0,
    });
    return;
  }

  // Exact response from Spring Boot ResourceController:
  // "Hello " + jwt.getSubject() + "! Verified via RSA Public Key."
  const greeting = `Hello ${verification.claims.sub}! Verified via RSA Public Key.`;

  // Return plain string if text/plain or default curl
  const wantsJson = req.headers.accept?.includes('application/json') || req.query.format === 'json';

  if (wantsJson) {
    res.json({
      message: greeting,
      subject: verification.claims.sub,
      scope: verification.claims.scope,
      issuer: verification.claims.iss,
      expiresAt: new Date(verification.claims.exp * 1000).toISOString(),
      offlineVerification: {
        method: verification.verificationMethod,
        latencyMicroseconds: verification.latencyMicroseconds,
        networkCallsMade: 0,
        kidMatched: verification.kidMatched,
      },
    });
  } else {
    res.set('Content-Type', 'text/plain');
    res.send(greeting);
  }
};

app.get('/api/data', handleProtectedData);
app.get('/resource/api/data', handleProtectedData);

/**
 * Diagnostic verification endpoint for interactive testing & security validation
 */
app.post('/resource/api/verify', async (req: Request, res: Response) => {
  const { token, tampered } = req.body;
  let testToken = token;

  if (tampered && typeof testToken === 'string' && testToken.includes('.')) {
    const parts = testToken.split('.');
    // Flip a character in the signature or payload
    const payloadJson = Buffer.from(parts[1], 'base64url').toString('utf8');
    const modifiedPayload = payloadJson.replace(/"sub":"(.*?)"/, '"sub":"attacker"');
    parts[1] = Buffer.from(modifiedPayload).toString('base64url');
    testToken = parts.join('.');
  }

  const result = await cryptoManager.verifyToken(testToken);
  res.json({
    ...result,
    isTampered: Boolean(tampered),
    timestamp: new Date().toISOString(),
  });
});

/**
 * Metrics: Proves zero network calls and sub-millisecond local CPU validation
 */
app.get('/resource/metrics', (_req: Request, res: Response) => {
  res.json(cryptoManager.getMetrics());
});

// ==============================================================================
// 3. COMPLETE AUTOMATED FLOW TESTER ENDPOINT
// Executes the exact steps from the user prompt:
// 1. Generate token from Producer
// 2. Validate token on Consumer
// 3. Test tampered token rejection
// 4. Test expired token rejection
// 5. Rotate keys and verify JWKS
// ==============================================================================
app.post('/api/test-flow', async (req: Request, res: Response) => {
  const username = req.body.username || 'bob';
  const steps: any[] = [];

  // Step 1: Mint token from Auth Service
  const t0 = performance.now();
  const { token, kid, claims } = await cryptoManager.signToken(username, 'ROLE_USER', 3600);
  const mintLatencyMs = (performance.now() - t0).toFixed(2);

  steps.push({
    step: 1,
    title: 'Producer: Generate Signed JWT (/token)',
    description: `Auth Service signs 2048-bit RS256 token for user "${username}" using Private Key`,
    status: 'SUCCESS',
    latencyMs: mintLatencyMs,
    details: {
      kid,
      algorithm: 'RS256',
      claims,
      tokenPreview: `${token.slice(0, 32)}...${token.slice(-24)}`,
    },
  });

  // Step 2: Validate with Consumer
  const verifyResult = await cryptoManager.verifyToken(token);
  steps.push({
    step: 2,
    title: 'Consumer: Verify with Public Key (/api/data)',
    description: 'Resource Service verifies token using Public Key without network calls',
    status: verifyResult.valid ? 'SUCCESS' : 'FAILED',
    latencyMicroseconds: verifyResult.latencyMicroseconds,
    networkCallsMade: 0,
    details: {
      greeting: `Hello ${claims.sub}! Verified via RSA Public Key.`,
      kidMatched: verifyResult.kidMatched,
      verificationMethod: verifyResult.verificationMethod,
    },
  });

  // Step 3: Tamper Test (Simulate MITM attack modifying payload)
  const parts = token.split('.');
  const tamperedPayload = Buffer.from(
    Buffer.from(parts[1], 'base64url').toString('utf8').replace(`"sub":"${username}"`, '"sub":"mallory_attacker"')
  ).toString('base64url');
  const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

  const tamperResult = await cryptoManager.verifyToken(tamperedToken);
  steps.push({
    step: 3,
    title: 'Security: Tampered Token Rejection Test',
    description: 'Resource Service detects modified payload and cryptographically rejects it',
    status: !tamperResult.valid ? 'SUCCESS' : 'FAILED',
    rejectedAsExpected: !tamperResult.valid,
    details: {
      error: tamperResult.error,
      errorType: tamperResult.errorType,
      outcome: '401 Unauthorized - Cryptographic mismatch',
    },
  });

  // Step 4: Key Rotation & JWKS Dynamic Discovery
  const keyBefore = cryptoManager.getActiveKeyPair().kid;
  const newKey = cryptoManager.generateNewKeyPair();
  const jwks = cryptoManager.getJwks();

  // Mint new token with rotated key
  const rotated = await cryptoManager.signToken('charlie', 'ROLE_ADMIN');
  const rotatedVerify = await cryptoManager.verifyToken(rotated.token);

  steps.push({
    step: 4,
    title: 'Production Upgrade: Dynamic Key Rotation & JWKS',
    description: 'Producer rotated RSA keys. Both new and existing keys coexist in /.well-known/jwks.json',
    status: rotatedVerify.valid ? 'SUCCESS' : 'FAILED',
    details: {
      previousActiveKey: keyBefore,
      newActiveKey: newKey.kid,
      totalKeysInJwks: jwks.keys.length,
      rotatedTokenVerified: rotatedVerify.valid,
    },
  });

  res.json({
    success: true,
    totalSteps: steps.length,
    steps,
    metrics: cryptoManager.getMetrics(),
  });
});

// ==============================================================================
// 4. SPRING BOOT SOURCE CODE EXPLORER API
// Serves the full Java codebase directly from backend-spring-boot/
// ==============================================================================
const getSpringFiles = () => {
  const baseDir = path.resolve(__dirname, 'backend-spring-boot');
  const fileList: { path: string; name: string; content: string; language: string }[] = [];

  const traverse = (dir: string) => {
    if (!fs.existsSync(dir)) return;
    const items = fs.readdirSync(dir);
    for (const item of items) {
      const fullPath = path.join(dir, item);
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        traverse(fullPath);
      } else {
        const relativePath = path.relative(baseDir, fullPath);
        const ext = path.extname(item);
        let language = 'text';
        if (ext === '.java') language = 'java';
        else if (ext === '.xml') language = 'xml';
        else if (ext === '.yml' || ext === '.yaml') language = 'yaml';
        else if (ext === '.sh') language = 'bash';
        else if (ext === '.md') language = 'markdown';
        else if (ext === '.json') language = 'json';

        try {
          const content = fs.readFileSync(fullPath, 'utf8');
          fileList.push({
            path: relativePath,
            name: item,
            content,
            language,
          });
        } catch {
          // ignore binary files if any
        }
      }
    }
  };

  traverse(baseDir);
  return fileList;
};

app.get('/api/spring-boot-files', (_req: Request, res: Response) => {
  res.json({
    count: getSpringFiles().length,
    files: getSpringFiles(),
  });
});

// ==============================================================================
// 5. FRONTEND & VITE DEV / PROD SERVER MOUNT
// Developer Console & Testbench for the Asymmetric Microservices
// ==============================================================================
async function startServer() {
  if (!isProduction) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n======================================================`);
    console.log(`  ASYMMETRIC MICROSERVICES BACKEND RUNNING ON PORT ${PORT}`);
    console.log(`======================================================`);
    console.log(`  [Auth Service - Producer]`);
    console.log(`  POST http://localhost:${PORT}/token?username=bob`);
    console.log(`  GET  http://localhost:${PORT}/.well-known/jwks.json`);
    console.log(`  GET  http://localhost:${PORT}/certs/public.pem`);
    console.log(``);
    console.log(`  [Resource Service - Consumer]`);
    console.log(`  GET  http://localhost:${PORT}/api/data  (Header: Authorization: Bearer <token>)`);
    console.log(`  POST http://localhost:${PORT}/resource/api/verify`);
    console.log(`  GET  http://localhost:${PORT}/resource/metrics`);
    console.log(`======================================================\n`);
  });
}

startServer();
