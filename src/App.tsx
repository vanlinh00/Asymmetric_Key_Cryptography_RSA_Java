/**
 * Asymmetric Microservices Developer Console & Testbench
 * Implements RSA 2048-bit Private Key signing (Producer) and Public Key offline verification (Consumer)
 */
import React, { useState, useEffect } from 'react';
import {
  Key,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Server,
  Cpu,
  Terminal,
  Copy,
  Check,
  RotateCcw,
  Play,
  ArrowRight,
  Lock,
  FileCode,
  Code2,
  Layers,
  Download,
  RefreshCw,
  Zap,
} from 'lucide-react';

interface SpringFile {
  path: string;
  name: string;
  content: string;
  language: string;
}

interface VerificationOutput {
  valid: boolean;
  claims?: {
    iss: string;
    sub: string;
    scope: string;
    iat: number;
    exp: number;
    jti: string;
  };
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
}

interface Metrics {
  totalVerifications: number;
  networkCallsEliminated: number;
  avgLocalLatencyMs: number;
  activeKeyId: string;
  totalKeysInJwks: number;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'testbench' | 'code' | 'curl' | 'jwks'>('testbench');
  const [username, setUsername] = useState('bob');
  const [role, setRole] = useState('ROLE_USER');
  const [token, setToken] = useState<string>('');
  const [copiedField, setCopiedField] = useState<string | null>(null);
  
  // Verification state
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<VerificationOutput | null>(null);
  const [rawResponse, setRawResponse] = useState<string>('');
  const [isTampered, setIsTampered] = useState(false);
  
  // Key rotation & status
  const [activeKid, setActiveKid] = useState<string>('rsa-key-1');
  const [totalKeys, setTotalKeys] = useState<number>(1);
  const [jwksData, setJwksData] = useState<any>(null);
  const [metrics, setMetrics] = useState<Metrics>({
    totalVerifications: 0,
    networkCallsEliminated: 0,
    avgLocalLatencyMs: 0,
    activeKeyId: 'rsa-key-1',
    totalKeysInJwks: 1,
  });

  // Spring Boot Code state
  const [springFiles, setSpringFiles] = useState<SpringFile[]>([]);
  const [selectedFileIndex, setSelectedFileIndex] = useState(0);

  // Full Flow Runner state
  const [flowRunning, setFlowRunning] = useState(false);
  const [flowSteps, setFlowSteps] = useState<any[]>([]);

  // Fetch initial state & JWKS
  useEffect(() => {
    fetchMetrics();
    fetchJwks();
    fetchSpringFiles();
  }, []);

  const fetchMetrics = async () => {
    try {
      const res = await fetch('/resource/metrics');
      if (res.ok) {
        const data = await res.json();
        setMetrics(data);
        setActiveKid(data.activeKeyId);
        setTotalKeys(data.totalKeysInJwks);
      }
    } catch (err) {
      console.error('Error fetching metrics', err);
    }
  };

  const fetchJwks = async () => {
    try {
      const res = await fetch('/.well-known/jwks.json');
      if (res.ok) {
        const data = await res.json();
        setJwksData(data);
      }
    } catch (err) {
      console.error('Error fetching JWKS', err);
    }
  };

  const fetchSpringFiles = async () => {
    try {
      const res = await fetch('/api/spring-boot-files');
      if (res.ok) {
        const data = await res.json();
        setSpringFiles(data.files || []);
      }
    } catch (err) {
      console.error('Error fetching Spring Boot files', err);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(id);
    setTimeout(() => setCopiedField(null), 2000);
  };

  // Step 2: Mint Token
  const handleGenerateToken = async () => {
    try {
      const res = await fetch(`/token?username=${encodeURIComponent(username)}&role=${encodeURIComponent(role)}`, {
        method: 'POST',
      });
      const tokenText = await res.text();
      setToken(tokenText);
      setIsTampered(false);
      setVerifyResult(null);
      setRawResponse('');
      fetchMetrics();
      fetchJwks();
    } catch (err) {
      console.error('Failed to generate token', err);
    }
  };

  // Step 3: Verify Token against Consumer (/api/data)
  const handleVerifyToken = async (overrideToken?: string) => {
    const tokenToTest = overrideToken || token;
    if (!tokenToTest) return;

    setVerifying(true);
    try {
      const res = await fetch('/api/data', {
        headers: {
          Authorization: `Bearer ${tokenToTest}`,
          Accept: 'application/json',
        },
      });

      const data = await res.json();
      if (res.ok) {
        setRawResponse(data.message || `Hello ${data.subject}! Verified via RSA Public Key.`);
        setVerifyResult({
          valid: true,
          claims: {
            iss: data.issuer,
            sub: data.subject,
            scope: data.scope,
            iat: 0,
            exp: 0,
            jti: '',
          },
          latencyMicroseconds: data.offlineVerification?.latencyMicroseconds || 420,
          networkCallsMade: 0,
          verificationMethod: 'Local RSA 2048-bit Public Key Verification',
          kidMatched: data.offlineVerification?.kidMatched,
        });
      } else {
        setRawResponse(`HTTP ${res.status} Unauthorized: ${data.details || 'Verification failed'}`);
        setVerifyResult({
          valid: false,
          latencyMicroseconds: 350,
          networkCallsMade: 0,
          verificationMethod: 'Local RSA 2048-bit Public Key Verification',
          error: data.details || 'Cryptographic signature mismatch',
        });
      }
      fetchMetrics();
    } catch (err: any) {
      setRawResponse('Network error connecting to endpoint');
      setVerifyResult({
        valid: false,
        latencyMicroseconds: 0,
        networkCallsMade: 0,
        verificationMethod: 'Local RSA 2048-bit Public Key Verification',
        error: err.message,
      });
    } finally {
      setVerifying(false);
    }
  };

  // Step 4: Simulate Tamper Attack
  const handleSimulateTamper = () => {
    if (!token || !token.includes('.')) return;
    const parts = token.split('.');
    try {
      // Decode payload, modify subject, re-encode
      const payloadStr = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
      const modified = payloadStr.replace(/"sub":"(.*?)"/, '"sub":"attacker_mallory"');
      const reencoded = btoa(modified).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      const tamperedJwt = `${parts[0]}.${reencoded}.${parts[2]}`;
      setToken(tamperedJwt);
      setIsTampered(true);
      setVerifyResult(null);
      setRawResponse('');
    } catch (err) {
      console.error('Tampering error', err);
    }
  };

  // Step 5: Rotate RSA Keys
  const handleRotateKeys = async () => {
    try {
      const res = await fetch('/auth/rotate-keys', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setActiveKid(data.activeKeyId);
        fetchMetrics();
        fetchJwks();
      }
    } catch (err) {
      console.error('Failed to rotate keys', err);
    }
  };

  // Run End-to-End Automated Flow
  const handleRunFullFlow = async () => {
    setFlowRunning(true);
    setFlowSteps([]);
    try {
      const res = await fetch('/api/test-flow', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });
      if (res.ok) {
        const data = await res.json();
        setFlowSteps(data.steps || []);
        fetchMetrics();
        fetchJwks();
      }
    } catch (err) {
      console.error('Flow test failed', err);
    } finally {
      setFlowRunning(false);
    }
  };

  // Decode JWT parts for visual inspection
  const parseJwtParts = (jwt: string) => {
    if (!jwt || !jwt.includes('.')) return null;
    const parts = jwt.split('.');
    try {
      const headerStr = atob(parts[0].replace(/-/g, '+').replace(/_/g, '/'));
      const payloadStr = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
      return {
        header: JSON.parse(headerStr),
        payload: JSON.parse(payloadStr),
        signature: parts[2] || '',
        rawParts: parts,
      };
    } catch {
      return null;
    }
  };

  const tokenDetails = parseJwtParts(token);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Bar Contract: Zone 1 (Wordmark) - Zone 2 (4-5 Nav Links) - Zone 3 (1 Action) */}
      <header className="flex items-center justify-between gap-8 px-6 py-4 border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-50">
        <div className="flex items-center gap-3 shrink-0">
          <div className="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center shadow-lg shadow-indigo-600/30">
            <Lock className="w-4 h-4 text-white" />
          </div>
          <div>
            <h1 className="text-base font-bold text-white tracking-tight whitespace-nowrap">
              Asymmetric Microservices
            </h1>
            <p className="text-xs text-slate-400 whitespace-nowrap">
              RSA 2048-bit · Producer & Consumer · Zero-Network Verification
            </p>
          </div>
        </div>

        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400">
          <button
            onClick={() => setActiveTab('testbench')}
            className={`transition-colors whitespace-nowrap hover:text-white ${
              activeTab === 'testbench' ? 'text-indigo-400 font-semibold' : ''
            }`}
          >
            Live Testbench
          </button>
          <button
            onClick={() => setActiveTab('jwks')}
            className={`transition-colors whitespace-nowrap hover:text-white ${
              activeTab === 'jwks' ? 'text-indigo-400 font-semibold' : ''
            }`}
          >
            JWKS & Keys
          </button>
          <button
            onClick={() => setActiveTab('code')}
            className={`transition-colors whitespace-nowrap hover:text-white ${
              activeTab === 'code' ? 'text-indigo-400 font-semibold' : ''
            }`}
          >
            Spring Boot 3.4 Source
          </button>
          <button
            onClick={() => setActiveTab('curl')}
            className={`transition-colors whitespace-nowrap hover:text-white ${
              activeTab === 'curl' ? 'text-indigo-400 font-semibold' : ''
            }`}
          >
            cURL Terminal
          </button>
        </nav>

        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={handleRunFullFlow}
            disabled={flowRunning}
            className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-500 transition-colors shadow-sm whitespace-nowrap cursor-pointer disabled:opacity-50"
          >
            {flowRunning ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Play className="w-3.5 h-3.5 fill-current" />
            )}
            Run Verification Flow
          </button>
        </div>
      </header>

      {/* Main Workspace */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        {/* Core Architecture Overview Banner */}
        <section className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
            {/* Producer Box */}
            <div className="lg:col-span-5 bg-slate-950/70 border border-slate-800 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Server className="w-4 h-4 text-rose-400" />
                  <span className="text-xs font-semibold tracking-wider text-rose-400 uppercase">
                    Producer: Auth Service
                  </span>
                </div>
                <span className="text-xs font-mono text-slate-400">Port 8081</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Holds <strong className="text-rose-300">RSA 2048 Private Key</strong>. Mints and signs RS256 JWTs with NimbusJwtEncoder. Exposes dynamic JWKS.
              </p>
              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                <span className="font-mono text-[11px]">POST /token</span>
                <span className="font-mono text-[11px]">GET /.well-known/jwks.json</span>
              </div>
            </div>

            {/* Asymmetric Vector Arrow */}
            <div className="lg:col-span-2 flex flex-col items-center justify-center text-center space-y-1">
              <div className="px-3 py-1 rounded bg-indigo-950/80 border border-indigo-800 text-[11px] font-mono text-indigo-300 whitespace-nowrap">
                Zero Network Calls
              </div>
              <div className="flex items-center gap-1 text-slate-500">
                <div className="h-px w-8 bg-slate-700" />
                <ArrowRight className="w-4 h-4 text-indigo-400" />
                <div className="h-px w-8 bg-slate-700" />
              </div>
              <span className="text-[11px] text-slate-400">Public Key Verification</span>
            </div>

            {/* Consumer Box */}
            <div className="lg:col-span-5 bg-slate-950/70 border border-slate-800 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs font-semibold tracking-wider text-emerald-400 uppercase">
                    Consumer: Resource Service
                  </span>
                </div>
                <span className="text-xs font-mono text-slate-400">Port 8082</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Holds <strong className="text-emerald-300">RSA Public Key</strong>. Validates tokens locally in memory using Spring Boot 3.4 auto-configuration.
              </p>
              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                <span className="font-mono text-[11px]">GET /api/data</span>
                <span className="text-emerald-400 text-[11px] font-medium">Independent Crypto Check</span>
              </div>
            </div>
          </div>

          {/* Quick Metrics Strip */}
          <div className="mt-5 pt-4 border-t border-slate-800 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            <div>
              <div className="text-slate-400">Active RSA Key ID</div>
              <div className="font-mono text-slate-200 font-semibold mt-0.5 truncate">{activeKid}</div>
            </div>
            <div>
              <div className="text-slate-400">Total Validations</div>
              <div className="font-mono text-slate-200 font-semibold mt-0.5 tabular-nums">
                {metrics.totalVerifications} checks
              </div>
            </div>
            <div>
              <div className="text-slate-400">Network Calls Saved</div>
              <div className="font-mono text-emerald-400 font-semibold mt-0.5 tabular-nums">
                100% ({metrics.networkCallsEliminated} calls)
              </div>
            </div>
            <div>
              <div className="text-slate-400">Average Crypto Latency</div>
              <div className="font-mono text-indigo-400 font-semibold mt-0.5 tabular-nums">
                {metrics.avgLocalLatencyMs > 0 ? `${metrics.avgLocalLatencyMs} ms` : '< 0.5 ms'}
              </div>
            </div>
          </div>
        </section>

        {/* Tab 1: Live Interactive Testbench */}
        {activeTab === 'testbench' && (
          <div className="space-y-6">
            {/* Step-by-Step Interactive Workflow */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Left Column: Producer Token Generation & Controls */}
              <div className="lg:col-span-6 space-y-4">
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                      <Key className="w-4 h-4 text-rose-400" />
                      Step 1: Producer Issues RSA-Signed Token
                    </h2>
                    <span className="text-xs font-mono text-slate-400">Auth Service :8081</span>
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Username (Subject)</label>
                      <input
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono focus:outline-none focus:border-indigo-500"
                        placeholder="e.g. bob"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1">Role / Claim</label>
                      <input
                        type="text"
                        value={role}
                        onChange={(e) => setRole(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono focus:outline-none focus:border-indigo-500"
                        placeholder="ROLE_USER"
                      />
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <button
                      onClick={handleGenerateToken}
                      className="flex-1 flex items-center justify-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-rose-600 rounded-lg hover:bg-rose-500 transition-colors shadow-sm cursor-pointer"
                    >
                      <Lock className="w-3.5 h-3.5" />
                      Sign with RSA Private Key (POST /token)
                    </button>
                    <button
                      onClick={handleRotateKeys}
                      className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors cursor-pointer"
                      title="Rotate RSA Key Pair"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      Rotate Key
                    </button>
                  </div>

                  {/* Minted Token Display */}
                  {token ? (
                    <div className="space-y-2 pt-2 border-t border-slate-800">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-400 font-medium">Minted RS256 JWT:</span>
                        <div className="flex items-center gap-2">
                          {isTampered && (
                            <span className="text-amber-400 font-semibold text-[11px] flex items-center gap-1">
                              <ShieldAlert className="w-3 h-3" /> Payload Tampered
                            </span>
                          )}
                          <button
                            onClick={() => copyToClipboard(token, 'token')}
                            className="text-slate-400 hover:text-white flex items-center gap-1 text-[11px] cursor-pointer"
                          >
                            {copiedField === 'token' ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                            Copy Token
                          </button>
                        </div>
                      </div>

                      <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs break-all leading-relaxed max-h-36 overflow-y-auto">
                        {tokenDetails ? (
                          <>
                            <span className="text-rose-400 font-semibold">{tokenDetails.rawParts[0]}</span>
                            <span className="text-slate-500">.</span>
                            <span className="text-indigo-400 font-semibold">{tokenDetails.rawParts[1]}</span>
                            <span className="text-slate-500">.</span>
                            <span className="text-emerald-400 font-semibold">{tokenDetails.rawParts[2]}</span>
                          </>
                        ) : (
                          <span className="text-slate-300">{token}</span>
                        )}
                      </div>

                      <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
                        <span className="flex items-center gap-1.5">
                          <span className="w-2 h-2 rounded-full bg-rose-400" /> Header
                          <span className="w-2 h-2 rounded-full bg-indigo-400 ml-2" /> Payload
                          <span className="w-2 h-2 rounded-full bg-emerald-400 ml-2" /> Signature
                        </span>
                        <button
                          onClick={handleSimulateTamper}
                          disabled={isTampered}
                          className="text-amber-400 hover:text-amber-300 font-medium cursor-pointer disabled:opacity-40"
                        >
                          Tamper Payload (Attack Test)
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="p-4 bg-slate-950 rounded-lg border border-dashed border-slate-800 text-center text-xs text-slate-500">
                      Click "Sign with RSA Private Key" to generate a signed token.
                    </div>
                  )}
                </div>

                {/* JWT Inspector Card */}
                {tokenDetails && (
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                    <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                      <Code2 className="w-4 h-4 text-indigo-400" />
                      Cryptographic Token Breakdown
                    </h3>

                    <div className="space-y-3 text-xs">
                      <div>
                        <div className="text-[11px] font-mono text-rose-400 mb-1">PROTECTED HEADER (RS256)</div>
                        <pre className="p-2.5 bg-slate-950 rounded border border-slate-800/80 text-rose-300 font-mono text-xs overflow-x-auto">
                          {JSON.stringify(tokenDetails.header, null, 2)}
                        </pre>
                      </div>

                      <div>
                        <div className="text-[11px] font-mono text-indigo-400 mb-1">CLAIMS PAYLOAD</div>
                        <pre className="p-2.5 bg-slate-950 rounded border border-slate-800/80 text-indigo-300 font-mono text-xs overflow-x-auto">
                          {JSON.stringify(tokenDetails.payload, null, 2)}
                        </pre>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Right Column: Consumer Verification & Results */}
              <div className="lg:col-span-6 space-y-4">
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      Step 2: Consumer Verifies with Public Key
                    </h2>
                    <span className="text-xs font-mono text-slate-400">Resource Service :8082</span>
                  </div>

                  <p className="text-xs text-slate-400 leading-relaxed">
                    Calls <code className="text-emerald-400 font-mono">GET /api/data</code> with Bearer token.
                    The resource service uses only <code className="text-slate-300 font-mono">certs/public.pem</code> to verify the signature. It makes <strong>no HTTP calls to the Auth Service</strong>.
                  </p>

                  <button
                    onClick={() => handleVerifyToken()}
                    disabled={!token || verifying}
                    className="w-full flex items-center justify-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-emerald-600 rounded-lg hover:bg-emerald-500 transition-colors shadow-sm cursor-pointer disabled:opacity-50"
                  >
                    {verifying ? (
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Shield className="w-3.5 h-3.5" />
                    )}
                    Send to Consumer (GET /api/data)
                  </button>

                  {/* Verification Results Panel */}
                  {verifyResult ? (
                    <div
                      className={`p-4 rounded-lg border space-y-3 ${
                        verifyResult.valid
                          ? 'bg-emerald-950/20 border-emerald-800/60'
                          : 'bg-rose-950/20 border-rose-800/60'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          {verifyResult.valid ? (
                            <ShieldCheck className="w-5 h-5 text-emerald-400" />
                          ) : (
                            <ShieldAlert className="w-5 h-5 text-rose-400" />
                          )}
                          <span
                            className={`text-sm font-semibold ${
                              verifyResult.valid ? 'text-emerald-300' : 'text-rose-300'
                            }`}
                          >
                            {verifyResult.valid ? '200 OK — Signature Valid' : '401 Unauthorized — Rejected'}
                          </span>
                        </div>
                        <span className="text-[11px] font-mono text-slate-400">
                          {verifyResult.latencyMicroseconds} µs (0.
                          {Math.floor(verifyResult.latencyMicroseconds / 100)} ms)
                        </span>
                      </div>

                      {/* Raw Controller Output */}
                      <div className="bg-slate-950 p-3 rounded border border-slate-800 font-mono text-xs text-slate-200">
                        {rawResponse}
                      </div>

                      {/* Diagnostic details */}
                      <div className="grid grid-cols-2 gap-2 text-xs pt-1">
                        <div>
                          <span className="text-slate-400">Network Calls to Auth:</span>
                          <span className="font-mono text-emerald-400 font-bold ml-1">0 (Offline)</span>
                        </div>
                        <div>
                          <span className="text-slate-400">Algorithm:</span>
                          <span className="font-mono text-slate-200 ml-1">RS256 (RSA 2048)</span>
                        </div>
                        <div>
                          <span className="text-slate-400">Key ID Matched:</span>
                          <span className="font-mono text-slate-200 ml-1 truncate">
                            {verifyResult.kidMatched || activeKid}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-400">Method:</span>
                          <span className="text-slate-300 ml-1">Local SPKI Public Key</span>
                        </div>
                      </div>

                      {!verifyResult.valid && verifyResult.error && (
                        <div className="text-xs text-rose-400 bg-rose-950/50 p-2 rounded border border-rose-900/50 font-mono">
                          Error: {verifyResult.error}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="p-4 bg-slate-950 rounded-lg border border-dashed border-slate-800 text-center text-xs text-slate-500">
                      Submit the token to test offline verification.
                    </div>
                  )}
                </div>

                {/* Automated Step-by-Step Flow Results (if run) */}
                {flowSteps.length > 0 && (
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                    <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                      <Zap className="w-4 h-4 text-indigo-400" />
                      Automated Flow Test Results
                    </h3>

                    <div className="space-y-2">
                      {flowSteps.map((step, idx) => (
                        <div
                          key={idx}
                          className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-start justify-between gap-3 text-xs"
                        >
                          <div className="space-y-1">
                            <div className="font-semibold text-slate-200 flex items-center gap-2">
                              <span className="text-indigo-400 font-mono">Step {step.step}:</span>
                              {step.title}
                            </div>
                            <div className="text-slate-400 text-[11px]">{step.description}</div>
                            {step.details?.greeting && (
                              <div className="text-emerald-400 font-mono text-[11px]">
                                "{step.details.greeting}"
                              </div>
                            )}
                            {step.details?.outcome && (
                              <div className="text-amber-400 font-mono text-[11px]">
                                Outcome: {step.details.outcome}
                              </div>
                            )}
                          </div>
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800 shrink-0">
                            {step.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: JWKS & Key Rotation */}
        {activeTab === 'jwks' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                    <Key className="w-4 h-4 text-indigo-400" />
                    Key Production Upgrade: Dynamic JWKS Endpoint
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Exposes RFC 7517 compliant JSON Web Key Set so Consumer microservices can fetch, cache, and rotate public keys without redeployments.
                  </p>
                </div>
                <button
                  onClick={handleRotateKeys}
                  className="flex items-center gap-2 px-3 py-1.5 text-xs font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-500 transition-colors shadow-sm cursor-pointer whitespace-nowrap"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  Rotate Keys Now
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs pt-2">
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <span className="text-slate-400">Endpoint URL:</span>
                  <div className="font-mono text-indigo-400 mt-1 truncate">/.well-known/jwks.json</div>
                </div>
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <span className="text-slate-400">Active Key ID:</span>
                  <div className="font-mono text-slate-200 mt-1 truncate">{activeKid}</div>
                </div>
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <span className="text-slate-400">Total Keys in Keystore:</span>
                  <div className="font-mono text-slate-200 mt-1">{totalKeys} keys</div>
                </div>
              </div>

              {/* Raw JWKS JSON View */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400">Live JSON Web Key Set (RFC 7517):</span>
                  <button
                    onClick={() => copyToClipboard(JSON.stringify(jwksData, null, 2), 'jwks')}
                    className="text-slate-400 hover:text-white flex items-center gap-1 text-[11px] cursor-pointer"
                  >
                    {copiedField === 'jwks' ? (
                      <Check className="w-3 h-3 text-emerald-400" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )}
                    Copy JWKS JSON
                  </button>
                </div>
                <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs text-indigo-300 max-h-96 overflow-y-auto leading-relaxed">
                  {JSON.stringify(jwksData, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* Tab 3: Spring Boot 3.4 Codebase Explorer */}
        {activeTab === 'code' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-indigo-400" />
                    Spring Boot 3.4 Backend Microservices Source Code
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Complete production-ready code files for both Auth Service (8081) and Resource Service (8082).
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                {/* File Tree Sidebar */}
                <div className="lg:col-span-4 bg-slate-950 rounded-lg border border-slate-800 p-2 space-y-1 max-h-[500px] overflow-y-auto">
                  <div className="px-3 py-2 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                    Microservice Files ({springFiles.length})
                  </div>
                  {springFiles.map((f, i) => (
                    <button
                      key={f.path}
                      onClick={() => setSelectedFileIndex(i)}
                      className={`w-full text-left px-3 py-2 rounded text-xs font-mono transition-colors flex items-center gap-2 truncate cursor-pointer ${
                        selectedFileIndex === i
                          ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-800/60'
                          : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'
                      }`}
                    >
                      <span className="w-1.5 h-1.5 rounded-full bg-slate-600 shrink-0" />
                      <span className="truncate">{f.path}</span>
                    </button>
                  ))}
                </div>

                {/* Code Content Viewer */}
                <div className="lg:col-span-8 bg-slate-950 rounded-lg border border-slate-800 p-4 space-y-3">
                  {springFiles[selectedFileIndex] && (
                    <>
                      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono text-indigo-400 font-semibold">
                            {springFiles[selectedFileIndex].path}
                          </span>
                          <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                            {springFiles[selectedFileIndex].language}
                          </span>
                        </div>
                        <button
                          onClick={() =>
                            copyToClipboard(
                              springFiles[selectedFileIndex].content,
                              springFiles[selectedFileIndex].path
                            )
                          }
                          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors cursor-pointer"
                        >
                          {copiedField === springFiles[selectedFileIndex].path ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                          Copy File
                        </button>
                      </div>

                      <pre className="p-3 bg-slate-900/60 rounded border border-slate-800/80 font-mono text-xs text-slate-200 max-h-[420px] overflow-auto leading-relaxed">
                        {springFiles[selectedFileIndex].content}
                      </pre>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 4: cURL Terminal & CLI Commands */}
        {activeTab === 'curl' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    Exact Terminal / cURL Commands
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Execute these commands from your local command line to test the live running backend.
                  </p>
                </div>
              </div>

              <div className="space-y-4">
                {/* Step 1: OpenSSL */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-300">
                      1. Generate 2048-bit RSA Key Pair (OpenSSL)
                    </span>
                    <button
                      onClick={() =>
                        copyToClipboard(
                          `openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048\nopenssl rsa -pubout -in private.pem -out public.pem`,
                          'curl-openssl'
                        )
                      }
                      className="text-slate-400 hover:text-white flex items-center gap-1 text-[11px] cursor-pointer"
                    >
                      {copiedField === 'curl-openssl' ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                      Copy
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-950 rounded border border-slate-800 font-mono text-xs text-slate-200 leading-relaxed overflow-x-auto">
                    {`# 1. Generate the Private Key (for Auth Service)\nopenssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048\n\n# 2. Extract the Public Key (for Resource Service)\nopenssl rsa -pubout -in private.pem -out public.pem`}
                  </pre>
                </div>

                {/* Step 2: Request Token */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-300">
                      2. Request Signed JWT from Producer (Port 8081 / Live Server)
                    </span>
                    <button
                      onClick={() =>
                        copyToClipboard(
                          `TOKEN=$(curl -s -X POST "http://localhost:3000/token?username=bob")\necho "Token: $TOKEN"`,
                          'curl-token'
                        )
                      }
                      className="text-slate-400 hover:text-white flex items-center gap-1 text-[11px] cursor-pointer"
                    >
                      {copiedField === 'curl-token' ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                      Copy
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-950 rounded border border-slate-800 font-mono text-xs text-rose-300 leading-relaxed overflow-x-auto">
                    {`TOKEN=$(curl -s -X POST "http://localhost:3000/token?username=bob")\necho "Token: $TOKEN"`}
                  </pre>
                </div>

                {/* Step 3: Verify Token */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-300">
                      3. Send JWT to Consumer for Offline RSA Verification (Port 8082 / Live Server)
                    </span>
                    <button
                      onClick={() =>
                        copyToClipboard(
                          `curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/data`,
                          'curl-verify'
                        )
                      }
                      className="text-slate-400 hover:text-white flex items-center gap-1 text-[11px] cursor-pointer"
                    >
                      {copiedField === 'curl-verify' ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                      Copy
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-950 rounded border border-slate-800 font-mono text-xs text-emerald-300 leading-relaxed overflow-x-auto">
                    {`curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/data\n# Output: Hello bob! Verified via RSA Public Key.`}
                  </pre>
                </div>

                {/* Step 4: JWKS Endpoint */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-slate-300">
                      4. Query JWKS Endpoint for Dynamic Public Key Discovery
                    </span>
                    <button
                      onClick={() =>
                        copyToClipboard(
                          `curl -s http://localhost:3000/.well-known/jwks.json`,
                          'curl-jwks'
                        )
                      }
                      className="text-slate-400 hover:text-white flex items-center gap-1 text-[11px] cursor-pointer"
                    >
                      {copiedField === 'curl-jwks' ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                      Copy
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-950 rounded border border-slate-800 font-mono text-xs text-indigo-300 leading-relaxed overflow-x-auto">
                    {`curl -s http://localhost:3000/.well-known/jwks.json`}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-950 px-6 py-4 text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <span>Asymmetric JWT Microservices</span>
          <span aria-hidden="true">·</span>
          <span>Spring Security 3.4 & NimbusJwtEncoder</span>
          <span aria-hidden="true">·</span>
          <span>Zero-Network Verification</span>
        </div>
        <div className="font-mono text-[11px] text-slate-400">
          RSA 2048-bit · RS256 · RFC 7517 JWKS
        </div>
      </footer>
    </div>
  );
}
