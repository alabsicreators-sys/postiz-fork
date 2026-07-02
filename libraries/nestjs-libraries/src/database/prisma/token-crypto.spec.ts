/**
 * Unit tests for the Nashir thin-fork token encryption patch
 * (token-crypto.ts + the decrypt-walk in prisma.service.ts).
 *
 * No real GCP access: '@google-cloud/kms' is jest-mocked with tuple-style
 * responses matching the KmsClientLike interface.
 *
 * NOTE on running: this repo ships no working jest wiring — the root
 * jest.config.ts imports '@nx/jest', which is not a dependency (and there is
 * no nx.json) — so run this spec with the standalone config:
 *
 *   npx jest -c libraries/nestjs-libraries/jest.config.cjs --coverage=false
 *
 * token-crypto.ts caches its key material and warn-once state at module scope,
 * so every test loads a fresh copy via jest.isolateModules().
 */

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

const mockKmsEncrypt = jest.fn();
const mockKmsDecrypt = jest.fn();

// token-crypto.ts lazy-imports '@google-cloud/kms' only when
// POSTIZ_KMS_KEY_RESOURCE is set; mock it so no real GCP client is created.
jest.mock(
  '@google-cloud/kms',
  () => ({
    KeyManagementServiceClient: class {
      encrypt = mockKmsEncrypt;
      decrypt = mockKmsDecrypt;
    },
  }),
  { virtual: true }
);

// prisma.service.ts imports NestJS and the generated Prisma client; neither is
// needed by decryptIntegrationTokens(), so stub them out.
jest.mock(
  '@nestjs/common',
  () => ({
    Injectable: () => (target: unknown) => target,
  }),
  { virtual: true }
);
jest.mock(
  '@prisma/client',
  () => ({
    PrismaClient: class {
      $use() {
        /* middleware registration is a no-op in unit tests */
      }
      $connect() {}
      $disconnect() {}
    },
  }),
  { virtual: true }
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type TokenCryptoModule = typeof import('./token-crypto');
type PrismaServiceModule = typeof import('./prisma.service');

const SOFTWARE_KEY_B64 = Buffer.alloc(32, 7).toString('base64');
const KMS_RESOURCE = 'projects/p/locations/l/keyRings/kr/cryptoKeys/ck';
const KMS_WRAP_PREFIX = Buffer.from('kms-wrapped:');

/** Loads a fresh token-crypto module (fresh key/warn state) from current env. */
function loadTokenCrypto(): TokenCryptoModule {
  let mod: TokenCryptoModule | undefined;
  jest.isolateModules(() => {
    mod = require('./token-crypto');
  });
  return mod as TokenCryptoModule;
}

/** Loads token-crypto + prisma.service in the SAME registry so they share state. */
function loadWithPrismaService(): {
  tc: TokenCryptoModule;
  ps: PrismaServiceModule;
} {
  let tc: TokenCryptoModule | undefined;
  let ps: PrismaServiceModule | undefined;
  jest.isolateModules(() => {
    tc = require('./token-crypto');
    ps = require('./prisma.service');
  });
  return { tc: tc as TokenCryptoModule, ps: ps as PrismaServiceModule };
}

/** Tuple-style mock KMS: wrap = prefix + plaintext, unwrap strips the prefix. */
function installKmsMockImplementations(): void {
  mockKmsEncrypt.mockImplementation(
    async ({ plaintext }: { name: string; plaintext: Buffer }) => [
      { ciphertext: Buffer.concat([KMS_WRAP_PREFIX, plaintext]) },
      undefined,
      undefined,
    ]
  );
  mockKmsDecrypt.mockImplementation(
    async ({ ciphertext }: { name: string; ciphertext: Buffer }) => [
      { plaintext: Buffer.from(ciphertext).subarray(KMS_WRAP_PREFIX.length) },
      undefined,
      undefined,
    ]
  );
}

const originalSoftwareKey = process.env.POSTIZ_TOKEN_ENCRYPTION_KEY;
const originalKmsResource = process.env.POSTIZ_KMS_KEY_RESOURCE;

beforeEach(() => {
  delete process.env.POSTIZ_TOKEN_ENCRYPTION_KEY;
  delete process.env.POSTIZ_KMS_KEY_RESOURCE;
  mockKmsEncrypt.mockReset();
  mockKmsDecrypt.mockReset();
});

afterAll(() => {
  if (originalSoftwareKey === undefined) {
    delete process.env.POSTIZ_TOKEN_ENCRYPTION_KEY;
  } else {
    process.env.POSTIZ_TOKEN_ENCRYPTION_KEY = originalSoftwareKey;
  }
  if (originalKmsResource === undefined) {
    delete process.env.POSTIZ_KMS_KEY_RESOURCE;
  } else {
    process.env.POSTIZ_KMS_KEY_RESOURCE = originalKmsResource;
  }
});

// ---------------------------------------------------------------------------
// (i) Software-key round-trip
// ---------------------------------------------------------------------------

describe('software-key mode (POSTIZ_TOKEN_ENCRYPTION_KEY)', () => {
  beforeEach(() => {
    process.env.POSTIZ_TOKEN_ENCRYPTION_KEY = SOFTWARE_KEY_B64;
  });

  it('reports encryption as enabled', () => {
    const { isTokenEncryptionEnabled } = loadTokenCrypto();
    expect(isTokenEncryptionEnabled()).toBe(true);
  });

  it('round-trips a token through a v1 5-part envelope', async () => {
    const { encryptToken, decryptToken } = loadTokenCrypto();
    const plaintext = 'super-secret-oauth-token';

    const envelope = await encryptToken(plaintext);

    expect(envelope).not.toBe(plaintext);
    expect(envelope.startsWith('v1:')).toBe(true);
    const parts = envelope.split(':');
    expect(parts).toHaveLength(5);
    for (const part of parts.slice(1)) {
      expect(part.length).toBeGreaterThan(0);
    }
    // iv is 12 bytes, GCM tag is 16 bytes.
    expect(Buffer.from(parts[1], 'base64')).toHaveLength(12);
    expect(Buffer.from(parts[2], 'base64')).toHaveLength(16);
    // 5th part is the wrapped DEK: iv(12) + tag(16) + dek(32) under software KEK.
    expect(Buffer.from(parts[4], 'base64')).toHaveLength(12 + 16 + 32);

    await expect(decryptToken(envelope)).resolves.toBe(plaintext);
  });

  it('produces a fresh envelope per call (random DEK/IV) that still decrypts', async () => {
    const { encryptToken, decryptToken } = loadTokenCrypto();
    const a = await encryptToken('same-input');
    const b = await encryptToken('same-input');
    expect(a).not.toBe(b);
    await expect(decryptToken(a)).resolves.toBe('same-input');
    await expect(decryptToken(b)).resolves.toBe('same-input');
  });

  it('passes empty strings through and never double-encrypts an envelope', async () => {
    const { encryptToken } = loadTokenCrypto();
    await expect(encryptToken('')).resolves.toBe('');
    const envelope = await encryptToken('tok');
    await expect(encryptToken(envelope)).resolves.toBe(envelope);
  });

  it('rejects a key that does not decode to 32 bytes at module load', () => {
    process.env.POSTIZ_TOKEN_ENCRYPTION_KEY = Buffer.alloc(16, 1).toString(
      'base64'
    );
    expect(() => loadTokenCrypto()).toThrow(
      /must decode to 32 bytes \(got 16\)/
    );
  });
});

// ---------------------------------------------------------------------------
// (ii) Malformed input behavior
// ---------------------------------------------------------------------------

describe('malformed / non-envelope input', () => {
  beforeEach(() => {
    process.env.POSTIZ_TOKEN_ENCRYPTION_KEY = SOFTWARE_KEY_B64;
  });

  it('passes non-v1-prefixed values through unchanged (legacy plaintext rows)', async () => {
    const { decryptToken } = loadTokenCrypto();
    await expect(decryptToken('legacy-plaintext-token')).resolves.toBe(
      'legacy-plaintext-token'
    );
    await expect(decryptToken('v2:not:a:known:envelope')).resolves.toBe(
      'v2:not:a:known:envelope'
    );
    await expect(decryptToken('')).resolves.toBe('');
  });

  it('rejects a v1 envelope with too few parts', async () => {
    const { decryptToken } = loadTokenCrypto();
    await expect(decryptToken('v1:only:three')).rejects.toThrow(
      'Malformed token ciphertext envelope'
    );
  });

  it('accepts the legacy 6-part envelope (v1:: join-bug format)', async () => {
    const { encryptToken, decryptToken } = loadTokenCrypto();
    const canonical = await encryptToken('legacy-round-trip');
    // The pre-fix encrypt() joined ENVELOPE_PREFIX ("v1:") with ':' producing
    // an empty 2nd segment; rows written that way must still decrypt.
    const legacy = canonical.replace(/^v1:/, 'v1::');
    expect(legacy.split(':')).toHaveLength(6);
    await expect(decryptToken(legacy)).resolves.toBe('legacy-round-trip');
  });

  it('rejects a v1 envelope with too many parts', async () => {
    const { decryptToken } = loadTokenCrypto();
    await expect(decryptToken('v1:a:b:c:d:e')).rejects.toThrow(
      'Malformed token ciphertext envelope'
    );
  });

  it('rejects a v1 envelope with empty segments', async () => {
    const { decryptToken } = loadTokenCrypto();
    await expect(decryptToken('v1::::')).rejects.toThrow(
      'Malformed token ciphertext envelope'
    );
  });

  it('rejects a tampered ciphertext (GCM auth failure)', async () => {
    const { encryptToken, decryptToken } = loadTokenCrypto();
    const parts = (await encryptToken('tamper-me')).split(':');
    const ctLen = Buffer.from(parts[3], 'base64').length;
    parts[3] = Buffer.alloc(ctLen, 0x5a).toString('base64'); // forged ct
    await expect(decryptToken(parts.join(':'))).rejects.toThrow();
  });

  it('passes even v1-prefixed values through when encryption is disabled', async () => {
    delete process.env.POSTIZ_TOKEN_ENCRYPTION_KEY;
    const { decryptToken } = loadTokenCrypto();
    await expect(decryptToken('v1:a:b:c:d')).resolves.toBe('v1:a:b:c:d');
  });
});

// ---------------------------------------------------------------------------
// (iii) Plaintext fallback (no key configured)
// ---------------------------------------------------------------------------

describe('plaintext fallback (no key configured)', () => {
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  it('reports encryption as disabled', () => {
    const { isTokenEncryptionEnabled } = loadTokenCrypto();
    expect(isTokenEncryptionEnabled()).toBe(false);
  });

  it('returns input unchanged and warns exactly once across writes', async () => {
    const { encryptToken, decryptToken } = loadTokenCrypto();

    await expect(encryptToken('first-token')).resolves.toBe('first-token');
    await expect(encryptToken('second-token')).resolves.toBe('second-token');
    await expect(decryptToken('first-token')).resolves.toBe('first-token');

    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0][0]).toContain('stored in plaintext');
  });
});

// ---------------------------------------------------------------------------
// (iv) KMS mode with mocked @google-cloud/kms
// ---------------------------------------------------------------------------

describe('KMS mode (POSTIZ_KMS_KEY_RESOURCE, mocked client)', () => {
  beforeEach(() => {
    process.env.POSTIZ_KMS_KEY_RESOURCE = KMS_RESOURCE;
    installKmsMockImplementations();
  });

  it('round-trips a token with a KMS-wrapped DEK', async () => {
    const { encryptToken, decryptToken } = loadTokenCrypto();
    const plaintext = 'kms-protected-token';

    const envelope = await encryptToken(plaintext);
    const parts = envelope.split(':');
    expect(parts).toHaveLength(5);
    expect(parts[0]).toBe('v1');

    // Wrapped DEK is non-empty: mock wrap = prefix + 32-byte DEK.
    const wrappedDek = Buffer.from(parts[4], 'base64');
    expect(wrappedDek.length).toBe(KMS_WRAP_PREFIX.length + 32);

    await expect(decryptToken(envelope)).resolves.toBe(plaintext);

    // Tuple-style client called with the configured key resource.
    expect(mockKmsEncrypt).toHaveBeenCalledTimes(1);
    const encryptArg = mockKmsEncrypt.mock.calls[0][0];
    expect(encryptArg.name).toBe(KMS_RESOURCE);
    expect(Buffer.isBuffer(encryptArg.plaintext)).toBe(true);
    expect(encryptArg.plaintext).toHaveLength(32); // only the DEK goes to KMS
    expect(mockKmsDecrypt).toHaveBeenCalledTimes(1);
    expect(mockKmsDecrypt.mock.calls[0][0].name).toBe(KMS_RESOURCE);
  });

  it('takes precedence over the software key when both are configured', async () => {
    process.env.POSTIZ_TOKEN_ENCRYPTION_KEY = SOFTWARE_KEY_B64;
    const { encryptToken, decryptToken } = loadTokenCrypto();
    const envelope = await encryptToken('both-configured');
    expect(mockKmsEncrypt).toHaveBeenCalledTimes(1);
    await expect(decryptToken(envelope)).resolves.toBe('both-configured');
  });

  it('accepts base64-string payloads in KMS responses (tuple response, string field)', async () => {
    mockKmsEncrypt.mockImplementation(
      async ({ plaintext }: { plaintext: Buffer }) => [
        {
          ciphertext: Buffer.concat([KMS_WRAP_PREFIX, plaintext]).toString(
            'base64'
          ),
        },
        undefined,
        undefined,
      ]
    );
    mockKmsDecrypt.mockImplementation(
      async ({ ciphertext }: { ciphertext: Buffer }) => [
        {
          plaintext: Buffer.from(ciphertext)
            .subarray(KMS_WRAP_PREFIX.length)
            .toString('base64'),
        },
        undefined,
        undefined,
      ]
    );
    const { encryptToken, decryptToken } = loadTokenCrypto();
    const envelope = await encryptToken('string-response-token');
    await expect(decryptToken(envelope)).resolves.toBe('string-response-token');
  });

  it('surfaces empty KMS encrypt responses as TokenCryptoError', async () => {
    mockKmsEncrypt.mockImplementation(async () => [{}, undefined, undefined]);
    const { encryptToken } = loadTokenCrypto();
    await expect(encryptToken('doomed')).rejects.toThrow(
      'KMS encrypt returned empty ciphertext'
    );
  });

  it('reuses one lazily-created KMS client across calls', async () => {
    const { encryptToken } = loadTokenCrypto();
    await encryptToken('one');
    await encryptToken('two');
    expect(mockKmsEncrypt).toHaveBeenCalledTimes(2);
  });
});

// ---------------------------------------------------------------------------
// (v) decryptIntegrationTokens (prisma.service.ts read-path walk)
// ---------------------------------------------------------------------------

describe('decryptIntegrationTokens (prisma.service.ts)', () => {
  beforeEach(() => {
    process.env.POSTIZ_TOKEN_ENCRYPTION_KEY = SOFTWARE_KEY_B64;
  });

  async function encryptedIntegration(
    tc: TokenCryptoModule,
    id: string
  ): Promise<Record<string, unknown>> {
    return {
      id,
      providerIdentifier: 'x',
      name: `account-${id}`,
      token: await tc.encryptToken(`token-${id}`),
      refreshToken: await tc.encryptToken(`refresh-${id}`),
    };
  }

  it('decrypts a top-level Integration-shaped object', async () => {
    const { tc, ps } = loadWithPrismaService();
    const row = await encryptedIntegration(tc, 'i1');

    const out = (await ps.decryptIntegrationTokens(row)) as Record<
      string,
      unknown
    >;

    expect(out.token).toBe('token-i1');
    expect(out.refreshToken).toBe('refresh-i1');
    expect(out.id).toBe('i1');
    expect(out.name).toBe('account-i1');
    expect(out.providerIdentifier).toBe('x');
  });

  it('decrypts every element of an array result', async () => {
    const { tc, ps } = loadWithPrismaService();
    const rows = [
      await encryptedIntegration(tc, 'a'),
      await encryptedIntegration(tc, 'b'),
    ];

    const out = (await ps.decryptIntegrationTokens(rows)) as Array<
      Record<string, unknown>
    >;

    expect(out).toHaveLength(2);
    expect(out[0].token).toBe('token-a');
    expect(out[1].token).toBe('token-b');
    expect(out[1].refreshToken).toBe('refresh-b');
  });

  it('decrypts an integration nested under an included relation', async () => {
    const { tc, ps } = loadWithPrismaService();
    const post = {
      id: 'post1',
      content: 'hello world',
      integration: await encryptedIntegration(tc, 'nested'),
    };

    const out = (await ps.decryptIntegrationTokens(post)) as {
      id: string;
      content: string;
      integration: Record<string, unknown>;
    };

    expect(out.id).toBe('post1');
    expect(out.content).toBe('hello world');
    expect(out.integration.token).toBe('token-nested');
    expect(out.integration.refreshToken).toBe('refresh-nested');
  });

  it('preserves a null refreshToken on an Integration-shaped object', async () => {
    const { tc, ps } = loadWithPrismaService();
    const row = {
      id: 'i2',
      providerIdentifier: 'y',
      token: await tc.encryptToken('token-i2'),
      refreshToken: null as string | null,
    };

    const out = (await ps.decryptIntegrationTokens(row)) as Record<
      string,
      unknown
    >;

    expect(out.token).toBe('token-i2');
    expect(out.refreshToken).toBeNull();
  });

  it('leaves non-Integration objects and primitives untouched', async () => {
    const { tc, ps } = loadWithPrismaService();

    // token present but no providerIdentifier -> NOT Integration-shaped, so the
    // (undecryptable-as-is) string stays exactly as stored.
    const stored = await tc.encryptToken('not-walked');
    const notIntegration = { id: 'u1', token: stored };
    const outNotIntegration = (await ps.decryptIntegrationTokens(
      notIntegration
    )) as Record<string, unknown>;
    expect(outNotIntegration.token).toBe(stored);

    // Plain object without token fields is structurally unchanged.
    const user = { id: 'u2', email: 'user@example.com', posts: [{ id: 'p1' }] };
    await expect(ps.decryptIntegrationTokens(user)).resolves.toEqual(user);

    // Primitives and nullish values pass through.
    await expect(ps.decryptIntegrationTokens('just-a-string')).resolves.toBe(
      'just-a-string'
    );
    await expect(ps.decryptIntegrationTokens(42)).resolves.toBe(42);
    await expect(ps.decryptIntegrationTokens(null)).resolves.toBeNull();
    await expect(
      ps.decryptIntegrationTokens(undefined)
    ).resolves.toBeUndefined();
  });
});
