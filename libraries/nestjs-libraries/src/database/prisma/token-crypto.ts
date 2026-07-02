/**
 * Postiz thin-fork patch #1 — field-level AES-GCM encryption for integration tokens.
 *
 * Platform OAuth tokens (Integration.token + Integration.refreshToken) are encrypted at rest
 * using a key from env:
 *   - POSTIZ_TOKEN_ENCRYPTION_KEY — base64-encoded 32-byte AES key (dev/test/self-host).
 *   - POSTIZ_KMS_KEY_RESOURCE — GCP Cloud KMS symmetric key resource name (prod).
 *
 * If neither is configured the middleware passes plaintext through (dev fallback) and logs a
 * warning on first write. Ciphertext envelope (5 parts):
 *   v1:<iv_b64>:<tag_b64>:<ct_b64>:<wrapped_dek_b64>
 * where <wrapped_dek_b64> is the random per-record 32-byte DEK wrapped by the configured KEK
 * (GCP Cloud KMS when POSTIZ_KMS_KEY_RESOURCE is set, otherwise the software KEK from
 * POSTIZ_TOKEN_ENCRYPTION_KEY).
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;
const TAG_BYTES = 16;
const ENVELOPE_PREFIX = 'v1:';

export class TokenCryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TokenCryptoError';
  }
}

interface KmsClientLike {
  encrypt(request: { name: string; plaintext: Buffer }): Promise<[EncryptResponse, unknown, unknown]>;
  decrypt(request: { name: string; ciphertext: Buffer }): Promise<[DecryptResponse, unknown, unknown]>;
}

interface EncryptResponse {
  ciphertext?: Uint8Array | string | null;
}

interface DecryptResponse {
  plaintext?: Uint8Array | string | null;
}

function toBuffer(value: Uint8Array | string): Buffer {
  return typeof value === 'string' ? Buffer.from(value, 'base64') : Buffer.from(value);
}

class TokenCrypto {
  private kmsClient?: KmsClientLike;
  private softwareKey?: Buffer;
  private kmsResource?: string;
  private warnedPlaintext = false;

  constructor() {
    const kmsResource = process.env.POSTIZ_KMS_KEY_RESOURCE;
    const softwareKeyB64 = process.env.POSTIZ_TOKEN_ENCRYPTION_KEY;

    if (kmsResource) {
      this.kmsResource = kmsResource;
    } else if (softwareKeyB64) {
      const key = Buffer.from(softwareKeyB64, 'base64');
      if (key.length !== 32) {
        throw new TokenCryptoError(
          `POSTIZ_TOKEN_ENCRYPTION_KEY must decode to 32 bytes (got ${key.length})`
        );
      }
      this.softwareKey = key;
    }
  }

  get enabled(): boolean {
    return this.kmsResource !== undefined || this.softwareKey !== undefined;
  }

  private async getKmsClient(): Promise<KmsClientLike> {
    if (this.kmsClient) return this.kmsClient;
    const mod = await import('@google-cloud/kms');
    this.kmsClient = new mod.KeyManagementServiceClient();
    return this.kmsClient;
  }

  private async encryptKey(plaintext: Buffer): Promise<Buffer> {
    if (this.kmsResource) {
      const client = await this.getKmsClient();
      const [res] = await client.encrypt({ name: this.kmsResource, plaintext });
      if (!res?.ciphertext) throw new TokenCryptoError('KMS encrypt returned empty ciphertext');
      return toBuffer(res.ciphertext);
    }
    if (this.softwareKey) {
      const iv = randomBytes(IV_BYTES);
      const cipher = createCipheriv(ALGORITHM, this.softwareKey, iv);
      const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const tag = cipher.getAuthTag();
      return Buffer.concat([iv, tag, ct]);
    }
    throw new TokenCryptoError('Token encryption is disabled but encryptKey was called');
  }

  private async decryptKey(ciphertext: Buffer): Promise<Buffer> {
    if (this.kmsResource) {
      const client = await this.getKmsClient();
      const [res] = await client.decrypt({ name: this.kmsResource, ciphertext });
      if (!res?.plaintext) throw new TokenCryptoError('KMS decrypt returned empty plaintext');
      return toBuffer(res.plaintext);
    }
    if (this.softwareKey) {
      if (ciphertext.length <= IV_BYTES + TAG_BYTES) {
        throw new TokenCryptoError('Malformed encrypted data key');
      }
      const iv = ciphertext.subarray(0, IV_BYTES);
      const tag = ciphertext.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
      const ct = ciphertext.subarray(IV_BYTES + TAG_BYTES);
      const decipher = createDecipheriv(ALGORITHM, this.softwareKey, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ct), decipher.final()]);
    }
    throw new TokenCryptoError('Token encryption is disabled but decryptKey was called');
  }

  /**
   * Per-record envelope encryption: a random 32-byte DEK seals the payload, then the DEK is
   * wrapped by the configured KEK. This bounds KMS calls to 32 bytes and supports rotation.
   */
  async encrypt(plaintext: string): Promise<string> {
    if (!this.enabled) {
      if (!this.warnedPlaintext) {
        console.warn(
          '[token-crypto] Neither POSTIZ_KMS_KEY_RESOURCE nor POSTIZ_TOKEN_ENCRYPTION_KEY is set. ' +
            'Integration tokens are stored in plaintext. This is only acceptable in dev/test.'
        );
        this.warnedPlaintext = true;
      }
      return plaintext;
    }
    if (plaintext === '' || plaintext.startsWith(ENVELOPE_PREFIX)) {
      return plaintext;
    }
    const dek = randomBytes(32);
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv(ALGORITHM, dek, iv);
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    const wrappedDek = await this.encryptKey(dek);
    // ENVELOPE_PREFIX already ends with ':' — concatenate, don't join, or the
    // envelope gains an empty segment (v1::...) that decrypt() rejects.
    return (
      ENVELOPE_PREFIX +
      [
        iv.toString('base64'),
        tag.toString('base64'),
        ct.toString('base64'),
        wrappedDek.toString('base64'),
      ].join(':')
    );
  }

  async decrypt(envelope: string): Promise<string> {
    if (!this.enabled || envelope === '' || !envelope.startsWith(ENVELOPE_PREFIX)) {
      return envelope;
    }
    const parts = envelope.split(':');
    // Canonical: v1:<iv>:<tag>:<ct>:<wrappedDek> (5 parts). Also accept the
    // legacy 6-part form v1::<iv>:<tag>:<ct>:<wrappedDek> written by a former
    // encrypt() join bug (empty 2nd segment).
    let ivB64: string | undefined;
    let tagB64: string | undefined;
    let ctB64: string | undefined;
    let wrappedDekB64: string | undefined;
    if (parts.length === 5) {
      [, ivB64, tagB64, ctB64, wrappedDekB64] = parts;
    } else if (parts.length === 6 && parts[1] === '') {
      [, , ivB64, tagB64, ctB64, wrappedDekB64] = parts;
    } else {
      throw new TokenCryptoError('Malformed token ciphertext envelope');
    }
    if (!ivB64 || !tagB64 || !ctB64 || !wrappedDekB64) {
      throw new TokenCryptoError('Malformed token ciphertext envelope');
    }
    const wrappedDek = Buffer.from(wrappedDekB64, 'base64');
    const dek = await this.decryptKey(wrappedDek);
    const iv = Buffer.from(ivB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const ct = Buffer.from(ctB64, 'base64');
    const decipher = createDecipheriv(ALGORITHM, dek, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  }
}

const tokenCrypto = new TokenCrypto();

/** Encrypt a plaintext token value for DB storage. */
export async function encryptToken(plaintext: string): Promise<string> {
  return tokenCrypto.encrypt(plaintext);
}

/** Decrypt a DB-stored token value to plaintext. */
export async function decryptToken(envelope: string): Promise<string> {
  return tokenCrypto.decrypt(envelope);
}

/** True when token encryption is configured. */
export function isTokenEncryptionEnabled(): boolean {
  return tokenCrypto.enabled;
}
