import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { encryptToken, decryptToken } from './token-crypto';

/**
 * Thin-fork patch #1 — decrypt integration tokens after reads.
 * Recursively walks result trees so included relations are also decrypted.
 */
async function decryptIntegrationTokens(value: unknown): Promise<unknown> {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) {
    return Promise.all(value.map((v) => decryptIntegrationTokens(v)));
  }
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    // Integration-shaped object: has token (string) and providerIdentifier (string).
    if (typeof record.token === 'string' && typeof record.providerIdentifier === 'string') {
      const [token, refreshToken] = await Promise.all([
        decryptToken(record.token),
        typeof record.refreshToken === 'string' ? decryptToken(record.refreshToken) : record.refreshToken,
      ]);
      return { ...record, token, refreshToken };
    }
    // Otherwise recurse into plain objects (e.g. nested includes).
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(record)) {
      out[k] = await decryptIntegrationTokens(v);
    }
    return out;
  }
  return value;
}

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  constructor() {
    super({
      log: [
        {
          emit: 'event',
          level: 'query',
        },
      ],
    });

    this.$use(async (params, next) => {
      // Only intercept integration model operations.
      if (params.model !== 'Integration') {
        return next(params);
      }

      const writeActions = new Set([
        'create',
        'update',
        'upsert',
        'updateMany',
        'createMany',
      ]);

      if (writeActions.has(params.action)) {
        const data = params.args?.data;
        if (data) {
          // createMany carries an array of records.
          if (Array.isArray(data)) {
            for (const row of data) {
              if (typeof row.token === 'string') {
                row.token = await encryptToken(row.token);
              }
              if (typeof row.refreshToken === 'string') {
                row.refreshToken = await encryptToken(row.refreshToken);
              }
            }
          } else {
            if (typeof data.token === 'string') {
              data.token = await encryptToken(data.token);
            }
            if (typeof data.refreshToken === 'string') {
              data.refreshToken = await encryptToken(data.refreshToken);
            }
            // upsert has nested create/update payloads.
            if (data.create) {
              if (typeof data.create.token === 'string') {
                data.create.token = await encryptToken(data.create.token);
              }
              if (typeof data.create.refreshToken === 'string') {
                data.create.refreshToken = await encryptToken(data.create.refreshToken);
              }
            }
            if (data.update) {
              if (typeof data.update.token === 'string') {
                data.update.token = await encryptToken(data.update.token);
              }
              if (typeof data.update.refreshToken === 'string') {
                data.update.refreshToken = await encryptToken(data.update.refreshToken);
              }
            }
          }
        }
      }

      const result = await next(params);

      const readActions = new Set([
        'findUnique',
        'findFirst',
        'findMany',
        'findUniqueOrThrow',
        'findFirstOrThrow',
        'upsert',
        'create',
        'update',
      ]);

      if (readActions.has(params.action) && result !== null && result !== undefined) {
        if (Array.isArray(result)) {
          return Promise.all(result.map(async (r) => decryptIntegrationTokens(r)));
        }
        return decryptIntegrationTokens(result);
      }

      return result;
    });
  }
  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}

@Injectable()
export class PrismaRepository<T extends keyof PrismaService> {
  public model: Pick<PrismaService, T>;
  constructor(private _prismaService: PrismaService) {
    this.model = this._prismaService;
  }
}

@Injectable()
export class PrismaTransaction {
  public model: Pick<PrismaService, '$transaction'>;
  constructor(private _prismaService: PrismaService) {
    this.model = this._prismaService;
  }
}
