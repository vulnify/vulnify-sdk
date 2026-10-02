import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

export const DEFAULT_BASE_URL = 'https://api.vulnify.io';

export interface Credentials {
  apiKey?: string;
  baseUrl?: string;
}

export function credentialsPath(home = homedir()): string {
  return join(home, '.config', 'vulnify', 'credentials.json');
}

export function readCredentials(home = homedir()): Credentials {
  const file = credentialsPath(home);
  if (!existsSync(file)) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    throw new Error(`Could not read ${file}`);
  }
  if (!parsed || typeof parsed !== 'object') throw new Error(`Could not read ${file}`);
  const body = parsed as Record<string, unknown>;
  return {
    apiKey: typeof body.apiKey === 'string' ? body.apiKey : undefined,
    baseUrl: typeof body.baseUrl === 'string' ? body.baseUrl : undefined,
  };
}

/** Env vars win over the file. The file wins over the default base URL. */
export function resolveConfig(env: NodeJS.ProcessEnv, home = homedir()): { apiKey?: string; baseUrl: string } {
  const file = readCredentials(home);
  const apiKey = env.VULNIFY_API_KEY || file.apiKey;
  const baseUrl = (env.VULNIFY_BASE_URL || file.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
  return { apiKey, baseUrl };
}

export function writeCredentials(home: string, creds: { apiKey: string; baseUrl: string }): string {
  const file = credentialsPath(home);
  const dir = join(home, '.config', 'vulnify');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  writeFileSync(file, `${JSON.stringify({ apiKey: creds.apiKey, baseUrl: creds.baseUrl }, null, 2)}\n`, { mode: 0o600 });
  chmodSync(file, 0o600);
  return file;
}
