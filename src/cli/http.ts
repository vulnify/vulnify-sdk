export const UNSUPPORTED_MESSAGE = 'This Vulnify server does not support policies as code yet';

export class CliError extends Error {
  constructor(
    message: string,
    readonly exitCode: number,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = 'CliError';
  }
}

export function unsupportedError(): CliError {
  return new CliError(UNSUPPORTED_MESSAGE, 4);
}

export function authError(message: string, details?: unknown): CliError {
  return new CliError(message, 5, details);
}

async function readBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return { message: text };
  }
}

/**
 * Calls the API. 404 becomes the policies-as-code unsupported error (exit 4).
 * 401 and 403 are auth errors (exit 5).
 */
export async function apiRequest(method: string, url: string, apiKey: string, body?: unknown): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${apiKey}`,
        Accept: 'application/json',
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(20_000),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'network error';
    throw new CliError(`Vulnify could not be reached (${message})`, 1);
  }
  const parsed = await readBody(res);
  if (res.status === 404) throw unsupportedError();
  if (res.status === 401 || res.status === 403) {
    const message = messageOf(parsed) || `Vulnify rejected the API key (${res.status})`;
    throw authError(message, parsed);
  }
  if (!res.ok) throw new CliError(formatApiError(res.status, parsed), 1, parsed);
  return parsed;
}

export function formatApiError(status: number, body: unknown): string {
  if (isRecord(body) && isRecord(body.fields)) {
    const lines = Object.entries(body.fields).map(([key, value]) => `${key}: ${typeof value === 'string' ? value : JSON.stringify(value)}`);
    if (lines.length) return lines.join('\n');
  }
  return messageOf(body) || `Vulnify responded ${status}`;
}

export function messageOf(body: unknown): string {
  if (!body || typeof body !== 'object') return '';
  const record = body as { message?: unknown; error?: unknown };
  if (typeof record.message === 'string' && record.message) return record.message;
  if (typeof record.error === 'string' && record.error) return record.error;
  return '';
}

/** Login probe. A 401 means the key was rejected. 404 on a missing event means the key was accepted. */
export async function probeApiKey(baseUrl: string, apiKey: string): Promise<void> {
  const url = `${baseUrl}/v1/events/00000000-0000-4000-8000-000000000000`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: 'GET',
      headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/json' },
      signal: AbortSignal.timeout(15_000),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'network error';
    throw new CliError(`Vulnify could not be reached (${message})`, 1);
  }
  const body = await readBody(res);
  const message = messageOf(body);
  if (res.status === 401) throw authError(message || 'Invalid API key', body);
  if (/^Cannot (GET|POST|PUT|PATCH|DELETE)\b/.test(message)) {
    throw new CliError(`This base URL has no decision API (${baseUrl})`, 1, body);
  }
  if (res.status === 200 || res.status === 403 || res.status === 404) return;
  throw new CliError(message || `Vulnify responded ${res.status}`, res.status === 401 ? 5 : 1, body);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

