import Ajv, { type ErrorObject } from 'ajv/dist/2020';
import { existsSync, readFileSync, readdirSync, statSync } from 'fs';
import { dirname, join, relative } from 'path';
import { parseAllDocuments, type Document, type Node } from 'yaml';

export interface LoadedDoc {
  file: string;
  /** 1-based line of the document start inside the file. */
  line: number;
  kind: string;
  data: Record<string, unknown>;
  doc: Document;
  text: string;
}

export interface SchemaError {
  file: string;
  line: number;
  message: string;
}

let validator: { validate: (schemaId: string, data: unknown) => boolean; errors?: ErrorObject[] | null } | null = null;
let schemaId = '';

export function schemaPath(): string {
  let dir = __dirname;
  for (let i = 0; i < 6; i++) {
    const candidate = join(dir, 'schema', 'policies.v1.json');
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('schema/policies.v1.json was not found next to the package');
}

function ajv(): NonNullable<typeof validator> {
  if (validator) return validator;
  const raw = JSON.parse(readFileSync(schemaPath(), 'utf8')) as { $id?: string };
  schemaId = raw.$id ?? 'https://docs.vulnify.io/schemas/policies.v1.json';
  const instance = new Ajv({ allErrors: true, strict: false });
  instance.addSchema(raw);
  validator = instance;
  return instance;
}

export function listYamlFiles(root: string): string[] {
  if (!existsSync(root)) return [];
  const stat = statSync(root);
  if (stat.isFile()) return [root];
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const ent of readdirSync(dir, { withFileTypes: true })) {
      if (ent.name === 'node_modules' || ent.name.startsWith('.')) continue;
      const path = join(dir, ent.name);
      if (ent.isDirectory()) walk(path);
      else if (/\.ya?ml$/i.test(ent.name)) out.push(path);
    }
  };
  walk(root);
  return out.sort();
}

function lineAt(text: string, offset: number): number {
  let line = 1;
  const end = Math.max(0, Math.min(offset, text.length));
  for (let i = 0; i < end; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function pointerToPath(pointer: string, extra?: string): (string | number)[] {
  const parts = pointer
    ? pointer
        .split('/')
        .slice(1)
        .map((seg) => seg.replace(/~1/g, '/').replace(/~0/g, '~'))
    : [];
  if (extra) parts.push(extra);
  return parts.map((seg) => (/^\d+$/.test(seg) ? Number(seg) : seg));
}

function nodeLine(text: string, doc: Document, path: (string | number)[]): number {
  const start = doc.range?.[0] ?? 0;
  let node: Node | undefined;
  for (let i = path.length; i >= 0; i--) {
    const found = doc.getIn(path.slice(0, i), true);
    if (found && typeof found === 'object' && 'range' in found && Array.isArray((found as Node).range)) {
      node = found as Node;
      break;
    }
  }
  const offset = node?.range?.[0] ?? start;
  return lineAt(text, offset);
}

function formatAjv(err: ErrorObject): { message: string; extra?: string } {
  const additional = err.params && typeof err.params === 'object' && 'additionalProperty' in err.params
    ? String((err.params as { additionalProperty: unknown }).additionalProperty)
    : undefined;
  const path = err.instancePath || '/';
  const where = additional ? `${path}/${additional}` : path;
  return { message: `${where} ${err.message ?? 'is invalid'}`, extra: additional };
}

export function loadDocuments(file: string): { docs: LoadedDoc[]; errors: SchemaError[] } {
  const text = readFileSync(file, 'utf8');
  const parsed = parseAllDocuments(text);
  const docs: LoadedDoc[] = [];
  const errors: SchemaError[] = [];
  parsed.forEach((doc, index) => {
    const start = doc.range?.[0] ?? 0;
    const line = lineAt(text, start);
    for (const err of doc.errors) {
      const pos = err.linePos?.[0];
      errors.push({
        file,
        line: pos?.line ?? line,
        message: err.message,
      });
    }
    if (doc.errors.length) return;
    const data = doc.toJS({ maxAliasCount: 0 });
    if (data == null) return;
    if (typeof data !== 'object' || Array.isArray(data)) {
      errors.push({ file, line, message: `document ${index + 1} must be a mapping` });
      return;
    }
    const record = data as Record<string, unknown>;
    docs.push({ file, line, kind: typeof record.kind === 'string' ? record.kind : '', data: record, doc, text });
  });
  return { docs, errors };
}

export function validateDocument(loaded: LoadedDoc, schemaRef: '#/$defs/policyDocument' | '#/$defs/policyTestDocument'): SchemaError[] {
  const instance = ajv();
  const id = `${schemaId}${schemaRef}`;
  const ok = instance.validate(id, loaded.data);
  if (ok) return [];
  return (instance.errors ?? []).map((err) => {
    const formatted = formatAjv(err);
    const path = pointerToPath(err.instancePath || '', formatted.extra);
    return { file: loaded.file, line: nodeLine(loaded.text, loaded.doc, path), message: formatted.message };
  });
}

export function formatSchemaError(err: SchemaError, cwd: string): string {
  const file = relative(cwd, err.file) || err.file;
  return `${file}:${err.line}: ${err.message}`;
}

export function policyName(data: Record<string, unknown>): string {
  const metadata = data.metadata;
  if (!metadata || typeof metadata !== 'object') return '';
  const name = (metadata as { name?: unknown }).name;
  return typeof name === 'string' ? name : '';
}

const SPEC_KEYS = ['description', 'enabled', 'action', 'resource', 'condition', 'decision', 'mode', 'approverRoles'] as const;

/** PolicySpec sent to the API. metadata.name becomes name. id and updatedAt are not sent. */
export function toPolicySpec(data: Record<string, unknown>): Record<string, unknown> {
  const spec = (data.spec && typeof data.spec === 'object' ? data.spec : {}) as Record<string, unknown>;
  const out: Record<string, unknown> = { name: policyName(data) };
  for (const key of SPEC_KEYS) {
    if (spec[key] !== undefined) out[key] = spec[key];
  }
  return out;
}

export function toTestCase(data: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { name: data.name, input: data.input };
  if (data.expect !== undefined) out.expect = data.expect;
  return out;
}
