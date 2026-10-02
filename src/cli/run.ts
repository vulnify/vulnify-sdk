import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { homedir } from 'os';
import { dirname, join, relative, resolve } from 'path';
import { stringify } from 'yaml';
import { Vulnify } from '../index';
import type { AgentAction, Decision } from '../index';
import { readCredentials, resolveConfig, writeCredentials, DEFAULT_BASE_URL } from './credentials';
import {
  formatSchemaError,
  listYamlFiles,
  loadDocuments,
  policyName,
  schemaPath,
  toPolicySpec,
  toTestCase,
  validateDocument,
  type LoadedDoc,
  type SchemaError,
} from './documents';
import { CliError, apiRequest, authError, isRecord, probeApiKey, UNSUPPORTED_MESSAGE } from './http';
import { EXAMPLE_POLICY_YAML, EXAMPLE_TEST_YAML, GITIGNORE_HINT, GITIGNORE_STDOUT } from './templates';

export interface RunIO {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  homedir?: string;
  stdout?: (chunk: string) => void;
  stderr?: (chunk: string) => void;
  fetch?: typeof fetch;
}

const VALUE_FLAGS = new Set(['api-key', 'base-url', 'agent', 'action', 'resource', 'destination', 'records', 'out']);
const BOOL_FLAGS = new Set(['prune', 'dry-run', 'local', 'sensitive', 'version']);
const EVENT_ACTIONS = new Set(['READ_DATA', 'WRITE_DATA', 'DELETE_DATA', 'EXPORT_DATA', 'SEND_EMAIL']);
const DESTINATIONS = new Set(['INTERNAL', 'EXTERNAL_EMAIL', 'EXTERNAL_API']);

interface Flags {
  [key: string]: string | boolean | undefined;
  'api-key'?: string;
  'base-url'?: string;
  agent?: string;
  action?: string;
  resource?: string;
  destination?: string;
  records?: string;
  out?: string;
  prune?: boolean;
  'dry-run'?: boolean;
  local?: boolean;
  sensitive?: boolean;
  version?: boolean;
}

interface Parsed {
  json: boolean;
  help: boolean;
  positionals: string[];
  flags: Flags;
}

function parseArgv(argv: string[]): Parsed {
  const flags: Flags = {};
  const positionals: string[] = [];
  let json = false;
  let help = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--') {
      positionals.push(...argv.slice(i + 1));
      break;
    }
    if (arg === '--json') {
      json = true;
      continue;
    }
    if (arg === '--help' || arg === '-h') {
      help = true;
      continue;
    }
    if (!arg.startsWith('--')) {
      positionals.push(arg);
      continue;
    }
    const eq = arg.indexOf('=');
    const name = eq === -1 ? arg.slice(2) : arg.slice(2, eq);
    if (VALUE_FLAGS.has(name)) {
      const value = eq === -1 ? argv[++i] : arg.slice(eq + 1);
      if (value === undefined || value.startsWith('--')) throw new CliError(`Missing value for --${name}`, 1);
      flags[name] = value;
      continue;
    }
    if (BOOL_FLAGS.has(name)) {
      if (eq !== -1) throw new CliError(`--${name} does not take a value`, 1);
      flags[name] = true;
      continue;
    }
    throw new CliError(`Unknown flag --${name}`, 1);
  }
  return { json, help, positionals, flags };
}

const HELP = `vulnify — policies as code and one-off decisions

Usage:
  vulnify init
  vulnify login [--api-key <key>] [--base-url <url>]
  vulnify check --agent <name> --action <action> --resource <name> [--destination <dest>] [--records <n>] [--sensitive]
  vulnify policies validate [path]
  vulnify policies pull [--out <dir>]
  vulnify policies apply [path] [--prune] [--dry-run]
  vulnify test [path] [--local]

Every command accepts --json. There is no telemetry.

Credentials:
  ~/.config/vulnify/credentials.json (mode 0600)
  VULNIFY_API_KEY and VULNIFY_BASE_URL take precedence.
  Default base URL: ${DEFAULT_BASE_URL}

Exit codes:
  0  ok, or ALLOW from check
  1  test failure or validation error
  2  REVIEW (check only)
  3  BLOCK (check only)
  4  this server has no policies-as-code API
  5  auth error

policies pull, apply, and test print "${UNSUPPORTED_MESSAGE}" and exit 4 when the server responds 404.
`;

function helpText(): string {
  return HELP;
}

interface Context {
  cwd: string;
  env: NodeJS.ProcessEnv;
  home: string;
  json: boolean;
  stdout: (chunk: string) => void;
  stderr: (chunk: string) => void;
}

function emit(ctx: Context, data: unknown, text: string): void {
  if (ctx.json) ctx.stdout(`${JSON.stringify(data, null, 2)}\n`);
  else ctx.stdout(text.endsWith('\n') ? text : `${text}\n`);
}

function fail(ctx: Context, err: CliError): number {
  const payload = { ok: false, exitCode: err.exitCode, error: err.message, ...(err.details === undefined ? {} : { details: err.details }) };
  emit(ctx, payload, err.message);
  return err.exitCode;
}

function requireKey(ctx: Context): { apiKey: string; baseUrl: string } {
  const config = resolveConfig(ctx.env, ctx.home);
  if (!config.apiKey) throw authError('No API key. Run vulnify login --api-key <key> or set VULNIFY_API_KEY.');
  return { apiKey: config.apiKey, baseUrl: config.baseUrl };
}

function readKind(ctx: Context, path: string, kind: 'Policy' | 'PolicyTest'): LoadedDoc[] {
  const files = listYamlFiles(path);
  if (!files.length) throw new CliError(`No YAML files in ${relative(ctx.cwd, path) || path}`, 1);
  const docs: LoadedDoc[] = [];
  const errors: SchemaError[] = [];
  for (const file of files) {
    const loaded = loadDocuments(file);
    errors.push(...loaded.errors);
    for (const doc of loaded.docs) {
      if (doc.kind !== kind) continue;
      const schemaRef = kind === 'Policy' ? '#/$defs/policyDocument' : '#/$defs/policyTestDocument';
      errors.push(...validateDocument(doc, schemaRef));
      docs.push(doc);
    }
  }
  if (errors.length) {
    throw new CliError(errors.map((err) => formatSchemaError(err, ctx.cwd)).join('\n'), 1, errors);
  }
  if (!docs.length) throw new CliError(`No kind: ${kind} documents in ${relative(ctx.cwd, path) || path}`, 1);
  const names = new Map<string, string>();
  for (const doc of docs) {
    const name = kind === 'Policy' ? policyName(doc.data) : policyName(doc.data);
    if (!name || kind !== 'Policy') continue;
    const prev = names.get(name);
    if (prev) throw new CliError(`Duplicate policy name "${name}" in ${relative(ctx.cwd, prev)} and ${relative(ctx.cwd, doc.file)}`, 1);
    names.set(name, doc.file);
  }
  return docs;
}

function defaultDir(ctx: Context, folder: string): string {
  return join(ctx.cwd, 'vulnify', folder);
}

async function commandInit(ctx: Context): Promise<number> {
  const policyFile = join(ctx.cwd, 'vulnify', 'policies', 'example.yaml');
  const testFile = join(ctx.cwd, 'vulnify', 'tests', 'example.test.yaml');
  const ignoreFile = join(ctx.cwd, 'vulnify', '.gitignore');
  const existing = [policyFile, testFile, ignoreFile].filter((file) => existsSync(file));
  if (existing.length) {
    throw new CliError(`Refusing to overwrite ${existing.map((file) => relative(ctx.cwd, file)).join(', ')}`, 1);
  }
  mkdirSync(dirname(policyFile), { recursive: true });
  mkdirSync(dirname(testFile), { recursive: true });
  writeFileSync(policyFile, EXAMPLE_POLICY_YAML);
  writeFileSync(testFile, EXAMPLE_TEST_YAML);
  writeFileSync(ignoreFile, GITIGNORE_HINT);
  const created = ['vulnify/policies/example.yaml', 'vulnify/tests/example.test.yaml', 'vulnify/.gitignore'];
  emit(ctx, { ok: true, exitCode: 0, created }, `${created.map((file) => `created ${file}`).join('\n')}\n${GITIGNORE_STDOUT}`);
  return 0;
}

async function commandLogin(ctx: Context, flags: Flags): Promise<number> {
  const file = readCredentials(ctx.home);
  const apiKey = flags['api-key'] || ctx.env.VULNIFY_API_KEY;
  if (!apiKey) throw authError('Pass --api-key or set VULNIFY_API_KEY.');
  const baseUrl = (flags['base-url'] || ctx.env.VULNIFY_BASE_URL || file.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
  await probeApiKey(baseUrl, apiKey);
  const path = writeCredentials(ctx.home, { apiKey, baseUrl });
  emit(
    ctx,
    { ok: true, exitCode: 0, baseUrl, credentials: path },
    `Saved credentials to ${path} (mode 0600).\nBase URL: ${baseUrl}\n`,
  );
  return 0;
}

function decisionExit(decision: Decision): number {
  if (decision === 'ALLOW') return 0;
  if (decision === 'REVIEW') return 2;
  return 3;
}

async function commandCheck(ctx: Context, flags: Flags): Promise<number> {
  const { apiKey, baseUrl } = requireKey(ctx);
  const agent = flags.agent;
  const action = flags.action;
  const resource = flags.resource;
  if (!agent || !action || !resource) throw new CliError('check requires --agent, --action, and --resource', 1);
  if (!EVENT_ACTIONS.has(action)) throw new CliError(`Unknown action ${action}`, 1);
  if (flags.destination && !DESTINATIONS.has(flags.destination)) throw new CliError(`Unknown destination ${flags.destination}`, 1);
  let recordsAffected: number | undefined;
  if (flags.records !== undefined) {
    if (!/^\d+$/.test(flags.records)) throw new CliError('--records must be an integer >= 0', 1);
    recordsAffected = Number(flags.records);
  }
  if (flags.sensitive) {
    ctx.stderr('Warning: --sensitive is not sent. POST /v1/events has no sensitive flag.\n');
  }
  if (apiKey.startsWith('vln_live_')) {
    ctx.stderr('Warning: this check uses a LIVE key and records a real event.\n');
  }
  const body: AgentAction = {
    agent,
    action: action as AgentAction['action'],
    resource,
    ...(flags.destination ? { destination: flags.destination as AgentAction['destination'] } : {}),
    ...(recordsAffected === undefined ? {} : { recordsAffected }),
  };
  const client = new Vulnify({ apiKey, baseUrl, retries: 0, timeoutMs: 10_000 });
  try {
    const decision = await client.check(body);
    if (decision.degraded) {
      throw new CliError(decision.reasons.join('; ') || 'Vulnify could not be reached', 1, decision);
    }
    const outcome = decision.finalDecision ?? decision.decision;
    const code = decisionExit(outcome);
    const lines = [
      outcome,
      decision.riskScore == null ? '' : `score ${decision.riskScore}${decision.riskLevel ? ` ${decision.riskLevel}` : ''}`,
      decision.policy ? `policy ${decision.policy.name}` : 'policy none',
      decision.reasons.length ? decision.reasons.join('; ') : '',
    ].filter(Boolean);
    emit(ctx, { ok: code === 0, exitCode: code, ...decision }, `${lines.join('\n')}\n`);
    return code;
  } catch (err) {
    if (err instanceof CliError) throw err;
    const message = err instanceof Error ? err.message : 'check failed';
    const status = /Vulnify request rejected \((401|403)\)/.exec(message);
    if (status) throw authError(message);
    throw new CliError(message, 1);
  }
}

function slug(name: string): string {
  const cleaned = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return cleaned || 'policy';
}

async function commandPull(ctx: Context, flags: Flags): Promise<number> {
  const { apiKey, baseUrl } = requireKey(ctx);
  const outDir = resolve(ctx.cwd, flags.out || defaultDir(ctx, 'policies'));
  const body = await apiRequest('GET', `${baseUrl}/v1/policies`, apiKey);
  if (!isRecord(body) || !Array.isArray(body.policies)) throw new CliError('Unexpected response from GET /v1/policies', 1, body);
  const policies = [...body.policies].sort((a, b) => String(isRecord(a) ? a.name : '').localeCompare(String(isRecord(b) ? b.name : '')));
  mkdirSync(outDir, { recursive: true });
  const written: { name: string; file: string }[] = [];
  const used = new Set<string>();
  for (const policy of policies) {
    if (!isRecord(policy) || typeof policy.name !== 'string') throw new CliError('A policy in the response has no name', 1, policy);
    let fileName = `${slug(policy.name)}.yaml`;
    let n = 2;
    while (used.has(fileName)) {
      fileName = `${slug(policy.name)}-${n}.yaml`;
      n += 1;
    }
    used.add(fileName);
    const spec: Record<string, unknown> = {};
    for (const key of ['description', 'enabled', 'action', 'resource', 'condition', 'decision', 'mode', 'approverRoles']) {
      if (policy[key] !== undefined) spec[key] = policy[key];
    }
    const metadata: Record<string, unknown> = { name: policy.name };
    if (typeof policy.id === 'string') metadata.id = policy.id;
    if (typeof policy.updatedAt === 'string') metadata.updatedAt = policy.updatedAt;
    const yaml = stringify({ apiVersion: 'vulnify.io/v1', kind: 'Policy', metadata, spec });
    const file = join(outDir, fileName);
    writeFileSync(file, yaml.endsWith('\n') ? yaml : `${yaml}\n`);
    written.push({ name: policy.name, file: relative(ctx.cwd, file) });
  }
  const text = written.length ? written.map((item) => `wrote ${item.file}`).join('\n') + '\n' : 'No policies.\n';
  emit(ctx, { ok: true, exitCode: 0, policies: written }, text);
  return 0;
}

async function commandApply(ctx: Context, path: string | undefined, flags: Flags): Promise<number> {
  const target = resolve(ctx.cwd, path || defaultDir(ctx, 'policies'));
  const docs = readKind(ctx, target, 'Policy');
  const { apiKey, baseUrl } = requireKey(ctx);
  const payload = {
    policies: docs.map((doc) => toPolicySpec(doc.data)),
    prune: flags.prune === true,
    dryRun: flags['dry-run'] === true,
  };
  const body = await apiRequest('POST', `${baseUrl}/v1/policies/apply`, apiKey, payload);
  if (!isRecord(body) || !Array.isArray(body.changes)) throw new CliError('Unexpected response from POST /v1/policies/apply', 1, body);
  const lines = [`${body.dryRun === true ? 'dry-run' : 'applied'}`];
  for (const change of body.changes) {
    if (!isRecord(change)) continue;
    lines.push(`${String(change.op ?? 'unknown').padEnd(9)} ${String(change.name ?? '')}`);
  }
  emit(ctx, { ...body, ok: true, exitCode: 0 }, `${lines.join('\n')}\n`);
  return 0;
}

async function commandValidate(ctx: Context, path: string | undefined): Promise<number> {
  const target = resolve(ctx.cwd, path || defaultDir(ctx, 'policies'));
  const docs = readKind(ctx, target, 'Policy');
  emit(
    ctx,
    { ok: true, exitCode: 0, count: docs.length, schema: schemaPath() },
    `Validated ${docs.length} ${docs.length === 1 ? 'policy' : 'policies'} against schema/policies.v1.json\n`,
  );
  return 0;
}

async function commandTest(ctx: Context, path: string | undefined, flags: Flags): Promise<number> {
  const target = resolve(ctx.cwd, path || defaultDir(ctx, 'tests'));
  const docs = readKind(ctx, target, 'PolicyTest');
  const cases = docs.flatMap((doc) => {
    const list = doc.data.cases;
    if (!Array.isArray(list)) return [];
    return list.filter(isRecord).map((item) => toTestCase(item));
  });
  if (cases.length > 200) throw new CliError('POST /v1/policies/test accepts at most 200 cases', 1);
  const payload: Record<string, unknown> = { cases };
  if (flags.local) {
    const policyDir = defaultDir(ctx, 'policies');
    const policies = readKind(ctx, policyDir, 'Policy');
    payload.policies = policies.map((doc) => toPolicySpec(doc.data));
  }
  const { apiKey, baseUrl } = requireKey(ctx);
  const body = await apiRequest('POST', `${baseUrl}/v1/policies/test`, apiKey, payload);
  if (!isRecord(body) || !Array.isArray(body.results)) throw new CliError('Unexpected response from POST /v1/policies/test', 1, body);
  const lines: string[] = [];
  let failed = 0;
  for (const result of body.results) {
    if (!isRecord(result)) {
      failed += 1;
      lines.push('FAIL  invalid result');
      continue;
    }
    const name = String(result.name ?? '');
    const decision = String(result.decision ?? '');
    const policy = result.matchedPolicy == null ? 'none' : String(result.matchedPolicy);
    const pass = result.pass;
    if (pass === false || (pass !== true && pass !== null)) {
      failed += 1;
      lines.push(`FAIL  ${name}  ${decision}  policy ${policy}`);
    } else if (pass === null) {
      lines.push(`SKIP  ${name}  ${decision}  policy ${policy}`);
    } else {
      lines.push(`PASS  ${name}  ${decision}  policy ${policy}`);
    }
  }
  const code = failed > 0 ? 1 : 0;
  emit(ctx, { failed, results: body.results, ok: code === 0, exitCode: code }, `${lines.join('\n')}\n`);
  return code;
}

async function dispatch(ctx: Context, parsed: Parsed): Promise<number> {
  const [command, sub, ...rest] = parsed.positionals;
  if (parsed.flags.version && !command) {
    emit(ctx, { ok: true, exitCode: 0, version: packageVersion() }, `${packageVersion()}\n`);
    return 0;
  }
  if (!command) {
    emit(ctx, { ok: true, exitCode: 0, help: helpText() }, helpText());
    return parsed.help ? 0 : 1;
  }
  if (parsed.help) {
    emit(ctx, { ok: true, exitCode: 0, help: helpText() }, helpText());
    return 0;
  }
  if (rest.length && command !== 'policies') throw new CliError(`Unexpected argument ${rest[0]}`, 1);
  switch (command) {
    case 'init':
      if (sub) throw new CliError(`Unexpected argument ${sub}`, 1);
      return commandInit(ctx);
    case 'login':
      if (sub) throw new CliError(`Unexpected argument ${sub}`, 1);
      return commandLogin(ctx, parsed.flags);
    case 'check':
      if (sub) throw new CliError(`Unexpected argument ${sub}`, 1);
      return commandCheck(ctx, parsed.flags);
    case 'policies':
      if (sub === 'validate') {
        if (rest.length > 1) throw new CliError(`Unexpected argument ${rest[1]}`, 1);
        return commandValidate(ctx, rest[0]);
      }
      if (sub === 'pull') {
        if (rest.length) throw new CliError(`Unexpected argument ${rest[0]}`, 1);
        return commandPull(ctx, parsed.flags);
      }
      if (sub === 'apply') {
        if (rest.length > 1) throw new CliError(`Unexpected argument ${rest[1]}`, 1);
        return commandApply(ctx, rest[0], parsed.flags);
      }
      throw new CliError('Usage: vulnify policies validate|pull|apply', 1);
    case 'test':
      if (rest.length) throw new CliError(`Unexpected argument ${rest[0]}`, 1);
      return commandTest(ctx, sub, parsed.flags);
    default:
      throw new CliError(`Unknown command ${command}`, 1);
  }
}

export async function run(argv: string[], options: RunIO = {}): Promise<number> {
  const previous = globalThis.fetch;
  if (options.fetch) globalThis.fetch = options.fetch;
  const ctx: Context = {
    cwd: options.cwd ?? process.cwd(),
    env: options.env ?? process.env,
    home: options.homedir ?? homedir(),
    json: argv.includes('--json'),
    stdout: options.stdout ?? ((chunk) => process.stdout.write(chunk)),
    stderr: options.stderr ?? ((chunk) => process.stderr.write(chunk)),
  };
  try {
    const parsed = parseArgv(argv);
    ctx.json = parsed.json;
    return await dispatch(ctx, parsed);
  } catch (err) {
    if (err instanceof CliError) return fail(ctx, err);
    const message = err instanceof Error ? err.message : 'vulnify failed';
    return fail(ctx, new CliError(message, 1));
  } finally {
    if (options.fetch) globalThis.fetch = previous;
  }
}

function packageVersion(): string {
  let dir = __dirname;
  for (let i = 0; i < 6; i++) {
    const file = join(dir, 'package.json');
    if (existsSync(file)) {
      const parsed = JSON.parse(readFileSync(file, 'utf8')) as { version?: string };
      if (parsed.version) return parsed.version;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return '0.0.0';
}
