import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { run } from './run';
import { UNSUPPORTED_MESSAGE } from './http';

const allow = {
  id: '1',
  decision: 'ALLOW',
  finalDecision: 'ALLOW',
  evaluatedDecision: 'ALLOW',
  monitored: false,
  review: null,
  riskLevel: 'LOW',
  riskScore: 5,
  reasons: ['ok'],
  policy: null,
  dlpFindings: [],
  lgpdCategories: [],
  quotaExceeded: false,
  sandbox: false,
};

function response(status: number, body: unknown) {
  const text = JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => text,
    json: async () => body,
  };
}

function createHarness() {
  const cwd = mkdtempSync(join(tmpdir(), 'vulnify-cli-'));
  const home = mkdtempSync(join(tmpdir(), 'vulnify-home-'));
  const stdout: string[] = [];
  const stderr: string[] = [];
  const fetchMock = jest.fn();
  const base = {
    cwd,
    homedir: home,
    stdout: (chunk: string) => {
      stdout.push(chunk);
    },
    stderr: (chunk: string) => {
      stderr.push(chunk);
    },
    fetch: fetchMock as unknown as typeof fetch,
  };
  return {
    cwd,
    home,
    fetchMock,
    async run(argv: string[], env: NodeJS.ProcessEnv = {}) {
      stdout.length = 0;
      stderr.length = 0;
      const code = await run(argv, { ...base, env });
      return { code, out: stdout.join(''), err: stderr.join('') };
    },
    cleanup() {
      rmSync(cwd, { recursive: true, force: true });
      rmSync(home, { recursive: true, force: true });
    },
  };
}

const POLICY = `apiVersion: vulnify.io/v1
kind: Policy
metadata:
  name: block-bulk-customer-export
spec:
  description: Block exports of more than 1000 customer records
  enabled: true
  action: EXPORT
  resource: CUSTOMER_PII
  condition:
    minRecords: 1001
  decision: BLOCK
  mode: ENFORCE
  approverRoles:
    - OWNER
    - ADMIN
`;

const TEST_DOC = `apiVersion: vulnify.io/v1
kind: PolicyTest
metadata:
  name: export-rules
cases:
  - name: bulk export is blocked
    input:
      agent: support-bot
      action: EXPORT_DATA
      resource: customers-db
      recordsAffected: 5000
    expect:
      decision: BLOCK
      policy: block-bulk-customer-export
`;

describe('vulnify CLI', () => {
  let h: ReturnType<typeof createHarness>;

  beforeEach(() => {
    h = createHarness();
  });

  afterEach(() => {
    h.cleanup();
  });

  it('prints help and version', async () => {
    const help = await h.run(['--help']);
    expect(help.code).toBe(0);
    expect(help.out).toContain('vulnify policies apply');
    expect(help.out).toContain(UNSUPPORTED_MESSAGE);
    expect(help.out).toContain('0600');

    const version = await h.run(['--version']);
    expect(version.code).toBe(0);
    expect(version.out.trim()).toBe('0.3.0');

    const missing = await h.run([]);
    expect(missing.code).toBe(1);
    expect(missing.out).toContain('vulnify init');
  });

  it('init writes the example files and refuses to overwrite them', async () => {
    const created = await h.run(['init']);
    expect(created.code).toBe(0);
    expect(created.out).toContain('credentials.json');
    expect(created.out).toContain('0600');
    const policy = readFileSync(join(h.cwd, 'vulnify/policies/example.yaml'), 'utf8');
    const test = readFileSync(join(h.cwd, 'vulnify/tests/example.test.yaml'), 'utf8');
    const ignore = readFileSync(join(h.cwd, 'vulnify/.gitignore'), 'utf8');
    expect(policy).toContain('minRecords: 1001');
    expect(policy).not.toContain('recordsAffected:');
    expect(policy).toContain('action: EXPORT');
    expect(policy).toContain('resource: CUSTOMER_PII');
    expect(test).toContain('kind: PolicyTest');
    expect(test).toContain('action: EXPORT_DATA');
    expect(ignore).toContain('0600');

    const validated = await h.run(['policies', 'validate']);
    expect(validated.code).toBe(0);
    expect(validated.out).toContain('Validated 1 policy');

    const again = await h.run(['init']);
    expect(again.code).toBe(1);
    expect(again.out).toContain('Refusing to overwrite');
  });

  it('validate reports file:line for the placeholder condition grammar', async () => {
    const file = join(h.cwd, 'bad.yaml');
    writeFileSync(
      file,
      `apiVersion: vulnify.io/v1
kind: Policy
metadata:
  name: bad-export
spec:
  action: EXPORT_DATA
  resource: customers-db
  condition:
    recordsAffected:
      gt: 1000
  decision: BLOCK
`,
    );
    const result = await h.run(['policies', 'validate', file]);
    expect(result.code).toBe(1);
    expect(result.out).toMatch(/bad\.yaml:\d+:/);
    expect(result.out).toContain('recordsAffected');
    expect(result.out).toContain('/spec/action');
    const conditionLine = result.out.split('\n').find((line) => line.includes('recordsAffected'));
    expect(conditionLine).toBeTruthy();
    const lineNo = Number(conditionLine?.split(':')[1]);
    expect(lineNo).toBeGreaterThanOrEqual(9);

    const json = await h.run(['--json', 'policies', 'validate', file]);
    expect(json.code).toBe(1);
    expect(JSON.parse(json.out).exitCode).toBe(1);
  });

  it('accepts grouped conditions and rejects a bad agent id', async () => {
    const file = join(h.cwd, 'grouped.yaml');
    writeFileSync(
      file,
      `apiVersion: vulnify.io/v1
kind: Policy
metadata:
  name: grouped
spec:
  action: EXPORT
  resource: ANY
  decision: REVIEW
  condition:
    minRecords: 1000
    maxRecords: 5000
    containsSensitiveData: true
    outsideBusinessHours: true
    destination: EXTERNAL
    destinationContains: gmail.com
    minRiskScore: 40
    allOf:
      - action: EXPORT_DATA
        agentIds:
          - 11111111-1111-4111-8111-111111111111
    anyOf:
      - destination: INTERNAL
  approverRoles:
    - OWNER
`,
    );
    expect((await h.run(['policies', 'validate', file])).code).toBe(0);

    writeFileSync(file, readFileSync(file, 'utf8').replace('11111111-1111-4111-8111-111111111111', 'support-bot'));
    const bad = await h.run(['policies', 'validate', file]);
    expect(bad.code).toBe(1);
    expect(bad.out).toContain('agentIds');
  });

  it('rejects duplicate policy names', async () => {
    writeFileSync(join(h.cwd, 'a.yaml'), POLICY);
    writeFileSync(join(h.cwd, 'b.yaml'), POLICY);
    const result = await h.run(['policies', 'validate', h.cwd]);
    expect(result.code).toBe(1);
    expect(result.out).toContain('Duplicate policy name');
  });

  it('login stores the key with mode 0600 and treats 401 as auth failure', async () => {
    h.fetchMock.mockResolvedValue(response(404, { message: 'Event not found', statusCode: 404 }));
    const ok = await h.run(['login', '--api-key', 'vln_test_abc', '--base-url', 'https://api.example.test/']);
    expect(ok.code).toBe(0);
    const file = join(h.home, '.config', 'vulnify', 'credentials.json');
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(statSync(join(h.home, '.config', 'vulnify')).mode & 0o777).toBe(0o700);
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({
      apiKey: 'vln_test_abc',
      baseUrl: 'https://api.example.test',
    });
    expect(String(h.fetchMock.mock.calls[0][0])).toBe('https://api.example.test/v1/events/00000000-0000-4000-8000-000000000000');
    expect(h.fetchMock.mock.calls[0][1].headers.Authorization).toBe('Bearer vln_test_abc');

    h.fetchMock.mockResolvedValue(response(401, { message: 'Invalid API key', statusCode: 401 }));
    const denied = await h.run(['login', '--api-key', 'nope']);
    expect(denied.code).toBe(5);
    expect(denied.out).toContain('Invalid API key');

    h.fetchMock.mockResolvedValue(response(404, { message: 'Cannot GET /v1/events/00000000-0000-4000-8000-000000000000' }));
    const missingRoute = await h.run(['login', '--api-key', 'vln_test_abc', '--base-url', 'https://wrong.example']);
    expect(missingRoute.code).toBe(1);
    expect(missingRoute.out).toContain('no decision API');
  });

  it('check uses the SDK decision API and the documented exit codes', async () => {
    mkdirSyncCreds(h.home);
    writeFileSync(
      join(h.home, '.config', 'vulnify', 'credentials.json'),
      JSON.stringify({ apiKey: 'vln_test_file', baseUrl: 'https://file.example' }),
    );

    h.fetchMock.mockResolvedValue(response(200, allow));
    const allowed = await h.run(
      ['check', '--agent', 'support-bot', '--action', 'EXPORT_DATA', '--resource', 'customers-db', '--records', '12', '--destination', 'EXTERNAL_EMAIL'],
      { VULNIFY_API_KEY: 'vln_test_env', VULNIFY_BASE_URL: 'https://env.example' },
    );
    expect(allowed.code).toBe(0);
    expect(allowed.out).toContain('ALLOW');
    expect(String(h.fetchMock.mock.calls[0][0])).toBe('https://env.example/v1/events');
    expect(h.fetchMock.mock.calls[0][1].headers.Authorization).toBe('Bearer vln_test_env');
    expect(JSON.parse(h.fetchMock.mock.calls[0][1].body)).toEqual({
      agent: 'support-bot',
      action: 'EXPORT_DATA',
      resource: 'customers-db',
      destination: 'EXTERNAL_EMAIL',
      recordsAffected: 12,
    });

    h.fetchMock.mockResolvedValue(response(200, { ...allow, decision: 'REVIEW', finalDecision: 'REVIEW' }));
    expect((await h.run(['check', '--agent', 'a', '--action', 'READ_DATA', '--resource', 'r'])).code).toBe(2);

    h.fetchMock.mockResolvedValue(response(200, { ...allow, decision: 'REVIEW', finalDecision: 'BLOCK', reasons: ['denied'] }));
    const blocked = await h.run(['check', '--agent', 'a', '--action', 'READ_DATA', '--resource', 'r']);
    expect(blocked.code).toBe(3);
    expect(blocked.out).toContain('BLOCK');

    h.fetchMock.mockResolvedValue(response(401, { message: 'Invalid API key' }));
    expect((await h.run(['check', '--agent', 'a', '--action', 'READ_DATA', '--resource', 'r'])).code).toBe(5);

    h.fetchMock.mockRejectedValue(new Error('ECONNREFUSED'));
    const down = await h.run(['check', '--agent', 'a', '--action', 'READ_DATA', '--resource', 'r']);
    expect(down.code).toBe(1);
    expect(down.out).toContain('failMode=closed');

    h.fetchMock.mockResolvedValue(response(200, allow));
    const live = await h.run(['check', '--agent', 'a', '--action', 'READ_DATA', '--resource', 'r', '--sensitive'], {
      VULNIFY_API_KEY: 'vln_live_real',
    });
    expect(live.code).toBe(0);
    expect(live.err).toContain('LIVE key');
    expect(live.err).toContain('--sensitive is not sent');
    expect(JSON.parse(h.fetchMock.mock.calls.at(-1)[1].body)).not.toHaveProperty('containsSensitiveData');

    const json = await h.run(['--json', 'check', '--agent', 'a', '--action', 'READ_DATA', '--resource', 'r']);
    expect(JSON.parse(json.out).finalDecision).toBe('ALLOW');
    expect(JSON.parse(json.out).exitCode).toBe(0);
  });

  it('pull writes one YAML file per policy and exits 4 on 404', async () => {
    mkdirSyncCreds(h.home);
    writeFileSync(join(h.home, '.config', 'vulnify', 'credentials.json'), JSON.stringify({ apiKey: 'vln_test_k', baseUrl: 'https://api.example' }));

    h.fetchMock.mockResolvedValue(
      response(200, {
        apiVersion: 'vulnify.io/v1',
        policies: [
          {
            name: 'Zebra',
            id: '11111111-1111-4111-8111-111111111111',
            updatedAt: '2026-10-02T12:00:00.000Z',
            action: 'READ',
            decision: 'ALLOW',
            condition: {},
          },
          {
            name: 'block-bulk-customer-export',
            id: '22222222-2222-4222-8222-222222222222',
            updatedAt: '2026-10-02T12:00:00.000Z',
            description: 'Block exports of more than 1000 customer records',
            enabled: true,
            action: 'EXPORT',
            resource: 'CUSTOMER_PII',
            condition: { minRecords: 1001 },
            decision: 'BLOCK',
            mode: 'ENFORCE',
            approverRoles: ['OWNER', 'ADMIN'],
          },
        ],
      }),
    );
    const pulled = await h.run(['policies', 'pull', '--out', 'out']);
    expect(pulled.code).toBe(0);
    const names = ['block-bulk-customer-export.yaml', 'zebra.yaml'];
    expect(pulled.out).toContain('out/block-bulk-customer-export.yaml');
    expect(pulled.out).toContain('out/zebra.yaml');
    const bulk = readFileSync(join(h.cwd, 'out', names[0]), 'utf8');
    expect(bulk).toContain('minRecords: 1001');
    expect(bulk).toContain('kind: Policy');
    expect(bulk).toContain('22222222-2222-4222-8222-222222222222');
    expect((await h.run(['policies', 'validate', 'out'])).code).toBe(0);

    h.fetchMock.mockResolvedValue(response(404, { message: 'Cannot GET /v1/policies', error: 'Not Found', statusCode: 404 }));
    const missing = await h.run(['policies', 'pull']);
    expect(missing.code).toBe(4);
    expect(missing.out.trim()).toBe(UNSUPPORTED_MESSAGE);

    const missingJson = await h.run(['--json', 'policies', 'pull']);
    expect(missingJson.code).toBe(4);
    expect(JSON.parse(missingJson.out).error).toBe(UNSUPPORTED_MESSAGE);

    h.fetchMock.mockResolvedValue(response(401, { message: 'Invalid API key' }));
    expect((await h.run(['policies', 'pull'])).code).toBe(5);

    h.fetchMock.mockResolvedValue(response(429, { error: 'rate_limited' }));
    const limited = await h.run(['policies', 'pull']);
    expect(limited.code).toBe(1);
    expect(limited.out).toContain('rate_limited');
  });

  it('apply posts the change plan and does not call the server for an invalid file', async () => {
    mkdirSyncCreds(h.home);
    writeFileSync(join(h.home, '.config', 'vulnify', 'credentials.json'), JSON.stringify({ apiKey: 'vln_test_k', baseUrl: 'https://api.example' }));
    writeFileSync(join(h.cwd, 'policy.yaml'), POLICY);

    h.fetchMock.mockResolvedValue(
      response(200, { dryRun: true, changes: [{ name: 'block-bulk-customer-export', op: 'create' }] }),
    );
    const dry = await h.run(['policies', 'apply', 'policy.yaml', '--dry-run', '--prune']);
    expect(dry.code).toBe(0);
    expect(dry.out).toContain('dry-run');
    expect(dry.out).toContain('create');
    expect(dry.out).toContain('block-bulk-customer-export');
    const sent = JSON.parse(h.fetchMock.mock.calls[0][1].body);
    expect(h.fetchMock.mock.calls[0][0]).toBe('https://api.example/v1/policies/apply');
    expect(sent.dryRun).toBe(true);
    expect(sent.prune).toBe(true);
    expect(sent.policies[0]).toMatchObject({
      name: 'block-bulk-customer-export',
      action: 'EXPORT',
      resource: 'CUSTOMER_PII',
      condition: { minRecords: 1001 },
      decision: 'BLOCK',
    });
    expect(sent.policies[0].id).toBeUndefined();

    h.fetchMock.mockClear();
    writeFileSync(join(h.cwd, 'policy.yaml'), POLICY.replace('action: EXPORT', 'action: EXPORT_DATA'));
    const invalid = await h.run(['policies', 'apply', 'policy.yaml']);
    expect(invalid.code).toBe(1);
    expect(h.fetchMock).not.toHaveBeenCalled();

    writeFileSync(join(h.cwd, 'policy.yaml'), POLICY);
    h.fetchMock.mockResolvedValue(response(404, { message: 'Cannot POST /v1/policies/apply' }));
    const missing = await h.run(['policies', 'apply', 'policy.yaml']);
    expect(missing.code).toBe(4);
    expect(missing.out.trim()).toBe(UNSUPPORTED_MESSAGE);

    h.fetchMock.mockResolvedValue(
      response(400, { error: 'validation_error', fields: { 'policies[0].action': 'unknown action' } }),
    );
    const invalidServer = await h.run(['policies', 'apply', 'policy.yaml']);
    expect(invalidServer.code).toBe(1);
    expect(invalidServer.out).toContain('policies[0].action: unknown action');

    h.fetchMock.mockResolvedValue(
      response(403, { error: 'forbidden', message: 'policies:apply requires an org-wide LIVE key' }),
    );
    const forbidden = await h.run(['policies', 'apply', 'policy.yaml']);
    expect(forbidden.code).toBe(5);
    expect(forbidden.out).toContain('org-wide LIVE key');
  });

  it('test prints pass and fail and sends local policies only with --local', async () => {
    mkdirSyncCreds(h.home);
    writeFileSync(join(h.home, '.config', 'vulnify', 'credentials.json'), JSON.stringify({ apiKey: 'vln_test_k', baseUrl: 'https://api.example' }));
    mkdirSync(join(h.cwd, 'vulnify', 'policies'), { recursive: true });
    mkdirSync(join(h.cwd, 'vulnify', 'tests'), { recursive: true });
    writeFileSync(join(h.cwd, 'vulnify', 'policies', 'example.yaml'), POLICY);
    writeFileSync(join(h.cwd, 'vulnify', 'tests', 'example.test.yaml'), TEST_DOC);

    h.fetchMock.mockResolvedValue(
      response(200, {
        results: [
          {
            name: 'bulk export is blocked',
            decision: 'BLOCK',
            matchedPolicy: 'block-bulk-customer-export',
            riskScore: 80,
            riskLevel: 'HIGH',
            reasons: ['records'],
            pass: true,
          },
        ],
      }),
    );
    const passed = await h.run(['test']);
    expect(passed.code).toBe(0);
    expect(passed.out).toContain('PASS  bulk export is blocked');
    const withoutLocal = JSON.parse(h.fetchMock.mock.calls[0][1].body);
    expect(withoutLocal.policies).toBeUndefined();
    expect(withoutLocal.cases[0].name).toBe('bulk export is blocked');
    expect(String(h.fetchMock.mock.calls[0][0])).toBe('https://api.example/v1/policies/test');

    h.fetchMock.mockResolvedValue(
      response(200, {
        results: [
          {
            name: 'bulk export is blocked',
            decision: 'ALLOW',
            matchedPolicy: null,
            riskScore: 1,
            riskLevel: 'LOW',
            reasons: [],
            pass: false,
          },
        ],
      }),
    );
    const failed = await h.run(['test', '--local', '--json']);
    expect(failed.code).toBe(1);
    const body = JSON.parse(h.fetchMock.mock.calls.at(-1)[1].body);
    expect(body.policies).toHaveLength(1);
    expect(body.policies[0].name).toBe('block-bulk-customer-export');
    expect(JSON.parse(failed.out).failed).toBe(1);
    expect(JSON.parse(failed.out).exitCode).toBe(1);

    h.fetchMock.mockResolvedValue(response(404, { message: 'Cannot POST /v1/policies/test' }));
    const missing = await h.run(['test']);
    expect(missing.code).toBe(4);
    expect(missing.out.trim()).toBe(UNSUPPORTED_MESSAGE);

    h.fetchMock.mockResolvedValue(response(401, { error: 'Unauthorized', message: 'Invalid API key' }));
    expect((await h.run(['test'])).code).toBe(5);
  });

  it('commands that need a key exit 5 when none is configured', async () => {
    expect((await h.run(['policies', 'pull'])).code).toBe(5);
    writeFileSync(join(h.cwd, 'policy.yaml'), POLICY);
    expect((await h.run(['policies', 'apply', 'policy.yaml'])).code).toBe(5);
    writeFileSync(join(h.cwd, 'case.yaml'), TEST_DOC);
    expect((await h.run(['test', 'case.yaml'])).code).toBe(5);
    expect((await h.run(['check', '--agent', 'a', '--action', 'READ_DATA', '--resource', 'r'])).code).toBe(5);
    expect((await h.run(['login'])).code).toBe(5);
  });

  it('keeps a loose credential file from being required, and env still wins', async () => {
    mkdirSyncCreds(h.home);
    const file = join(h.home, '.config', 'vulnify', 'credentials.json');
    writeFileSync(file, JSON.stringify({ apiKey: 'vln_test_file', baseUrl: 'https://file.example' }));
    chmodSync(file, 0o644);
    h.fetchMock.mockResolvedValue(response(200, allow));
    const result = await h.run(['check', '--agent', 'a', '--action', 'READ_DATA', '--resource', 'r'], {
      VULNIFY_API_KEY: 'vln_test_env',
    });
    expect(result.code).toBe(0);
    expect(h.fetchMock.mock.calls[0][1].headers.Authorization).toBe('Bearer vln_test_env');
    expect(String(h.fetchMock.mock.calls[0][0])).toContain('https://file.example/v1/events');
  });
});

function mkdirSyncCreds(home: string) {
  mkdirSync(join(home, '.config', 'vulnify'), { recursive: true });
}
