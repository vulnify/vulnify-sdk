import { guardAiSdkTools, guardedTools, guardFunction, guardLangChainTool, guardMcpHandler, guardOpenAIAgentsTool, Vulnify } from './index';

const decision = (d: string) => ({
  ok: true, status: 200,
  json: async () => ({ id: 'e1', decision: d, evaluatedDecision: d, monitored: false, review: null, riskLevel: 'LOW', riskScore: 5, reasons: ['r'], policy: null }),
});
const describeExport = (a: { rows: number }) => ({ agent: 'SalesBot', action: 'EXPORT_DATA' as const, resource: 'Customer Database', recordsAffected: a.rows });

describe('adapters', () => {
  const v = new Vulnify({ apiKey: 'k', retries: 0 });

  it('guardFunction runs only on ALLOW and forwards the arguments to describe()', async () => {
    const fetchMock = jest.fn().mockResolvedValue(decision('ALLOW'));
    global.fetch = fetchMock as never;
    const run = jest.fn().mockResolvedValue('ok');
    await expect(guardFunction(v, describeExport, run)({ rows: 12 })).resolves.toBe('ok');
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).recordsAffected).toBe(12);

    global.fetch = jest.fn().mockResolvedValue(decision('BLOCK')) as never;
    await expect(guardFunction(v, describeExport, run)({ rows: 1 })).rejects.toThrow('BLOCK');
    expect(run).toHaveBeenCalledTimes(1);
  });

  it('guardedTools routes model tool calls and rejects unknown tools', async () => {
    global.fetch = jest.fn().mockResolvedValue(decision('ALLOW')) as never;
    const tools = guardedTools(v, { export_customers: { describe: describeExport, run: async (a: { rows: number }) => `exported ${a.rows}` } });
    await expect(tools.call('export_customers', { rows: 5 })).resolves.toBe('exported 5');
    await expect(tools.call('nope', {})).rejects.toThrow('Unknown tool');
  });

  it('guardLangChainTool guards invoke() and keeps the other properties', async () => {
    global.fetch = jest.fn().mockResolvedValue(decision('BLOCK')) as never;
    const tool = { name: 'export', description: 'd', invoke: jest.fn().mockResolvedValue('done') };
    const guarded = guardLangChainTool(v, tool, describeExport);
    expect(guarded.name).toBe('export');
    await expect(guarded.invoke({ rows: 1 })).rejects.toThrow('BLOCK');
    expect(tool.invoke).not.toHaveBeenCalled();
  });

  it('guardMcpHandler returns an MCP error result instead of throwing when blocked', async () => {
    global.fetch = jest.fn().mockResolvedValue(decision('BLOCK')) as never;
    const handler = jest.fn();
    const res = await guardMcpHandler(v, describeExport, handler)({ rows: 1 });
    expect(res).toMatchObject({ isError: true });
    expect(handler).not.toHaveBeenCalled();

    global.fetch = jest.fn().mockResolvedValue(decision('ALLOW')) as never;
    handler.mockResolvedValue({ content: [{ type: 'text', text: 'ok' }] });
    await expect(guardMcpHandler(v, describeExport, handler)({ rows: 1 })).resolves.toEqual({ content: [{ type: 'text', text: 'ok' }] });
  });

  it('guardOpenAIAgentsTool guards a tool config: runs on ALLOW, answers the block message to the model on BLOCK', async () => {
    const execute = jest.fn().mockResolvedValue('exported');
    const config = { name: 'export_customers', description: 'd', parameters: {}, execute };
    const guarded = guardOpenAIAgentsTool(v, config, describeExport);
    expect(guarded.name).toBe('export_customers');

    global.fetch = jest.fn().mockResolvedValue(decision('ALLOW')) as never;
    await expect(guarded.execute({ rows: 3 }, { context: {} })).resolves.toBe('exported');
    expect(execute).toHaveBeenCalledWith({ rows: 3 }, { context: {} });

    global.fetch = jest.fn().mockResolvedValue(decision('BLOCK')) as never;
    await expect(guarded.execute({ rows: 3 })).resolves.toBe('Vulnify BLOCK: r');
    expect(execute).toHaveBeenCalledTimes(1);
    await expect(guardOpenAIAgentsTool(v, config, describeExport, { onBlocked: 'throw' }).execute({ rows: 3 })).rejects.toThrow('BLOCK');
  });

  it('guardOpenAIAgentsTool guards an existing function tool and parses its JSON input for describe()', async () => {
    const fetchMock = jest.fn().mockResolvedValue(decision('BLOCK'));
    global.fetch = fetchMock as never;
    const invoke = jest.fn().mockResolvedValue('exported');
    const fnTool = { type: 'function', name: 'export_customers', invoke };
    const guarded = guardOpenAIAgentsTool(v, fnTool, describeExport);
    await expect(guarded.invoke({}, '{"rows":42}')).resolves.toBe('Vulnify BLOCK: r');
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).recordsAffected).toBe(42);
    expect(invoke).not.toHaveBeenCalled();
    expect(() => guardOpenAIAgentsTool(v, { name: 'x' }, describeExport)).toThrow('execute');
  });

  it('guardAiSdkTools guards listed tools, leaves the others unchanged and returns a structured result when blocked', async () => {
    const exportTool = { description: 'd', inputSchema: {}, execute: jest.fn().mockResolvedValue({ ok: true }) };
    const readTool = { description: 'r', inputSchema: {}, execute: jest.fn() };
    const tools = guardAiSdkTools(v, { exportCustomers: exportTool, readDocs: readTool }, { exportCustomers: describeExport });
    expect(tools.readDocs).toBe(readTool);
    expect(tools.exportCustomers.description).toBe('d');

    global.fetch = jest.fn().mockResolvedValue(decision('ALLOW')) as never;
    await expect(tools.exportCustomers.execute({ rows: 1 }, { toolCallId: 't1' })).resolves.toEqual({ ok: true });
    expect(exportTool.execute).toHaveBeenCalledWith({ rows: 1 }, { toolCallId: 't1' });

    global.fetch = jest.fn().mockResolvedValue(decision('BLOCK')) as never;
    await expect(tools.exportCustomers.execute({ rows: 1 }, { toolCallId: 't2' })).resolves.toEqual({
      blocked: true, decision: 'BLOCK', reasons: ['r'], eventId: 'e1', message: 'Vulnify BLOCK: r',
    });
    expect(exportTool.execute).toHaveBeenCalledTimes(1);
    expect(() => guardAiSdkTools(v, { a: { description: 'no execute' } }, { a: describeExport })).toThrow('no execute');
  });
});
