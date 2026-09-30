import type { AgentAction, Vulnify, VulnifyDecision, WaitForReviewOptions } from './index';

/**
 * Framework adapters. They are duck-typed on purpose: the SDK has no dependency on LangChain, MCP, the
 * OpenAI Agents SDK, the Vercel AI SDK or the OpenAI/Anthropic SDKs, so it works with whichever version you use.
 */

type Describe<A> = (args: A) => AgentAction;

/** Wraps any async function so it only runs when Vulnify allows the described action. */
export function guardFunction<A, R>(vulnify: Vulnify, describe: Describe<A>, fn: (args: A) => Promise<R> | R, wait?: WaitForReviewOptions) {
  return (args: A): Promise<R> => vulnify.guard(describe(args), () => fn(args), wait);
}

export interface ToolDefinition<A = any, R = any> {
  /** Maps the model's tool arguments to the Vulnify action (agent, action, resource, destination, ...). */
  describe: Describe<A>;
  run: (args: A) => Promise<R> | R;
}

/**
 * OpenAI / Anthropic tool calls: register your tools once, then route every model tool call through `call`.
 *
 *   const tools = guardedTools(vulnify, { export_customers: { describe: (a) => ({...}), run: exportCustomers } });
 *   const result = await tools.call(toolUse.name, toolUse.input);
 */
export function guardedTools(vulnify: Vulnify, tools: Record<string, ToolDefinition>, wait?: WaitForReviewOptions) {
  return {
    async call(name: string, args: unknown) {
      const tool = tools[name];
      if (!tool) throw new Error(`Unknown tool: ${name}`);
      return vulnify.guard(tool.describe(args), () => tool.run(args), wait);
    },
  };
}

/** LangChain (JS) tools: returns a tool whose `invoke` (and legacy `call`) is guarded. */
export function guardLangChainTool<T extends { invoke?: (...a: any[]) => any; call?: (...a: any[]) => any }>(
  vulnify: Vulnify,
  tool: T,
  describe: Describe<any>,
  wait?: WaitForReviewOptions,
): T {
  const wrapped: any = Object.create(tool);
  for (const method of ['invoke', 'call'] as const) {
    const original = tool[method];
    if (typeof original === 'function') {
      wrapped[method] = (input: unknown, ...rest: unknown[]) =>
        vulnify.guard(describe(input), () => original.call(tool, input, ...rest), wait);
    }
  }
  return wrapped as T;
}

/**
 * MCP servers: wrap the handler you pass to `server.tool(name, schema, handler)`.
 * Blocked or unapproved calls return an MCP error result instead of throwing.
 */
export function guardMcpHandler<A, R>(vulnify: Vulnify, describe: Describe<A>, handler: (args: A, extra?: unknown) => Promise<R> | R, wait?: WaitForReviewOptions) {
  return async (args: A, extra?: unknown) => {
    try {
      return await vulnify.guard(describe(args), () => handler(args, extra), wait);
    } catch (err) {
      if (err instanceof Error && err.name === 'VulnifyBlockedError') {
        return { isError: true, content: [{ type: 'text', text: err.message }] };
      }
      throw err;
    }
  };
}

/** What a blocked tool call returns to the model when `onBlocked` is `'result'` (the default for agent frameworks). */
export interface VulnifyBlockedResult {
  blocked: true;
  decision: VulnifyDecision['decision'];
  reasons: string[];
  eventId: string | null;
  message: string;
}

export interface AgentToolGuardOptions {
  /** Wait for a human when the decision is REVIEW (runs only if approved). */
  wait?: WaitForReviewOptions;
  /**
   * `'result'` (default): the tool call answers with a {@link VulnifyBlockedResult} so the model learns it was not
   * allowed and can tell the user. `'throw'`: rethrow the VulnifyBlockedError (the framework's own error handling applies).
   */
  onBlocked?: 'result' | 'throw';
}

function blockedResult(err: unknown): VulnifyBlockedResult | null {
  if (!(err instanceof Error) || err.name !== 'VulnifyBlockedError') return null;
  const result = (err as Error & { result: VulnifyDecision }).result;
  return { blocked: true, decision: result.decision, reasons: result.reasons, eventId: result.id, message: err.message };
}

/** Runs fn when allowed; when blocked, answers `onBlocked(result)` unless the caller asked to rethrow. */
async function runGuarded<R, B>(
  vulnify: Vulnify,
  action: AgentAction,
  fn: () => Promise<R> | R,
  opts: AgentToolGuardOptions,
  onBlocked: (blocked: VulnifyBlockedResult) => B,
): Promise<R | B> {
  try {
    return await vulnify.guard(action, fn, opts.wait);
  } catch (err) {
    const blocked = opts.onBlocked === 'throw' ? null : blockedResult(err);
    if (blocked) return onBlocked(blocked);
    throw err;
  }
}

const asMessage = (b: VulnifyBlockedResult) => b.message;
const asResult = (b: VulnifyBlockedResult) => b;

/**
 * OpenAI Agents SDK (`@openai/agents`): guard a tool config before passing it to `tool()`, or an existing
 * function tool (its `invoke(runContext, input)` receives the arguments as a JSON string).
 *
 *   const exportCustomers = tool(guardOpenAIAgentsTool(vulnify, { name, description, parameters, execute }, describe));
 *
 * A blocked call returns the block message (text) to the model instead of running the tool (see `onBlocked`).
 */
export function guardOpenAIAgentsTool<T extends object>(vulnify: Vulnify, tool: T, describe: Describe<any>, opts: AgentToolGuardOptions = {}): T {
  const t = tool as T & { type?: string; execute?: (...a: any[]) => any; invoke?: (...a: any[]) => any };
  if (t.type === 'function' && typeof t.invoke === 'function') {
    const invoke = t.invoke;
    const wrapped: any = Object.create(tool);
    wrapped.invoke = (runContext: unknown, input: string, ...rest: unknown[]) => {
      let args: unknown = input;
      try {
        args = typeof input === 'string' ? JSON.parse(input) : input;
      } catch {
        // Not JSON: describe() receives the raw string.
      }
      return runGuarded(vulnify, describe(args), () => invoke.call(tool, runContext, input, ...rest), opts, asMessage);
    };
    return wrapped as T;
  }
  if (typeof t.execute !== 'function') throw new Error('guardOpenAIAgentsTool: expected a tool config with execute() or a function tool');
  const execute = t.execute;
  return {
    ...tool,
    execute: (input: unknown, ...rest: unknown[]) =>
      runGuarded(vulnify, describe(input), () => execute.call(tool, input, ...rest), opts, asMessage),
  };
}

/**
 * Vercel AI SDK (`ai`): guard the tools you pass to `generateText` / `streamText`.
 *
 *   const tools = guardAiSdkTools(vulnify, { exportCustomers: tool({ inputSchema, execute }) }, { exportCustomers: describe });
 *
 * Only tools listed in `describe` are guarded; the others are returned unchanged. A blocked call returns a
 * {@link VulnifyBlockedResult} as the tool output (see `onBlocked`).
 */
export function guardAiSdkTools<T extends Record<string, any>>(
  vulnify: Vulnify,
  tools: T,
  describe: Partial<Record<keyof T, Describe<any>>>,
  opts: AgentToolGuardOptions = {},
): T {
  const out: Record<string, any> = { ...tools };
  for (const [name, describeTool] of Object.entries(describe) as [string, Describe<any> | undefined][]) {
    const t = tools[name];
    if (!describeTool) continue;
    if (!t || typeof t.execute !== 'function') throw new Error(`guardAiSdkTools: tool "${name}" has no execute()`);
    const execute = t.execute;
    out[name] = { ...t, execute: (input: unknown, options?: unknown) => runGuarded(vulnify, describeTool(input), () => execute.call(t, input, options), opts, asResult) };
  }
  return out as T;
}
