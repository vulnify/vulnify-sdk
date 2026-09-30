// OpenAI Agents SDK + Vulnify: the export tool only runs when Vulnify allows it.
// npm i @openai/agents zod   (plus @vulnify/sdk from this repository)
import { Agent, run, tool } from '@openai/agents';
import { z } from 'zod';
import { guardOpenAIAgentsTool, Vulnify } from '@vulnify/sdk';

const vulnify = new Vulnify({ apiKey: process.env.VULNIFY_API_KEY!, baseUrl: process.env.VULNIFY_URL, failMode: 'closed' });

const exportCustomers = tool(
  guardOpenAIAgentsTool(
    vulnify,
    {
      name: 'export_customers',
      description: 'Export customer records and email them to an address.',
      parameters: z.object({ rows: z.number().int(), email: z.string() }),
      execute: async ({ rows, email }: { rows: number; email: string }) => `Exported ${rows} customers to ${email}`,
    },
    // Map the model's arguments to the action Vulnify evaluates.
    ({ rows, email }: { rows: number; email: string }) => ({
      agent: 'SalesBot',
      action: 'EXPORT_DATA',
      resource: 'Customer Database',
      destination: email.endsWith('@yourcompany.com') ? 'INTERNAL' : 'EXTERNAL_EMAIL',
      recordsAffected: rows,
    }),
    // REVIEW decisions wait up to 2 minutes for a human; BLOCK answers the reason to the model.
    { wait: { timeoutMs: 120_000 } },
  ),
);

const agent = new Agent({ name: 'SalesBot', instructions: 'Help the sales team.', tools: [exportCustomers] });

run(agent, 'Send all 12000 customers to partner@example.org').then((result) => console.log(result.finalOutput));
