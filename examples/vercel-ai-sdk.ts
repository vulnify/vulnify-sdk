// Vercel AI SDK + Vulnify: guarded tools for generateText / streamText.
// npm i ai @ai-sdk/openai zod   (plus @vulnify/sdk from this repository)
import { generateText, stepCountIs, tool } from 'ai';
import { openai } from '@ai-sdk/openai';
import { z } from 'zod';
import { guardAiSdkTools, Vulnify } from '@vulnify/sdk';

const vulnify = new Vulnify({ apiKey: process.env.VULNIFY_API_KEY!, baseUrl: process.env.VULNIFY_URL });

const tools = guardAiSdkTools(
  vulnify,
  {
    deleteTicket: tool({
      description: 'Delete a support ticket.',
      inputSchema: z.object({ ticketId: z.string() }),
      execute: async ({ ticketId }) => ({ deleted: ticketId }),
    }),
    searchDocs: tool({
      description: 'Search the public documentation.',
      inputSchema: z.object({ query: z.string() }),
      execute: async ({ query }) => ({ results: [`Docs about ${query}`] }),
    }),
  },
  // Only deleteTicket is guarded; searchDocs runs as is.
  { deleteTicket: () => ({ agent: 'SupportBot', action: 'DELETE_DATA', resource: 'Support Tickets', recordsAffected: 1 }) },
);

async function main() {
  const { text } = await generateText({
    model: openai('gpt-4o-mini'),
    tools,
    stopWhen: stepCountIs(3),
    prompt: 'Delete ticket T-123.',
  });
  // When Vulnify blocks, the tool output is { blocked: true, decision, reasons, eventId, message } and the model explains it.
  console.log(text);
}

main();
