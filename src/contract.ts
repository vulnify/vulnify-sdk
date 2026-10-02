import type { operations } from './generated/openapi';

/**
 * Decision JSON from the committed OpenAPI snapshot (`spec/openapi.json`).
 * POST /v1/events and GET /v1/events/{id} publish the same schema, and both require `finalDecision`.
 */
export type PostEvent = operations['IngestController_ingest']['responses'][200]['content']['application/json'];
export type GetEvent = operations['IngestController_status']['responses'][200]['content']['application/json'];
export type IngestRequest = operations['IngestController_ingest']['requestBody']['content']['application/json'];

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Assert<T extends true> = T;

type _postAndGetMatch = Assert<Equal<PostEvent, GetEvent>>;

export type Destination = NonNullable<IngestRequest['destination']>;
