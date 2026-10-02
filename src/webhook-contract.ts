import type { components } from './generated/openapi';
import type { WebhookAnomalyPayload, WebhookDecisionPayload, WebhookPayload, WebhookTestPayload } from './webhooks';

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Assert<T extends true> = T;

type Schemas = components['schemas'];

type _decision = Assert<Equal<WebhookDecisionPayload, Schemas['WebhookDecisionDelivery']>>;
type _anomaly = Assert<Equal<WebhookAnomalyPayload, Schemas['WebhookAnomalyDelivery']>>;
type _test = Assert<Equal<WebhookTestPayload, Schemas['WebhookTestDelivery']>>;
type _union = Assert<Equal<WebhookPayload, Schemas['WebhookDelivery']>>;
