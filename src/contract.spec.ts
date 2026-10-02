import spec from '../spec/openapi.json';

describe('committed OpenAPI snapshot', () => {
  const post = spec.paths['/v1/events'].post.responses['200'].content['application/json'].schema;
  const get = spec.paths['/v1/events/{id}'].get.responses['200'].content['application/json'].schema;

  it('gives GET /v1/events/{id} the same body as POST /v1/events', () => {
    expect(get).toEqual(post);
  });

  it('requires finalDecision and documents decision, anomaly, and test webhooks', () => {
    expect(post.properties.finalDecision.enum).toEqual(['ALLOW', 'REVIEW', 'BLOCK']);
    expect(post.required).toEqual(expect.arrayContaining(['finalDecision', 'quotaExceeded', 'sandbox', 'lgpdCategories']));
    expect(Object.keys(spec.webhooks).sort()).toEqual(['anomaly', 'decision', 'test']);
    const signature = spec.webhooks.decision.post.parameters.find((parameter) => parameter.name === 'X-Vulnify-Signature');
    expect(signature.schema.pattern).toBe('^t=[0-9]+,v1=[0-9a-f]{64}$');
    expect(spec.components.schemas.WebhookDecisionData.required).toEqual(expect.arrayContaining(['decision', 'finalDecision']));
    expect(spec.components.schemas.WebhookDecisionDelivery.required).toContain('eventId');
  });
});
