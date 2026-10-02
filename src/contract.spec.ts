import spec from '../spec/openapi.json';

describe('committed OpenAPI snapshot', () => {
  const post = spec.paths['/v1/events'].post.responses['200'].content['application/json'].schema;
  const get = spec.paths['/v1/events/{id}'].get.responses['200'].content['application/json'].schema;

  it('gives GET /v1/events/{id} the same body as POST /v1/events', () => {
    expect(get).toEqual(post);
  });

  it('requires finalDecision on a current decision and does not document webhooks', () => {
    expect(post.properties.finalDecision.enum).toEqual(['ALLOW', 'REVIEW', 'BLOCK']);
    expect(post.required).toEqual(expect.arrayContaining(['finalDecision', 'quotaExceeded', 'sandbox', 'lgpdCategories']));
    expect(spec).not.toHaveProperty('webhooks');
  });
});
