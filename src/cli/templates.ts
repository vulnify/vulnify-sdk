/** Example files from contract C4, with the API condition grammar. */
export const EXAMPLE_POLICY_YAML = `# Policies in this tree are safe to commit.
# API keys are not stored here. \`vulnify login\` writes ~/.config/vulnify/credentials.json (mode 0600).
#
# spec.action is the action family (ANY, READ, WRITE, DELETE, EXPORT).
# A specific event action such as EXPORT_DATA belongs in condition.action.
# spec.resource is a resource type. The event resource name belongs in a PolicyTest input.
# condition.minRecords means recordsAffected >= that number. More than 1000 records is 1001.
apiVersion: vulnify.io/v1
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

export const EXAMPLE_TEST_YAML = `# input.action is the event action. input.resource is the resource name.
# expect.policy is the metadata.name of a Policy document.
apiVersion: vulnify.io/v1
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

export const GITIGNORE_HINT = `# Policies and tests in this directory are safe to commit.
# Do not commit API keys. \`vulnify login\` writes ~/.config/vulnify/credentials.json
# with mode 0600, outside this repository.
`;

export const GITIGNORE_STDOUT =
  'Do not commit API keys. vulnify login stores them in ~/.config/vulnify/credentials.json (mode 0600), outside this repository. A hint was written to vulnify/.gitignore.\n';
