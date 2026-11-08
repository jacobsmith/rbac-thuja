# Thuja

Role-based access control for TypeScript with a built-in safety check. You write the policy as
plain data. At runtime, `policy.can()` answers permission checks. In your test suite, the Z3 SMT
solver checks the policy for **bypasses**: roles that can perform an action under conditions the
rest of the policy treats as off-limits.

```text
compliance_officer grants edit on article even when published == false does not hold
(3 of 4 roles that grant edit require it)
```

Thuja reports this as a test failure. It passes again only after someone fixes the policy or
records a reviewed, signed-off exception.

> Status: pre-release. This repo is where Thuja is being built before it moves to its own npm
> package. The API may still change.

## Why

Most permission bugs aren't in the authorization engine. They come from one role that was
granted a little too much. Code review rarely catches these, because nobody reads all the roles
side by side. Thuja does that comparison for you:

- **Inferred rules.** For each action and resource, Thuja finds the condition that most roles
  use (for example, "edit only when `published == false`") and flags any role that can act
  without it.
- **Declared rules.** You can also state invariants directly ("edit requires
  `published == false`", "only `publisher` may publish"). These replace inference for that
  action.
- **Proofs, not samples.** Every check is a Z3 query over every possible resource and context
  value. Thuja doesn't generate test cases.

## Quick start

```bash
npm install
npm test        # vitest
npm run build   # tsc → dist/
npm run bench   # scan benchmarks
```

### 1. Describe the shape of your domain

```ts
import { defineSchema } from './src/index.js';

export const cmsSchema = defineSchema({
    roles: ['writer', 'editor', 'publisher', 'compliance_officer'],
    actions: ['create', 'read', 'edit', 'publish', 'unpublish'],
    resources: {
        article: { published: 'boolean', authorId: 'string' },
    },
    context: { id: 'string' }, // attributes of the acting user/request
});
```

From this one object, Thuja derives both the TypeScript types and the Z3 encoding. You can't
misspell a role, action or attribute anywhere else.

### 2. Write the policy

The primary way to write a policy is resource-centric, so every role's condition for an action
sits side by side:

```ts
import { definePolicy } from './src/index.js';

const draft = { published: false };
const live = { published: true };

export const policy = definePolicy(cmsSchema, ({ resource }) => {
    resource('article', (article) => {
        article.create(['writer']);
        article.read({ writer: live, editor: live, publisher: live, compliance_officer: live });
        article.edit({ writer: draft, editor: draft, compliance_officer: true });
        article.publish(['publisher']);
        article.unpublish({ publisher: live });
    });
});
```

- Shorthand `{ published: false, authorId: ctx.id }` means every listed attribute must equal its
  value. The value can be a literal or a context attribute (ownership checks).
- `any(...)`, `all(...)`, `not(...)`, `context({...})` and `raw(...)` build compound
  conditions. They come in the second argument of the `resource` callback.
- A chained form, `resource('article').can('edit', ['writer'], draft)`, is also available.
- Granting the same role/action/resource twice throws. Combine the conditions with `any(...)`
  instead, so a policy never widens itself by accident.

You can also skip the DSL. `new Policy(schema, permissionsByRole)` accepts the raw data form
directly, which can come from a database or a config file. `definePolicy` compiles to that same
form. See [`src/examples/cms.ts`](src/examples/cms.ts).

### 3. Check permissions at runtime

```ts
const alice = { roles: ['writer'], id: 'u1' };

policy.can(alice, 'create');                                              // true
policy.can(alice, 'edit', { $type: 'article', published: true, authorId: 'u1' }); // false
```

`can()` doesn't load Z3. Apps that only check permissions never pull in the solver's wasm.
Conditions on missing attributes are *unknown*, and only a definite `true` grants (three-valued
logic, so it fails closed under `not`).

### 4. Verify the policy in a test

```ts
import { it } from 'vitest';
import { policy } from './policy';

it('has no unreviewed permission bypasses', async () => {
    await policy.verifyNoUnapprovedBypasses({ exceptionsFile: 'thuja.exceptions.json' });
});
```

That one test is the whole integration. The promise rejects with a `ThujaVerificationError` that
lists every problem, so any runner works (vitest, jest, mocha, `node:test`).

## Exceptions: approving a bypass on purpose

Some bypasses are intentional. Compliance may need to amend published articles for legal
takedowns, for example. You record those in a checked-in exceptions file:

```json
{
  "version": 1,
  "exceptions": {
    "compliance_officer|edit|article|inferred:published==false": {
      "fingerprint": "sha256:190e17…",
      "reason": "Compliance must amend published articles for legal takedowns.",
      "approvedBy": "jacob",
      "approvedAt": "2026-10-18",
      "expires": "2027-04-18"
    }
  }
}
```

The fingerprint covers **one role's permissions for one action**. Changing that grant
invalidates the approval, but adding unrelated permissions to the role doesn't.

| Situation                                      | Result                               |
|------------------------------------------------|--------------------------------------|
| Finding with no exception                      | fail: new bypass, needs approval     |
| Exception whose fingerprint matches            | pass                                 |
| Exception whose fingerprint changed            | fail: permissions changed, re-review |
| Exception with no matching finding             | fail: stale exception, remove it     |
| Exception past `expires`                       | fail                                 |
| Exception with an empty `reason`/`approvedBy`  | fail                                 |
| Declared role with no permissions              | fail: unused role (typo or leftover) |

**Updating the file.** Run `THUJA_UPDATE=1 npm test`. Thuja adds stubs for new findings,
refreshes changed fingerprints (and clears their approvals) and removes stale entries. The test
keeps failing until a person fills in `reason` and `approvedBy`. It works like snapshot
updating, except a person has to write the justification. Add a `CODEOWNERS` entry for the
exceptions file to make approval a real review gate.

## Declared invariants and guards

You can declare rules up front instead of relying on inference:

```ts
import { contextIs, defineSchema } from './src/index.js';

const governedCmsSchema = defineSchema({
    ...cmsSchema,
    context: { id: 'string', authenticated: 'boolean' },
    public: [{ action: 'read', resource: 'article' }],
    guards: [{ name: 'signed-in', requires: contextIs('authenticated', true), except: 'public' }],
    invariants: [
        {
            name: 'edit-unpublished-only',
            action: 'edit',
            resource: 'article',
            requires: { type: 'LiteralExpression', property: 'published', operator: 'eq', value: false },
        },
        { name: 'only-publishers-publish', action: ['publish', 'unpublish'], resource: 'article', onlyRoles: ['publisher'] },
    ],
});
```

- **`requires`** is a condition every granting role must imply. It replaces inference for that
  action. Thuja still warns when the declared rule is looser than what most roles actually
  require.
- **`onlyRoles`** is an allowlist of roles that may grant the action at all.
- **`guards`** are enforced by `can()` on top of each role's grant (for example, "signed-in users
  only, except for public actions").

## Limits

Inference only catches inconsistencies among rules the policy already partly expresses. If no
role ever conditions an action on something, Thuja can't invent that rule. Declare it as an
invariant. Thuja checks roles for consistency with each other; it doesn't prove the system is
safe in an absolute sense.

Conditions currently support equality on `boolean` and `string` attributes, comparisons against
context attributes, and `And`/`Or`/`Not`. Numeric comparison, set membership and hierarchies are
on the roadmap ([TODO.md](TODO.md)).

## Layout

| Path                  | What it holds                                                   |
|-----------------------|-----------------------------------------------------------------|
| `src/schema.ts`       | `defineSchema`, types derived from the schema                   |
| `src/dsl.ts`          | `definePolicy`, the resource-centric DSL                        |
| `src/policy.ts`       | `Policy`: `can()`, `findBypasses()`, `verifyNoUnapprovedBypasses()` |
| `src/conditions.ts`   | Condition evaluation and canonical keys                         |
| `src/PolicyEncoder.ts`| Z3 encoding of a policy (loaded lazily)                         |
| `src/scan.ts`         | Rule inference and the bypass scan                              |
| `src/verify.ts`       | Exceptions file handling                                        |
| `src/examples/`       | A worked CMS policy, written both ways, with exceptions files   |
| `src/stress.test.ts`  | 50-role stress policies checked against a brute-force oracle    |
