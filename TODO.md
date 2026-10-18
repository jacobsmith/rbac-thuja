# TODO

## Automated "problematic role/permission" scan

Right now, checking a safety property (e.g. "can any role edit a published
article?" or "can any role edit an article they don't own?") means hand-writing
a Z3 test: pick an action, pick a property to pin to its "dangerous" value, call
`anyRoleCanDo`, check `sat`/`unsat`, decode the implicated role(s) if `sat`.

Goal: automate this into a scan a developer can run over their own policy
without writing bespoke tests per property. Given a policy (a `CmsRbac`/
`Encodable` instance with roles already added), automatically surface roles
that grant an action under conditions other roles in the *same* policy treat
as disqualifying — e.g. "3 of your 4 roles that grant `edit` require
`published == false`; `compliance_officer` doesn't."

**Real limitation to keep in mind**: this can only catch inconsistencies among
invariants *already partially expressed somewhere in the policy*. It can't
invent a rule nobody ever encoded (e.g. "nobody should ever delete an article"
if no role's condition references deletion at all). It's cross-role
consistency-checking, not a proof the whole system is safe in some absolute
sense.

### Shape of the solution

1. **Group conditions by `(action, property[, contextProperty])`** across the
   *entire* policy (not per-role). Every condition anywhere touching
   `(edit, published)`, every one touching `(edit, authorId/id)`, etc. This
   infers which invariants the policy seems to care about from what's already
   written, rather than requiring the developer to declare "check ownership"
   separately.

   **Revised after the 50-role stress test:** treating *every* condition in a
   group as an invariant meant one unusual role got every rule-following role
   flagged for skipping its condition. That was 356 of 518 findings (69%).
   `inferInvariants` now uses the condition the **most roles** use (each role
   counts once). Ties keep all tied conditions, so both sides get flagged, and
   a group where `true` wins has no invariant. With this rule the stress
   policy produces 77 findings, exactly its 77 deviating grants.

   Needs a new method — something like `getDistinctConditions()` — on
   `Encodable`, since it already owns `roles`.

2. **For each group, derive the "dangerous pin" from the condition's own
   shape** — essentially the opposite of `encodeCondition`:
   - `LiteralExpression` (`published == false`) implies "shouldn't happen when
     `published == true`" → pin the *negated* literal.
   - `ContextExpression` (`authorId == id`) implies "shouldn't happen when
     they differ" → pin with `.neq()` instead of `.eq()`.

   Needs a `negateCondition`-style counterpart to `encodeCondition`, dispatched
   by `.type`/`.operator` the same way.

3. **Run `anyRoleCanDo(action, ...)` with that pin**, for every group — same
   pattern as the existing `'finds a role combination that can edit a
   published article'` and `'...that can edit an article they do not own'`
   tests, just generated instead of hand-typed.

4. **Report every `sat` result**, decoded via `holdsRole` + filter (same as
   those two tests already do), as something like: "role X grants `action`
   even when [dangerous condition] holds."

### Suggested order of attack
- [x] `inferInvariants()` in `scan.ts` (was `getDistinctConditions()` on `Encodable`) — enumerate distinct
      `(action, condition-shape)` pairs actually present across all roles.
- [x] Negation is just `Not(encodeCondition(...))` on `PolicyEncoder` (was `negateCondition` on `EncodableToZ3`) — produce the
      "dangerous pin" `Bool` for a given condition, mirroring `encodeCondition`'s
      dispatch structure.
- [x] Wire the two together into a scan method (`policy.findBypasses()`)
      that loops over distinct conditions, builds the pin, and solves
      **per role** (`roleCanDo(role, action) ∧ ¬invariant`) rather than via
      `anyRoleCanDo`. Permissions are a pure union (no deny), so a role
      combination can bypass only if one of its members can alone; per-role
      solving gives exact attribution, whereas a single `anyRoleCanDo` model
      can include incidental roles and only surfaces one offender.
- [x] Decide the reporting shape — structured `Finding[]`
      (`{ role, action, invariant, id }`); human-readable text is only
      rendered in the thrown error (see below).

## Exception allowlist + `verifyNoUnapprovedBypasses()` (pre-req for extracting Thuja)

Thuja will be extracted into an npm package. Consumers should be able to
write one unit test and have Thuja do everything else:

```typescript
import { policy } from '../src/authz/policy';

it('has no unreviewed permission bypasses', async () => {
    await policy.verifyNoUnapprovedBypasses({ exceptionsFile: 'thuja.exceptions.json' });
});
```

The test passes, or throws one `Error` that lists every problem. Throwing
keeps it independent of the test runner: vitest, jest, mocha and `node:test`
all treat a rejected promise as a failure, so Thuja doesn't depend on vitest.

### Exceptions file (checked into the consumer's repo)

```jsonc
{
  "version": 1,                       // Thuja's canonicalization version
  "exceptions": {
    "compliance_officer|edit|published==false": {
      "fingerprint": "sha256:…",      // canonical JSON of that role's permissions for that action
      "reason": "Legal must amend published articles for takedowns",
      "approvedBy": "jacob",
      "approvedAt": "2026-10-18",
      "expires": "2027-04-18"         // optional
    }
  }
}
```

- Fingerprint scope = **one role's permissions for one action**. Hashing the
  whole role is too noisy (adding `create` would invalidate an approved
  `edit` bypass), and hashing the whole policy would invalidate everything.
- `version` lets a later Thuja release change its canonicalization without
  silently mass-invalidating every consumer's approvals: it can migrate the
  fingerprints, or refuse with a clear message.

### Outcomes (all hard-fail)

| Situation                                   | Result                                    |
|---------------------------------------------|-------------------------------------------|
| Finding with no exception                   | fail: new bypass, needs approval          |
| Exception whose fingerprint matches         | pass                                      |
| Exception whose fingerprint changed         | fail: permissions changed, re-review      |
| Exception with no matching finding          | fail: stale exception, remove it          |
| Exception past `expires`                    | fail                                      |
| Exception with an empty `reason`/`approvedBy` | fail                                    |
| Role declared in `roles` with no permissions | fail: unused role (typo or leftover)  |

### Update flow

`THUJA_UPDATE=1 npm test` makes `verifyNoUnapprovedBypasses` rewrite the file.
It adds stubs for new findings with blank `reason`/`approvedBy`, refreshes
the fingerprints of changed exceptions and clears their approval fields,
and removes stale exceptions. The test still fails until a human fills in
the blanks. This works like `vitest -u`, but the human has to write a
justification. Using an env var rather than a `npx thuja` CLI avoids having
to load the consumer's TypeScript policy file from outside their test runner.

Thuja should document a `CODEOWNERS` entry for `thuja.exceptions.json` as the
real approval gate. The file records the decision; code review enforces it.

### Library-shape prerequisites
- [x] **Generic schema.** `Resource`, `RbacAction`, `RbacContext`
      (`encoder.ts`) and `resourceToZ3Mapping`/`contextToZ3Mapping` are
      hardcoded to the CMS article. Consumers need to declare their own
      resource/context shape (e.g. `{ published: 'bool', authorId: 'string' }`)
      and have Thuja derive both the TS types and the Z3 sorts/constants
      from it.
- [x] **`Policy` class** as the public entry point (replacing
      `CmsRbac`/`Encodable` naming), generic over the schema only; role names come from the optional `roles` list in the schema (`string` when omitted).
- [x] **Thuja owns Z3.** `init()`, `Context` creation and symbolic
      constants all stay internal; consumers never import `z3-solver`.
- [x] **Keep Z3 off the runtime path.** Apps calling `policy.can()` in
      production shouldn't load ~30MB of wasm. Either lazy-`import()`
      z3-solver inside `verifyNoUnapprovedBypasses`, or ship verification from
      a separate entrypoint (`thuja/verify`).
- [x] **Canonical serializer** for permissions/conditions, shared by
      fingerprints and finding IDs, with deterministic key order.
- [x] **Deterministic output.** Sort findings; no `console.log` in library
      code.
- [ ] **Declared invariants** (optional `invariants` option) on top of the
      inferred ones, to catch rules no role encodes yet.

## Compound conditions (AND / OR / NOT) — done

`Condition` is now recursive (`{ type: 'And' | 'Or', conditions }`,
`{ type: 'Not', condition }`), typed against the schema at every level.
Decisions made while building it:

- **Fail-closed under `Not`:** runtime evaluation uses three-valued (Kleene)
  logic, where a comparison on a missing attribute is *unknown*, and only a
  definite `true` grants. Without this, `Not(published == true)` would grant
  on a resource with no `published`.
- **Identity:** `conditionKey` normalizes (flatten, sort, dedupe, double
  negation, constant absorption). Atomic keys are unchanged, so existing
  exceptions files stay valid. The normalizer doesn't apply De Morgan;
  semantic equivalence is Z3's job.
- **Inference votes per role:** each role's effective condition for an
  action/resource (the Or of its permissions there) is one vote. Votes for
  logically equivalent conditions are merged with Z3; a 64-sample
  truth-table signature avoids most pairwise queries. Ties name the rule
  after the shortest spelling.
- **Trivial rules:** a rule that always holds is no rule. A rule that never
  holds means "nobody may do this", so any role that can act is flagged.
- **Speed:** roles whose condition is (equivalent to) the rule skip the
  solver. On the 50-role atomic policy, 355 of 432 checks are skipped and
  the scan drops from ~700ms to ~156ms.

Possible follow-ups:
- [ ] Flag "dead" permissions whose condition can never hold.
- [ ] Builder helpers (`and(...)`, `eq(...)`) if the object literals get tiring.

### Other condition types Cedar supports, for later reference

Roughly in order of how much new territory each opens (full list researched
2026-09-27, see sources below):

- **`!=`** — trivial; just `Not(eq)`. Add `'ne'` alongside `'eq'` in the
  `operator` union.
- **Numeric comparison** (`<`, `<=`, `>`, `>=`) — maps to Z3 `Int`/`Real`
  (decidable, Simplex-style). Only needed once `Resource` gains a numeric
  field.
- **`in` (hierarchy / set membership)** — needed for role hierarchies or
  group/org-membership checks. Simple membership is easy (`Or` of
  equalities, or Z3's Array/Set theory); a *transitive* hierarchy is a bigger
  lift — likely flatten the hierarchy before encoding rather than model
  transitivity in Z3 directly.
- **`has` (attribute presence)** — only relevant if `Resource` becomes a
  union of heterogeneous shapes (see the `Resource = Post | Author | Blog`
  idea floated earlier and deliberately deferred). Not needed under the
  current "every field is always present" design.
- **`like` (wildcard string matching)** — maps to Z3's regex/`Re` theory
  (already present in `z3-solver`'s type declarations). Workable, but nudges
  toward "combined theories, watch for undecidability" territory.
- **IP address / `datetime` / `duration` extension types** — Cedar-specific,
  for AWS-style network/IAM policies. Only worth mirroring if a real need
  (e.g. "business hours only") comes up.

Sources:
- [Cedar Policy Syntax](https://docs.cedarpolicy.com/policies/syntax-policy.html)
- [Cedar Operators Reference](https://docs.cedarpolicy.com/policies/syntax-operators.html)
