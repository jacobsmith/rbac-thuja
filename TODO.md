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
- [ ] `getDistinctConditions()` on `Encodable` — enumerate distinct
      `(action, condition-shape)` pairs actually present across all roles.
- [ ] `negateCondition` (or similarly named) on `EncodableToZ3` — produce the
      "dangerous pin" `Bool` for a given condition, mirroring `encodeCondition`'s
      dispatch structure.
- [ ] Wire the two together into a scan method (e.g. `findPolicyViolations()`)
      that loops over distinct conditions, builds the pin, runs
      `anyRoleCanDo`, and collects/decodes every `sat` finding.
- [ ] Decide the reporting shape — return structured results, or just
      console-log a human-readable summary?

## Compound conditions (AND / OR / NOT)

`RbacCondition` can currently only be `true` or a single atomic comparison
(`RbacBooleanExpression` / `RbacBooleanContextExpression`). Real policies need
to combine checks — e.g. "published == false AND authorId == id" — which isn't
expressible today. This is the gap most likely to be hit first when writing an
actual policy, ahead of any new data type.

Inspired by looking at what [Cedar](https://docs.cedarpolicy.com/policies/syntax-operators.html)
supports (`&&`, `||`, `!` inside `when`/`unless` clauses).

No new Z3 theory needed — `this.z3Context.And(...)` / `Or(...)` / `Not(...)`
are already imported and used elsewhere in `EncodableToZ3.ts`.

### Shape of the solution

Make `RbacCondition` recursive:
```typescript
type RbacCondition = true | RbacBooleanExpression | RbacBooleanContextExpression
    | { type: 'And', conditions: RbacCondition[] }
    | { type: 'Or', conditions: RbacCondition[] }
    | { type: 'Not', condition: RbacCondition };
```
`encodeCondition` gets new switch cases for `'And'`/`'Or'`/`'Not'` that
recurse over `conditions`/`condition` and combine the results with the
matching Z3 combinator.

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
