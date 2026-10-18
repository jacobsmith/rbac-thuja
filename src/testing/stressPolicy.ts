// Generators and a brute-force oracle for the stress tests. Not part of the build.

import { conditionKey, evaluateCondition, normalizeCondition } from '../conditions.js';
import { Policy } from '../policy.js';
import { defineSchema, type AnyCondition, type AnyInvariant, type AnyPermission, type Attributes, type PolicySchema } from '../schema.js';

// 50 roles: 10 departments x 5 levels.
const DEPARTMENTS = ['editorial', 'finance', 'legal', 'sales', 'support', 'engineering', 'marketing', 'hr', 'compliance', 'ops'];
const LEVELS = ['intern', 'associate', 'senior', 'lead', 'director'];
export const ROLES = DEPARTMENTS.flatMap((department) => LEVELS.map((level) => `${department}_${level}`));

export const schema = defineSchema({
    roles: ROLES,
    actions: ['create', 'read', 'update', 'delete', 'publish', 'archive', 'approve', 'export'],
    resources: {
        article: { published: 'boolean', archived: 'boolean', authorId: 'string', region: 'string', status: 'string' },
        invoice: { approved: 'boolean', ownerId: 'string', department: 'string', region: 'string' },
        comment: { hidden: 'boolean', authorId: 'string' },
        report: { confidential: 'boolean', department: 'string', region: 'string' },
        profile: { active: 'boolean', userId: 'string', department: 'string' },
    },
    context: { id: 'string', region: 'string', department: 'string', authenticated: 'boolean' },
});

export type PermissionsByRole = Map<string, Array<AnyPermission>>;

export const literal = (property: string, value: boolean | string): AnyCondition => ({ type: 'LiteralExpression', property, operator: 'eq', value });
export const fromContext = (property: string, contextProperty: string): AnyCondition => ({ type: 'ContextExpression', property, operator: 'eq', contextProperty });
const and = (...conditions: Array<AnyCondition>): AnyCondition => ({ type: 'And', conditions });
const or = (...conditions: Array<AnyCondition>): AnyCondition => ({ type: 'Or', conditions });
const not = (condition: AnyCondition): AnyCondition => ({ type: 'Not', condition });

// Atomic guards per resource. Each resource attribute is compared with at most one context
// attribute, which the oracle relies on (see bruteForceFindings).
export const GUARDS: Record<string, Array<AnyCondition>> = {
    article: [literal('published', false), literal('archived', false), fromContext('authorId', 'id'), fromContext('region', 'region'), literal('status', 'draft'), literal('status', 'review')],
    invoice: [literal('approved', false), fromContext('ownerId', 'id'), fromContext('department', 'department'), fromContext('region', 'region')],
    comment: [literal('hidden', false), fromContext('authorId', 'id')],
    report: [literal('confidential', false), fromContext('department', 'department'), fromContext('region', 'region')],
    profile: [fromContext('userId', 'id'), fromContext('department', 'department'), literal('active', true)],
};

const PAIRS = Object.keys(schema.resources).flatMap((resource) => schema.actions.map((action) => ({ resource, action })));

// mulberry32: small seeded PRNG so generated policies are identical on every run.
export function prng(seed: number) {
    return () => {
        seed = (seed + 0x6D2B79F5) | 0;
        let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

/** Atomic conditions only: one house rule per action/resource, with planted deviations. */
export function generateAtomicPermissions(seed = 20261018): PermissionsByRole {
    const random = prng(seed);
    const pick = <T>(items: ReadonlyArray<T>): T => items[Math.floor(random() * items.length)] as T;

    const houseRule = new Map(PAIRS.map(({ resource, action }) => [
        `${action}|${resource}`,
        // reading articles and comments is open to everyone who can read at all
        action === 'read' && (resource === 'article' || resource === 'comment') ? true : pick(GUARDS[resource]!),
    ]));

    const permissionsByRole: PermissionsByRole = new Map();
    for (const role of ROLES) {
        const permissions: Array<AnyPermission> = [];
        const count = 6 + Math.floor(random() * 7); // 6-12 action/resource pairs per role
        const chosen = [...PAIRS].sort(() => random() - 0.5).slice(0, count);

        for (const { resource, action } of chosen) {
            const rule = houseRule.get(`${action}|${resource}`)!;
            const roll = random();
            if (roll < 0.80) {
                permissions.push({ action, resource, condition: rule });
            } else if (roll < 0.87) {
                permissions.push({ action, resource, condition: true }); // unconditional bypass
            } else if (roll < 0.94) {
                permissions.push({ action, resource, condition: pick(GUARDS[resource]!) }); // possibly a different rule
            } else {
                // the house rule OR'd with a second guard: still a bypass if the second differs
                permissions.push({ action, resource, condition: rule });
                permissions.push({ action, resource, condition: pick(GUARDS[resource]!) });
            }
        }
        permissionsByRole.set(role, permissions);
    }
    return permissionsByRole;
}

export type Variant = 'exact' | 'rewritten' | 'split' | 'stricter' | 'looser' | 'unconditional' | 'unrelated';

/**
 * Compound conditions: each action/resource gets a nested And/Or/Not house rule, and each
 * role writes it one of several ways. `variants` records which, so tests can assert intent:
 * rewritten/split/stricter roles shouldn't be flagged; looser/unconditional ones should.
 */
export function generateCompoundPermissions(seed = 20261019): { permissionsByRole: PermissionsByRole, variants: Map<string, Variant>, houseRules: Map<string, AnyCondition> } {
    const random = prng(seed);
    const pick = <T>(items: ReadonlyArray<T>): T => items[Math.floor(random() * items.length)] as T;
    const shuffle = <T>(items: ReadonlyArray<T>): Array<T> => [...items].sort(() => random() - 0.5);

    // A random compound condition over a resource's guards, `depth` levels deep.
    const compound = (resource: string, depth: number): AnyCondition => {
        if (depth === 0) {
            const atom = pick(GUARDS[resource]!);
            return random() < 0.2 ? not(atom) : atom;
        }
        const width = 2 + Math.floor(random() * 2);
        const children = Array.from({ length: width }, () => compound(resource, random() < 0.5 ? depth - 1 : 0));
        return random() < 0.5 ? and(...children) : or(...children);
    };

    // Logically equivalent rewrites the normalizer can't see through on its own (De Morgan,
    // double negation, reordering), so recognising them needs Z3.
    const rewrite = (condition: AnyCondition): AnyCondition => {
        if (condition === true) {
            return true;
        }
        switch (condition.type) {
            case 'And':
            case 'Or': {
                const children = shuffle(condition.conditions.map(rewrite));
                if (random() < 0.5) {
                    const dual = children.map(not);
                    return not(condition.type === 'And' ? or(...dual) : and(...dual));
                }
                return condition.type === 'And' ? and(...children) : or(...children);
            }
            case 'Not': {
                return not(rewrite(condition.condition));
            }
            default: {
                return random() < 0.3 ? not(not(condition)) : condition;
            }
        }
    };

    const houseRules = new Map(PAIRS.map(({ resource, action }) => [`${action}|${resource}`, compound(resource, 2)]));
    const permissionsByRole: PermissionsByRole = new Map();
    const variants = new Map<string, Variant>();

    for (const role of ROLES) {
        const permissions: Array<AnyPermission> = [];
        const count = 6 + Math.floor(random() * 7);

        for (const { resource, action } of shuffle(PAIRS).slice(0, count)) {
            const rule = houseRules.get(`${action}|${resource}`)!;
            const extra = pick(GUARDS[resource]!);
            const roll = random();
            let variant: Variant;

            if (roll < 0.62) {
                variant = 'exact';
                permissions.push({ action, resource, condition: rule });
            } else if (roll < 0.72) {
                variant = 'rewritten';
                permissions.push({ action, resource, condition: rewrite(rule) });
            } else if (roll < 0.76 && rule !== true && rule.type === 'Or') {
                variant = 'split'; // one permission per disjunct: the union is the rule
                rule.conditions.forEach((condition) => permissions.push({ action, resource, condition }));
            } else if (roll < 0.83) {
                variant = 'stricter';
                permissions.push({ action, resource, condition: and(rule, extra) });
            } else if (roll < 0.91) {
                variant = 'looser';
                permissions.push({ action, resource, condition: or(rule, extra) });
            } else if (roll < 0.95) {
                variant = 'unconditional';
                permissions.push({ action, resource, condition: true });
            } else {
                variant = 'unrelated';
                permissions.push({ action, resource, condition: compound(resource, 2) });
            }
            variants.set(`${role}|${action}|${resource}`, variant);
        }
        permissionsByRole.set(role, permissions);
    }
    return { permissionsByRole, variants, houseRules };
}

export function buildPolicy(permissionsByRole: PermissionsByRole, policySchema: PolicySchema = schema) {
    return new Policy(policySchema, Object.fromEntries(permissionsByRole) as never);
}

export function countPermissions(permissionsByRole: PermissionsByRole) {
    return [...permissionsByRole.values()].reduce((sum, permissions) => sum + permissions.length, 0);
}

/**
 * Independent oracle for `findBypasses`: no Z3, no normalizer-based equivalence. It
 * enumerates every concrete resource/context assignment and uses the runtime evaluator.
 *
 * Conditions only compare for equality, so a string attribute only needs the literals the
 * policy uses plus enough fresh values to make any compared pair equal or unequal. Each
 * attribute here is compared with at most one context attribute (see GUARDS), so two
 * fresh values suffice. With every assignment enumerated, two conditions are equivalent
 * exactly when their truth tables match.
 */
export function bruteForceFindings(permissionsByRole: PermissionsByRole, policySchema: PolicySchema = schema): Set<string> {
    const findings = new Set<string>();
    const { truthTable } = enumerator(permissionsByRole, policySchema);

    for (const resource of Object.keys(policySchema.resources)) {
        for (const action of policySchema.actions) {
            // each role's effective condition: the Or of its permissions here
            // guards that apply here are enforced on every grant (public pairs may be exempt)
            const isPublicPair = (policySchema.public ?? []).some((entry) => entry.resource === resource
                && (typeof entry.action === 'string' ? entry.action === action : entry.action.includes(action)));
            const guardTables = (policySchema.guards ?? [])
                .filter((guard) => !(guard.except === 'public' && isPublicPair))
                .map((guard) => truthTable(guard.requires, resource));
            const withGuards = (table: string) => guardTables.reduce((acc, guard) =>
                [...acc].map((bit, i) => bit === '1' && guard[i] === '1' ? '1' : '0').join(''), table);

            // each role's effective condition: the Or of its permissions here. Rules are inferred
            // from the conditions as written; what a role can actually do also needs the guards.
            const roleRules = new Map<string, { key: string, table: string, grant: string }>();
            for (const [role, permissions] of permissionsByRole) {
                const conditions = permissions.filter((p) => p.action === action && p.resource === resource).map((p) => p.condition);
                if (conditions.length > 0) {
                    const effective: AnyCondition = { type: 'Or', conditions };
                    const table = truthTable(effective, resource);
                    roleRules.set(role, { key: conditionKey(normalizeCondition(effective)), table, grant: withGuards(table) });
                }
            }

            // classes of equivalent rules, named after their most common spelling (ties: shortest, then alphabetical)
            const classes = new Map<string, { roles: number, spellings: Map<string, number> }>();
            for (const { key, table } of roleRules.values()) {
                const entry = classes.get(table) ?? { roles: 0, spellings: new Map<string, number>() };
                entry.roles++;
                entry.spellings.set(key, (entry.spellings.get(key) ?? 0) + 1);
                classes.set(table, entry);
            }
            const top = Math.max(0, ...[...classes.values()].map((entry) => entry.roles));
            const rules = [...classes]
                .filter(([table, entry]) => entry.roles === top && table.includes('0')) // an always-true rule is no rule
                .map(([table, entry]) => {
                    const [name] = [...entry.spellings].sort(([a, countA], [b, countB]) => countB - countA || a.length - b.length || (a < b ? -1 : a > b ? 1 : 0))[0]!;
                    return { name, table };
                });

            const holds = (table: string) => (i: number) => table[i] === '1';
            const someWorld = (predicate: (i: number) => boolean) => {
                const worlds = rules[0]?.table.length ?? [...roleRules.values()][0]?.table.length ?? 0;
                for (let i = 0; i < worlds; i++) {
                    if (predicate(i)) { return true; }
                }
                return false;
            };

            // declared invariants for this pair
            const declared = (policySchema.invariants ?? []).filter((invariant) => invariant.resource === resource
                && (typeof invariant.action === 'string' ? invariant.action === action : invariant.action.includes(action)));

            const notAllowed = new Set<string>();
            for (const invariant of declared) {
                if (!invariant.onlyRoles) { continue; }
                for (const [role, rule] of roleRules) {
                    if (!invariant.onlyRoles.includes(role) && rule.grant.includes('1')) {
                        notAllowed.add(role);
                        findings.add(`${role}|${action}|${resource}|invariant:${invariant.name}`);
                    }
                }
            }

            const conditionInvariants = declared.filter((invariant) => invariant.requires !== undefined);
            if (conditionInvariants.length > 0) {
                const requiredTables = conditionInvariants.map((invariant) => truthTable(invariant.requires!, resource));
                conditionInvariants.forEach((invariant, n) => {
                    const required = holds(requiredTables[n]!);
                    for (const [role, rule] of roleRules) {
                        if (invariant.onlyRoles && !invariant.onlyRoles.includes(role)) { continue; }
                        const grants = holds(rule.grant);
                        if (someWorld((i) => grants(i) && !required(i))) {
                            findings.add(`${role}|${action}|${resource}|invariant:${invariant.name}`);
                        }
                    }
                });
                // loose: the declared conditions together allow something the inferred rule doesn't
                const names = conditionInvariants.map((invariant) => invariant.name).sort().join('+');
                for (const { name, table } of rules) {
                    const rule = holds(table);
                    if (someWorld((i) => requiredTables.every((t) => t[i] === '1') && guardTables.every((t) => t[i] === '1') && !rule(i))) {
                        findings.add(`invariant:${names}|${action}|${resource}|inferred:${name}`);
                    }
                }
                continue;
            }

            for (const [role, rule] of roleRules) {
                if (notAllowed.has(role)) { continue; }
                for (const { name, table } of rules) {
                    // a bypass: some assignment where the role grants but the rule doesn't hold
                    if ([...rule.grant].some((bit, i) => bit === '1' && table[i] === '0')) {
                        findings.add(`${role}|${action}|${resource}|inferred:${name}`);
                    }
                }
            }
        }
    }
    return findings;
}

/** Truth tables over every concrete assignment for a resource (see bruteForceFindings). */
export function enumerator(permissionsByRole: PermissionsByRole, policySchema: PolicySchema = schema) {
    const all = [...permissionsByRole.values()].flat();
    const literals = new Set<string>();
    const collect = (condition: AnyCondition) => {
        if (condition === true) { return; }
        switch (condition.type) {
            case 'And': case 'Or': { condition.conditions.forEach(collect); return; }
            case 'Not': { collect(condition.condition); return; }
            case 'LiteralExpression': case 'ContextLiteralExpression': { if (typeof condition.value === 'string') { literals.add(condition.value); } return; }
            default: { return; }
        }
    };
    all.forEach((permission) => collect(permission.condition));
    (policySchema.invariants ?? []).forEach((invariant) => invariant.requires !== undefined && collect(invariant.requires));
    (policySchema.guards ?? []).forEach((guard) => collect(guard.requires));
    const stringDomain = ['v1', 'v2', ...literals];

    const assignments = (attributes: Attributes): Array<Record<string, boolean | string>> =>
        Object.entries(attributes).reduce<Array<Record<string, boolean | string>>>(
            (partials, [name, type]) => partials.flatMap((partial) =>
                (type === 'boolean' ? [true, false] : stringDomain).map((value) => ({ ...partial, [name]: value }))),
            [{}],
        );

    const worldsByResource = new Map<string, Array<{ resourceValue: Record<string, boolean | string>, contextValue: Record<string, boolean | string> }>>();
    const worldsFor = (resource: string) => {
        let worlds = worldsByResource.get(resource);
        if (!worlds) {
            const attributes = policySchema.resources[resource]!;
            worlds = assignments(attributes).flatMap((resourceValue) =>
                assignments(policySchema.context).map((contextValue) => ({ resourceValue, contextValue })));
            worldsByResource.set(resource, worlds);
        }
        return worlds;
    };

    return {
        worldCount: (resource: string) => worldsFor(resource).length,
        truthTable: (condition: AnyCondition, resource: string) => worldsFor(resource)
            .map(({ resourceValue, contextValue }) => evaluateCondition(condition, resourceValue, contextValue) ? '1' : '0').join(''),
    };
}

export type InvariantStyle = 'exact' | 'looser' | 'stricter' | 'allowlist';

/**
 * Declared invariants for a compound policy: some pairs declare the house rule exactly,
 * some a looser or stricter version of it, and some an allowlist of a few roles.
 * Stricter invariants model the majority being wrong: most roles follow the house rule,
 * but the declared rule demands more.
 */
export function generateInvariants(
    permissionsByRole: PermissionsByRole,
    houseRules: Map<string, AnyCondition>,
    seed = 20261020,
): { invariants: Array<AnyInvariant>, styles: Map<string, InvariantStyle> } {
    const random = prng(seed);
    const invariants: Array<AnyInvariant> = [];
    const styles = new Map<string, InvariantStyle>();

    for (const [pairKey, rule] of houseRules) {
        const [action, resource] = pairKey.split('|') as [string, string];
        const roll = random();
        const extra = GUARDS[resource]![Math.floor(random() * GUARDS[resource]!.length)]!;
        const name = `${resource}-${action}`;
        let style: InvariantStyle | undefined;

        if (roll < 0.25) {
            style = 'exact';
            invariants.push({ name, action, resource, requires: rule });
        } else if (roll < 0.40) {
            style = 'looser';
            invariants.push({ name, action, resource, requires: or(rule, extra) });
        } else if (roll < 0.55) {
            style = 'stricter';
            invariants.push({ name, action, resource, requires: and(rule, extra) });
        } else if (roll < 0.65) {
            style = 'allowlist';
            const holders = [...permissionsByRole].filter(([, permissions]) => permissions.some((p) => p.action === action && p.resource === resource)).map(([role]) => role);
            invariants.push({ name, action, resource, onlyRoles: holders.slice(0, Math.ceil(holders.length / 2)) });
        }
        if (style) {
            styles.set(pairKey, style);
        }
    }
    return { invariants, styles };
}

/**
 * Adds context-only conditions to a compound policy: some grants additionally require (or
 * offer an alternative via) `context.authenticated`, so guards and context-only conditions
 * interact with everything else.
 */
export function withContextConditions(permissionsByRole: PermissionsByRole, seed = 20261021): PermissionsByRole {
    const random = prng(seed);
    const authenticated = (value: boolean): AnyCondition => ({ type: 'ContextLiteralExpression', contextProperty: 'authenticated', operator: 'eq', value });
    return new Map([...permissionsByRole].map(([role, permissions]) => [role, permissions.map((permission) => {
        const roll = random();
        if (roll < 0.15) {
            return { ...permission, condition: and(permission.condition, authenticated(true)) }; // redundant where guarded
        }
        if (roll < 0.22) {
            return { ...permission, condition: or(permission.condition, authenticated(true)) }; // any signed-in user
        }
        if (roll < 0.25) {
            return { ...permission, condition: authenticated(false) }; // anonymous only
        }
        return permission;
    })]));
}
