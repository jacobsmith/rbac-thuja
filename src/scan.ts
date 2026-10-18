import { createHash } from "node:crypto";
import type { Bool, init } from "z3-solver";
import { conditionKey, evaluateCondition, normalizeCondition } from "./conditions.js";
import { PolicyEncoder, type EncodablePolicy } from "./PolicyEncoder.js";
import type { AnyCondition, Attributes } from "./schema.js";

export type FindingKind =
    /** A role can act without satisfying a declared invariant's `requires`. */
    | 'invariant'
    /** A role outside an invariant's `onlyRoles` can act. */
    | 'not-allowed'
    /** No invariant declares conditions here, and a role deviates from the inferred rule. */
    | 'inferred'
    /** A declared invariant allows something the inferred rule (what most roles require) doesn't. */
    | 'loose-invariant';

export type Finding = {
    /**
     * Stable key for the exceptions file:
     * `role|action|resource|invariant:<name>` for 'invariant' and 'not-allowed',
     * `role|action|resource|inferred:<rule>` for 'inferred',
     * `invariant:<names>|action|resource|inferred:<rule>` for 'loose-invariant'.
     */
    id: string,
    kind: FindingKind,
    /** The role at fault; absent for 'loose-invariant', which is about the invariant itself. */
    role?: string,
    action: string,
    resource: string,
    /** Declared invariant name(s), joined with "+" when several cover the pair. */
    invariant?: string,
    /** The inferred rule, as `conditionKey`. */
    inferredRule?: string,
    /** One sentence for humans. */
    description: string,
    /** Hash of everything the finding depends on; when it changes, approvals go stale. */
    fingerprint: string,
};

let z3: ReturnType<typeof init> | undefined;

// Dynamic import so z3-solver's wasm is only loaded when a scan actually runs.
function loadZ3() {
    z3 ??= import("z3-solver").then((module) => module.init());
    return z3;
}

export type RoleRule = {
    /** `conditionKey` of `condition`. */
    key: string,
    /** The role's effective condition here: the Or of its permissions' conditions, normalized. */
    condition: AnyCondition,
};

export type InferredRuleGroup = {
    action: string,
    resource: string,
    /** Every role with at least one permission for this action/resource. */
    roleRules: Map<string, RoleRule>,
    /** The inferred rule(s), by key. More than one only when conditions tie. */
    conditions: Map<string, AnyCondition>,
    /** For each rule, the keys of every role condition known to be equivalent to it. */
    equivalentKeys: Map<string, Set<string>>,
};

/** Decides whether two conditions on `resource` are logically equivalent. */
export type Equivalence = (a: AnyCondition, b: AnyCondition, resource: string) => Promise<boolean>;

/**
 * Invariants are inferred from the policy itself. For each action/resource, every role's
 * effective condition (the Or of its permissions there) is one vote, and the condition with
 * the most votes is the rule, so only roles that deviate from it are flagged. Ties keep all
 * tied conditions (we can't tell which side is unusual, so both get flagged), and when
 * unconditional access is the most common there is no rule.
 *
 * Votes are grouped by normalized key. Given `equivalent`, votes for differently written but
 * logically equivalent conditions are merged too, e.g. `!(published==true)` and
 * `published==false`. A cheap truth-table signature over sample values rules out most
 * non-equivalent pairs before `equivalent` is asked.
 */
export async function inferRules(policy: EncodablePolicy, equivalent?: Equivalence): Promise<Map<string, InferredRuleGroup>> {
    const groups = new Map<string, InferredRuleGroup>();
    const sampler = new WorldSampler(policy);

    for (const [groupKey, { action, resource, roleRules }] of collectRoleRules(policy)) {
        // syntactic buckets: roles whose effective conditions normalize to the same key
        const buckets = new Map<string, { condition: AnyCondition, roles: Array<string> }>();
        for (const [role, rule] of roleRules) {
            const bucket = buckets.get(rule.key) ?? { condition: rule.condition, roles: [] };
            bucket.roles.push(role);
            buckets.set(rule.key, bucket);
        }

        // semantic classes: largest bucket first, so a class is named after its most common
        // spelling (ties: the shortest, then alphabetical)
        const ordered = [...buckets.entries()].sort(([keyA, a], [keyB, b]) =>
            b.roles.length - a.roles.length || keyA.length - keyB.length || (keyA < keyB ? -1 : keyA > keyB ? 1 : 0));
        const classes: Array<{ key: string, condition: AnyCondition, signature: string, keys: Set<string>, roles: number }> = [];

        for (const [key, bucket] of ordered) {
            const signature = sampler.signature(bucket.condition, resource);
            let match: typeof classes[number] | undefined;
            if (equivalent) {
                for (const candidate of classes) {
                    if (candidate.signature === signature && await equivalent(candidate.condition, bucket.condition, resource)) {
                        match = candidate;
                        break;
                    }
                }
            }
            if (match) {
                match.keys.add(key);
                match.roles += bucket.roles.length;
            } else {
                classes.push({ key, condition: bucket.condition, signature, keys: new Set([key]), roles: bucket.roles.length });
            }
        }

        // A rule that always holds isn't a rule: most roles are effectively unconditional here.
        // (A rule that never holds stays: "nobody may do this", so any role that can is flagged.)
        const isTautology = async (c: typeof classes[number]) => {
            if (c.keys.has('true')) {
                return true;
            }
            return equivalent !== undefined && !c.signature.includes('0') && await equivalent(c.condition, true, resource);
        };
        const mostVotes = Math.max(...classes.map((c) => c.roles));
        const winners: typeof classes = [];
        for (const c of classes.filter((c) => c.roles === mostVotes)) {
            if (!await isTautology(c)) {
                winners.push(c);
            }
        }
        if (winners.length === 0) {
            continue;
        }

        groups.set(groupKey, {
            action,
            resource,
            roleRules,
            conditions: new Map(winners.map((c) => [c.key, c.condition])),
            equivalentKeys: new Map(winners.map((c) => [c.key, c.keys])),
        });
    }

    return groups;
}

export function collectRoleRules(policy: EncodablePolicy) {
    const groups = new Map<string, { action: string, resource: string, roleRules: Map<string, RoleRule> }>();
    const conditionsByGroupRole = new Map<string, Map<string, Array<AnyCondition>>>();

    for (const role of policy.getRoles()) {
        for (const permission of policy.getPermissions(role)) {
            const groupKey = `${permission.action}|${permission.resource}`;
            if (!groups.has(groupKey)) {
                groups.set(groupKey, { action: permission.action, resource: permission.resource, roleRules: new Map() });
                conditionsByGroupRole.set(groupKey, new Map());
            }
            const byRole = conditionsByGroupRole.get(groupKey)!;
            byRole.set(role, [...(byRole.get(role) ?? []), permission.condition]);
        }
    }

    for (const [groupKey, byRole] of conditionsByGroupRole) {
        for (const [role, conditions] of byRole) {
            const condition = normalizeCondition({ type: 'Or', conditions });
            groups.get(groupKey)!.roleRules.set(role, { key: conditionKey(condition), condition });
        }
    }

    return groups;
}

/**
 * Deterministic sample assignments per resource, used to compute truth-table signatures.
 * Conditions only compare for equality, so string attributes draw from the literals the
 * policy uses plus two values it never mentions.
 */
class WorldSampler {
    private static readonly SAMPLES = 64;
    private worlds = new Map<string, Array<{ resource: Record<string, unknown>, context: Record<string, unknown> }>>();
    private policy: EncodablePolicy;

    constructor(policy: EncodablePolicy) {
        this.policy = policy;
    }

    signature(condition: AnyCondition, resource: string): string {
        return this.worldsFor(resource).map((world) => evaluateCondition(condition, world.resource, world.context) ? '1' : '0').join('');
    }

    private worldsFor(resource: string) {
        let worlds = this.worlds.get(resource);
        if (worlds) {
            return worlds;
        }

        const literals = new Set<string>(['\u0000thuja:a', '\u0000thuja:b']);
        const collect = (condition: AnyCondition) => {
            if (condition === true) { return; }
            switch (condition.type) {
                case 'And': case 'Or': { condition.conditions.forEach(collect); return; }
                case 'Not': { collect(condition.condition); return; }
                case 'LiteralExpression': { if (typeof condition.value === 'string') { literals.add(condition.value); } return; }
                case 'ContextExpression': { return; }
            }
        };
        for (const role of this.policy.getRoles()) {
            this.policy.getPermissions(role).filter((p) => p.resource === resource).forEach((p) => collect(p.condition));
        }

        const strings = [...literals].sort();
        let seed = 0x9E3779B9;
        const random = () => {
            seed = (seed + 0x6D2B79F5) | 0;
            let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
            t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
            return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
        };
        const assign = (attributes: Attributes) => Object.fromEntries(Object.entries(attributes).map(([name, type]) =>
            [name, type === 'boolean' ? random() < 0.5 : strings[Math.floor(random() * strings.length)]]));

        const attributes = this.policy.schema.resources[resource] ?? {};
        worlds = Array.from({ length: WorldSampler.SAMPLES }, () => ({ resource: assign(attributes), context: assign(this.policy.schema.context) }));
        this.worlds.set(resource, worlds);
        return worlds;
    }
}

export function permissionsFingerprint(policy: EncodablePolicy, role: string, action: string, resource: string, ...extra: Array<string>): string {
    const conditions = policy.getPermissions(role)
        .filter((permission) => permission.action === action && permission.resource === resource)
        .map((permission) => conditionKey(permission.condition));
    return hash({ action, resource, conditions: [...new Set(conditions)].sort(), ...(extra.length > 0 ? { extra } : {}) });
}

function hash(value: unknown): string {
    return `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;
}

/** A declared invariant, expanded to one entry per action it covers. */
type DeclaredInvariant = {
    name: string,
    requires?: AnyCondition,
    onlyRoles?: ReadonlyArray<string>,
    /** Canonical form of the definition, part of every fingerprint that depends on it. */
    definition: string,
};

function declaredInvariantsByPair(policy: EncodablePolicy): Map<string, Array<DeclaredInvariant>> {
    const byPair = new Map<string, Array<DeclaredInvariant>>();
    for (const invariant of policy.schema.invariants ?? []) {
        const declared: DeclaredInvariant = {
            name: invariant.name,
            ...(invariant.requires !== undefined ? { requires: invariant.requires } : {}),
            ...(invariant.onlyRoles !== undefined ? { onlyRoles: invariant.onlyRoles } : {}),
            definition: JSON.stringify({
                requires: invariant.requires === undefined ? null : conditionKey(invariant.requires),
                onlyRoles: invariant.onlyRoles === undefined ? null : [...invariant.onlyRoles].sort(),
            }),
        };
        const actions = typeof invariant.action === 'string' ? [invariant.action] : invariant.action;
        for (const action of actions) {
            const pairKey = `${action}|${invariant.resource}`;
            byPair.set(pairKey, [...(byPair.get(pairKey) ?? []), declared]);
        }
    }
    return byPair;
}

export type ScanStats = {
    /** Action/resource pairs some role has a permission for. */
    pairs: number,
    /** Of those, pairs where a declared invariant's `requires` replaced inference. */
    declaredPairs: number,
    /** Role-vs-rule questions answered by Z3. */
    solverChecks: number,
    /** Role-vs-rule questions skipped because the role uses (an equivalent of) the rule itself. */
    skippedChecks: number,
    /** Z3 queries spent merging equivalent conditions during inference. */
    equivalenceChecks: number,
};

export type ScanResult = {
    findings: Array<Finding>,
    /** Invariants whose `requires` always holds and that have no `onlyRoles`: they can never catch anything. */
    vacuousInvariants: Array<string>,
    stats: ScanStats,
};

export async function findBypasses(policy: EncodablePolicy): Promise<Array<Finding>> {
    return (await scanPolicy(policy)).findings;
}

export async function scanPolicy(policy: EncodablePolicy): Promise<ScanResult> {
    const { Context } = await loadZ3();
    const z3Context = new Context('main');
    const encoder = new PolicyEncoder(policy, z3Context);
    const solver = new z3Context.Solver();
    const findings: Array<Finding> = [];
    const stats: ScanStats = { pairs: 0, declaredPairs: 0, solverChecks: 0, skippedChecks: 0, equivalenceChecks: 0 };

    const isSat = async (...assertions: Array<Bool>) => {
        solver.push();
        assertions.forEach((assertion) => solver.add(assertion));
        try {
            // "unknown" isn't an answer, so asking again can't produce a wrong one; Z3 can give
            // up transiently (e.g. when interrupted), so retry once before failing.
            let result = await solver.check();
            if (result === 'unknown') {
                result = await solver.check();
            }
            if (result === 'unknown') {
                throw new Error(`Z3 could not decide a policy question (reason: ${solver.reasonUnknown()}).`);
            }
            return result === 'sat';
        } finally {
            solver.pop();
        }
    };

    const equivalent: Equivalence = async (a, b, resource) => {
        stats.equivalenceChecks++;
        const symbols = encoder.symbolsFor(resource);
        return !await isSat(encoder.encodeCondition(a, symbols).neq(encoder.encodeCondition(b, symbols)));
    };

    const declaredByPair = declaredInvariantsByPair(policy);
    const inferred = await inferRules(policy, equivalent);

    for (const [pairKey, { action, resource, roleRules }] of collectRoleRules(policy)) {
        stats.pairs++;
        const symbols = encoder.symbolsFor(resource);
        const declared = declaredByPair.get(pairKey) ?? [];
        const grants = new Map([...roleRules].map(([role, rule]) => [role, encoder.encodeCondition(rule.condition, symbols)]));
        const notAllowed = new Set<string>();

        // Allowlists: a role outside onlyRoles that can act at all is a finding.
        for (const invariant of declared) {
            if (!invariant.onlyRoles) {
                continue;
            }
            for (const [role, grant] of grants) {
                if (invariant.onlyRoles.includes(role)) {
                    continue;
                }
                stats.solverChecks++;
                if (await isSat(grant)) {
                    notAllowed.add(role);
                    findings.push({
                        id: `${role}|${action}|${resource}|invariant:${invariant.name}`,
                        kind: 'not-allowed',
                        role, action, resource,
                        invariant: invariant.name,
                        description: `Role "${role}" can ${action} ${resource}, but invariant "${invariant.name}" only allows ${invariant.onlyRoles.join(', ') || 'no roles'}.`,
                        fingerprint: permissionsFingerprint(policy, role, action, resource, invariant.definition),
                    });
                }
            }
        }

        const conditionInvariants = declared.filter((invariant) => invariant.requires !== undefined);
        const inferredGroup = inferred.get(pairKey);

        if (conditionInvariants.length > 0) {
            // Declared conditions replace inference for this pair...
            stats.declaredPairs++;
            for (const invariant of conditionInvariants) {
                const requires = invariant.requires!;
                const requiresKey = conditionKey(requires);
                const encodedRequires = encoder.encodeCondition(requires, symbols);

                for (const [role, rule] of roleRules) {
                    if (invariant.onlyRoles && !invariant.onlyRoles.includes(role)) {
                        continue; // already reported as not allowed at all
                    }
                    if (rule.key === requiresKey) {
                        stats.skippedChecks++;
                        continue;
                    }
                    stats.solverChecks++;
                    if (await isSat(grants.get(role)!, z3Context.Not(encodedRequires))) {
                        findings.push({
                            id: `${role}|${action}|${resource}|invariant:${invariant.name}`,
                            kind: 'invariant',
                            role, action, resource,
                            invariant: invariant.name,
                            description: `Role "${role}" can ${action} ${resource} without satisfying invariant "${invariant.name}" (${requiresKey}).`,
                            fingerprint: permissionsFingerprint(policy, role, action, resource, invariant.definition),
                        });
                    }
                }
            }

            // ...and inference only checks whether the declared conditions are looser than
            // what most roles actually require.
            if (inferredGroup) {
                const names = conditionInvariants.map((invariant) => invariant.name).sort();
                const declaredConditions = conditionInvariants.map((invariant) => encoder.encodeCondition(invariant.requires!, symbols));
                const allDeclared = declaredConditions.length === 1 ? declaredConditions[0]! : z3Context.And(...declaredConditions);
                const definitions = conditionInvariants.map((invariant) => invariant.definition).sort();

                for (const [ruleKey, rule] of inferredGroup.conditions) {
                    stats.solverChecks++;
                    if (await isSat(allDeclared, z3Context.Not(encoder.encodeCondition(rule, symbols)))) {
                        const label = names.length === 1 ? `invariant "${names[0]}" doesn't` : `invariants ${names.map((n) => `"${n}"`).join(' + ')} don't`;
                        findings.push({
                            id: `invariant:${names.join('+')}|${action}|${resource}|inferred:${ruleKey}`,
                            kind: 'loose-invariant',
                            action, resource,
                            invariant: names.join('+'),
                            inferredRule: ruleKey,
                            description: `Most roles that can ${action} ${resource} require ${ruleKey}, which ${label}.`,
                            fingerprint: hash({ action, resource, definitions, ruleKey }),
                        });
                    }
                }
            }
            continue;
        }

        // No declared conditions here: the inferred rule stands in, and deviations are findings.
        if (!inferredGroup) {
            continue;
        }
        const encodedRules = new Map([...inferredGroup.conditions].map(([key, condition]) => [key, encoder.encodeCondition(condition, symbols)]));

        // Permissions are a pure union (no deny), so a combination of roles can only
        // bypass a rule if one of its members can alone: checking roles one at a time is
        // complete, and attributes each finding to exactly one role.
        for (const [role, rule] of roleRules) {
            if (notAllowed.has(role)) {
                continue; // an allowlist already says this role shouldn't act here at all
            }
            for (const [ruleKey, encodedRule] of encodedRules) {
                // the role uses the rule itself (or an equivalent): it can't act without it
                if (inferredGroup.equivalentKeys.get(ruleKey)?.has(rule.key)) {
                    stats.skippedChecks++;
                    continue;
                }
                stats.solverChecks++;
                if (await isSat(grants.get(role)!, z3Context.Not(encodedRule))) {
                    findings.push({
                        id: `${role}|${action}|${resource}|inferred:${ruleKey}`,
                        kind: 'inferred',
                        role, action, resource,
                        inferredRule: ruleKey,
                        description: `No invariant covers ${action} ${resource}. Most roles require ${ruleKey}; "${role}" can act without it.`,
                        fingerprint: permissionsFingerprint(policy, role, action, resource),
                    });
                }
            }
        }
    }

    // An invariant whose requirement always holds, with no allowlist, can never catch anything.
    const vacuousInvariants: Array<string> = [];
    for (const invariant of policy.schema.invariants ?? []) {
        if (invariant.requires === undefined || invariant.onlyRoles !== undefined) {
            continue;
        }
        const symbols = encoder.symbolsFor(invariant.resource);
        if (!await isSat(z3Context.Not(encoder.encodeCondition(invariant.requires, symbols)))) {
            vacuousInvariants.push(invariant.name);
        }
    }

    findings.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
    return { findings, vacuousInvariants: vacuousInvariants.sort(), stats };
}
