import { createHash } from "node:crypto";
import type { Bool, init } from "z3-solver";
import { conditionKey, evaluateCondition, normalizeCondition } from "./conditions.js";
import { PolicyEncoder, type EncodablePolicy } from "./PolicyEncoder.js";
import type { AnyCondition, Attributes } from "./schema.js";

export type Finding = {
    /** Stable key for the exceptions file: `role|action|resource|invariant`. */
    id: string,
    role: string,
    action: string,
    resource: string,
    /** The condition (as `conditionKey`) this role grants the action without. */
    invariant: string,
    /** Hash of this role's permissions for this action/resource; changes when they do. */
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

export type InvariantGroup = {
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
export async function inferInvariants(policy: EncodablePolicy, equivalent?: Equivalence): Promise<Map<string, InvariantGroup>> {
    const groups = new Map<string, InvariantGroup>();
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

function collectRoleRules(policy: EncodablePolicy) {
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

export function permissionsFingerprint(policy: EncodablePolicy, role: string, action: string, resource: string): string {
    const conditions = policy.getPermissions(role)
        .filter((permission) => permission.action === action && permission.resource === resource)
        .map((permission) => conditionKey(permission.condition));
    const canonical = JSON.stringify({ action, resource, conditions: [...new Set(conditions)].sort() });

    return `sha256:${createHash('sha256').update(canonical).digest('hex')}`;
}

export type ScanStats = {
    /** Action/resource pairs that have an inferred rule. */
    groups: number,
    /** Role-vs-rule questions answered by Z3. */
    solverChecks: number,
    /** Role-vs-rule questions skipped because the role uses (an equivalent of) the rule itself. */
    skippedChecks: number,
    /** Z3 queries spent merging equivalent conditions during inference. */
    equivalenceChecks: number,
};

export async function findBypasses(policy: EncodablePolicy): Promise<Array<Finding>> {
    return (await scanPolicy(policy)).findings;
}

export async function scanPolicy(policy: EncodablePolicy): Promise<{ findings: Array<Finding>, stats: ScanStats }> {
    const { Context } = await loadZ3();
    const z3Context = new Context('main');
    const encoder = new PolicyEncoder(policy, z3Context);
    const solver = new z3Context.Solver();
    const findings: Array<Finding> = [];
    const stats: ScanStats = { groups: 0, solverChecks: 0, skippedChecks: 0, equivalenceChecks: 0 };

    const isSat = async (...assertions: Array<Bool>) => {
        solver.push();
        assertions.forEach((assertion) => solver.add(assertion));
        const result = await solver.check();
        solver.pop();
        if (result === 'unknown') {
            throw new Error('Z3 returned unknown.');
        }
        return result === 'sat';
    };

    const equivalent: Equivalence = async (a, b, resource) => {
        stats.equivalenceChecks++;
        const symbols = encoder.symbolsFor(resource);
        return !await isSat(encoder.encodeCondition(a, symbols).neq(encoder.encodeCondition(b, symbols)));
    };

    const groups = await inferInvariants(policy, equivalent);
    stats.groups = groups.size;

    for (const { action, resource, roleRules, conditions, equivalentKeys } of groups.values()) {
        const symbols = encoder.symbolsFor(resource);
        const encodedRules = new Map([...conditions].map(([key, condition]) => [key, encoder.encodeCondition(condition, symbols)]));

        // Permissions are a pure union (no deny), so a combination of roles can only
        // bypass an invariant if one of its members can alone: checking roles one at a
        // time is complete, and attributes each finding to exactly one role. Roles with
        // no permission here aren't in roleRules: they can't grant anything.
        for (const [role, rule] of roleRules) {
            const grants = encoder.encodeCondition(rule.condition, symbols);

            for (const [invariant, encodedRule] of encodedRules) {
                // the role uses the rule itself (or an equivalent): it can't act without it
                if (equivalentKeys.get(invariant)?.has(rule.key)) {
                    stats.skippedChecks++;
                    continue;
                }
                stats.solverChecks++;
                if (await isSat(grants, z3Context.Not(encodedRule))) {
                    findings.push({
                        id: `${role}|${action}|${resource}|${invariant}`,
                        role,
                        action,
                        resource,
                        invariant,
                        fingerprint: permissionsFingerprint(policy, role, action, resource),
                    });
                }
            }
        }
    }

    findings.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
    return { findings, stats };
}
