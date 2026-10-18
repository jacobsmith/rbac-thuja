import { createHash } from "node:crypto";
import type { init } from "z3-solver";
import { conditionKey } from "./conditions.js";
import { PolicyEncoder, type EncodablePolicy } from "./PolicyEncoder.js";
import type { AnyCondition } from "./schema.js";

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

/**
 * Invariants are inferred from the policy itself: for each action/resource, the condition
 * the most roles use is treated as the rule, so only roles that deviate from it are
 * flagged. Each role counts once per distinct condition. When conditions tie, all of them
 * are kept (we can't tell which side is unusual, so both get flagged). When unconditional
 * access (`true`) is the most common, that action/resource has no invariant.
 */
export function inferInvariants(policy: EncodablePolicy): Map<string, { action: string, resource: string, conditions: Map<string, AnyCondition> }> {
    const tallies = new Map<string, { action: string, resource: string, votes: Map<string, { condition: AnyCondition, roles: Set<string> }> }>();

    for (const role of policy.getRoles()) {
        for (const permission of policy.getPermissions(role)) {
            const groupKey = `${permission.action}|${permission.resource}`;
            let tally = tallies.get(groupKey);
            if (!tally) {
                tally = { action: permission.action, resource: permission.resource, votes: new Map() };
                tallies.set(groupKey, tally);
            }
            const key = conditionKey(permission.condition);
            let vote = tally.votes.get(key);
            if (!vote) {
                vote = { condition: permission.condition, roles: new Set() };
                tally.votes.set(key, vote);
            }
            vote.roles.add(role);
        }
    }

    const groups = new Map<string, { action: string, resource: string, conditions: Map<string, AnyCondition> }>();
    for (const [groupKey, { action, resource, votes }] of tallies) {
        const mostVotes = Math.max(...[...votes.values()].map((vote) => vote.roles.size));
        const conditions = new Map<string, AnyCondition>();
        for (const [key, vote] of votes) {
            if (vote.roles.size === mostVotes && vote.condition !== true) {
                conditions.set(key, vote.condition);
            }
        }
        if (conditions.size > 0) {
            groups.set(groupKey, { action, resource, conditions });
        }
    }

    return groups;
}

export function permissionsFingerprint(policy: EncodablePolicy, role: string, action: string, resource: string): string {
    const conditions = policy.getPermissions(role)
        .filter((permission) => permission.action === action && permission.resource === resource)
        .map((permission) => conditionKey(permission.condition));
    const canonical = JSON.stringify({ action, resource, conditions: [...new Set(conditions)].sort() });

    return `sha256:${createHash('sha256').update(canonical).digest('hex')}`;
}

export async function findBypasses(policy: EncodablePolicy): Promise<Array<Finding>> {
    const { Context } = await loadZ3();
    const z3Context = new Context('main');
    const encoder = new PolicyEncoder(policy, z3Context);
    const solver = new z3Context.Solver();
    const findings: Array<Finding> = [];

    for (const { action, resource, conditions } of inferInvariants(policy).values()) {
        const symbols = encoder.symbolsFor(resource);

        // Permissions are a pure union (no deny), so a combination of roles can only
        // bypass an invariant if one of its members can alone: checking roles one at a
        // time is complete, and attributes each finding to exactly one role.
        for (const role of policy.getRoles()) {
            // A role with no permission here can't grant anything; skip the solver calls.
            if (!policy.getPermissions(role).some((p) => p.action === action && p.resource === resource)) {
                continue;
            }
            const grants = encoder.roleCanDo(role, action, resource, symbols);

            for (const [invariant, condition] of conditions) {
                solver.push();
                solver.add(grants);
                solver.add(z3Context.Not(encoder.encodeCondition(condition, symbols)));
                const result = await solver.check();
                solver.pop();

                if (result === 'unknown') {
                    throw new Error(`Z3 could not decide whether "${role}" can ${action} ${resource} without ${invariant}.`);
                }
                if (result === 'sat') {
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

    return findings.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}
