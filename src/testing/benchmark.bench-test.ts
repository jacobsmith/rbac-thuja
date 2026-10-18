// Timing harness, run with `npm run bench` (kept out of `npm test`). Set BENCH_OUT to a
// path to also write the results as JSON.

import { writeFileSync } from 'node:fs';
import { it } from 'vitest';
import { scanPolicy } from '../scan.js';
import { defineSchema, type AnyCondition, type AnyPermission } from '../schema.js';
import {
    bruteForceFindings,
    buildPolicy,
    countPermissions,
    enumerator,
    generateAtomicPermissions,
    generateCompoundPermissions,
    prng,
    schema,
    type PermissionsByRole,
} from './stressPolicy.js';

const median = (values: Array<number>) => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)]!;
const round = (value: number, digits = 0) => Number(value.toFixed(digits));

async function timeScan(permissionsByRole: PermissionsByRole, policySchema = schema, runs = 5) {
    const times: Array<number> = [];
    let result: Awaited<ReturnType<typeof scanPolicy>> | undefined;
    for (let i = 0; i < runs; i++) {
        const policy = buildPolicy(permissionsByRole, policySchema);
        const started = performance.now();
        result = await scanPolicy(policy);
        times.push(performance.now() - started);
    }
    return { medianMs: round(median(times)), runsMs: times.map((t) => round(t)), findings: result!.findings.length, stats: result!.stats };
}

function timeOracle(permissionsByRole: PermissionsByRole, policySchema = schema) {
    const started = performance.now();
    const findings = bruteForceFindings(permissionsByRole, policySchema);
    return { ms: round(performance.now() - started), findings: findings.size };
}

function timeCan(permissionsByRole: PermissionsByRole) {
    const random = prng(7);
    const roles = [...permissionsByRole.keys()];
    const resources = Object.keys(schema.resources) as Array<keyof typeof schema.resources>;
    const strings = ['v1', 'v2', 'draft', 'review'];
    const makeResource = (name: keyof typeof schema.resources) => {
        const resource: Record<string, unknown> = { $type: name };
        for (const [attribute, type] of Object.entries(schema.resources[name])) {
            resource[attribute] = type === 'boolean' ? random() < 0.5 : strings[Math.floor(random() * strings.length)];
        }
        return resource;
    };

    const results: Record<string, { meanMicros: number, callsPerSec: number, grantRate: number }> = {};
    for (const rolesPerUser of [1, 3, 10, 50]) {
        const policy = buildPolicy(permissionsByRole);
        const users = Array.from({ length: 200 }, (_, i) => `user${i}`);
        for (const user of users) {
            for (let j = 0; j < rolesPerUser; j++) {
                policy.assignRole(user, roles[Math.floor(random() * roles.length)]!);
            }
        }
        const requests = Array.from({ length: 10_000 }, () => ({
            user: users[Math.floor(random() * users.length)]!,
            action: schema.actions[Math.floor(random() * schema.actions.length)]!,
            resource: makeResource(resources[Math.floor(random() * resources.length)]!),
            context: { id: strings[Math.floor(random() * 2)], region: strings[Math.floor(random() * 2)], department: strings[Math.floor(random() * 2)] },
        }));
        const call = (request: typeof requests[number]) => policy.can(request.user, request.action, request.resource as never, request.context as never);

        requests.forEach(call); // warm up the JIT
        const calls = 200_000;
        let granted = 0;
        const started = performance.now();
        for (let i = 0; i < calls; i++) {
            if (call(requests[i % requests.length]!)) {
                granted++;
            }
        }
        const ms = performance.now() - started;
        results[`${rolesPerUser} role(s)/user`] = { meanMicros: round((ms * 1000) / calls, 2), callsPerSec: Math.round(calls / (ms / 1000)), grantRate: round(granted / calls, 2) };
    }
    return results;
}

/**
 * One resource with `k` boolean attributes and a house rule that references all of them,
 * so brute force has to enumerate 2^k assignments while Z3 reasons symbolically.
 */
function scalingPolicy(k: number) {
    const attributes = Object.fromEntries(Array.from({ length: k }, (_, i) => [`b${i}`, 'boolean' as const]));
    const roles = Array.from({ length: 20 }, (_, i) => `role${i}`);
    const scalingSchema = defineSchema({ roles, actions: ['act'], resources: { thing: attributes }, context: {} });

    const random = prng(1000 + k);
    const atom = (i: number, value: boolean): AnyCondition => ({ type: 'LiteralExpression', property: `b${i}`, operator: 'eq', value });
    const clauses: Array<AnyCondition> = Array.from({ length: Math.ceil(k / 2) }, (_, j) =>
        ({ type: 'Or', conditions: [atom(2 * j, true), atom(Math.min(2 * j + 1, k - 1), false)] }));
    const rule: AnyCondition = { type: 'And', conditions: clauses };

    const permissionsByRole: PermissionsByRole = new Map();
    for (const role of roles) {
        const roll = random();
        const extra = atom(Math.floor(random() * k), random() < 0.5);
        const condition: AnyCondition =
            roll < 0.60 ? rule
            : roll < 0.75 ? { type: 'Or', conditions: [rule, extra] } // looser
            : roll < 0.85 ? { type: 'And', conditions: [rule, extra] } // stricter
            : roll < 0.95 ? { type: 'And', conditions: clauses.filter((_, j) => j !== Math.floor(random() * clauses.length)) } // drops a clause
            : true;
        permissionsByRole.set(role, [{ action: 'act', resource: 'thing', condition } as AnyPermission]);
    }
    return { scalingSchema, permissionsByRole };
}

it('benchmark', async () => {
    const results: Record<string, unknown> = {};

    let started = performance.now();
    const { init } = await import('z3-solver');
    await init();
    results['z3InitMs'] = round(performance.now() - started, 1);

    for (const [name, permissionsByRole] of [
        ['atomic', generateAtomicPermissions()],
        ['compound', generateCompoundPermissions().permissionsByRole],
    ] as const) {
        const { worldCount } = enumerator(permissionsByRole);
        results[name] = {
            roles: permissionsByRole.size,
            permissions: countPermissions(permissionsByRole),
            scan: await timeScan(permissionsByRole),
            bruteForce: { ...timeOracle(permissionsByRole), worldsPerResource: Object.fromEntries(Object.keys(schema.resources).map((r) => [r, worldCount(r)])) },
            can: timeCan(permissionsByRole),
        };
    }

    const scaling: Array<Record<string, unknown>> = [];
    let bruteForceTooSlow = false;
    for (const k of [4, 8, 12, 16, 18, 20, 22]) {
        const { scalingSchema, permissionsByRole } = scalingPolicy(k);
        const scan = await timeScan(permissionsByRole, scalingSchema, 3);
        const row: Record<string, unknown> = { attributes: k, worlds: 2 ** k, z3Ms: scan.medianMs, z3Findings: scan.findings, solverChecks: scan.stats.solverChecks };
        if (!bruteForceTooSlow) {
            const oracle = timeOracle(permissionsByRole, scalingSchema);
            Object.assign(row, { bruteForceMs: oracle.ms, bruteForceFindings: oracle.findings });
            bruteForceTooSlow = oracle.ms > 15_000;
        }
        scaling.push(row);
    }
    results['scaling'] = scaling;

    started = performance.now();
    results['machine'] = { node: process.version, platform: `${process.platform}-${process.arch}` };
    console.log(JSON.stringify(results, null, 2));
    if (process.env['BENCH_OUT']) {
        writeFileSync(process.env['BENCH_OUT'], JSON.stringify(results, null, 2));
    }
}, 1_800_000);
