import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { conditionKey, evaluateCondition } from './conditions.js';
import { ThujaVerificationError } from './errors.js';
import { Policy } from './policy.js';
import { defineSchema, type AnyCondition, type AnyPermission } from './schema.js';
import type { ExceptionsFile } from './verify.js';

// A large, deterministic policy: 50 roles (10 departments x 5 levels), 5 resource types,
// 8 actions, and several hundred permissions. Most permissions follow one "house rule"
// per action/resource; a few deliberately don't, which is what the scan has to find.

const DEPARTMENTS = ['editorial', 'finance', 'legal', 'sales', 'support', 'engineering', 'marketing', 'hr', 'compliance', 'ops'];
const LEVELS = ['intern', 'associate', 'senior', 'lead', 'director'];
const ROLES = DEPARTMENTS.flatMap((department) => LEVELS.map((level) => `${department}_${level}`));

const schema = defineSchema({
    roles: ROLES,
    actions: ['create', 'read', 'update', 'delete', 'publish', 'archive', 'approve', 'export'],
    resources: {
        article: { published: 'boolean', archived: 'boolean', authorId: 'string', region: 'string', status: 'string' },
        invoice: { approved: 'boolean', ownerId: 'string', department: 'string', region: 'string' },
        comment: { hidden: 'boolean', authorId: 'string' },
        report: { confidential: 'boolean', department: 'string', region: 'string' },
        profile: { active: 'boolean', userId: 'string', department: 'string' },
    },
    context: { id: 'string', region: 'string', department: 'string' },
});

const literal = (property: string, value: boolean | string): AnyCondition => ({ type: 'LiteralExpression', property, operator: 'eq', value });
const fromContext = (property: string, contextProperty: string): AnyCondition => ({ type: 'ContextExpression', property, operator: 'eq', contextProperty });

// Candidate guards per resource; each action/resource pair picks one as its house rule.
const GUARDS: Record<string, Array<AnyCondition>> = {
    article: [literal('published', false), literal('archived', false), fromContext('authorId', 'id'), fromContext('region', 'region'), literal('status', 'draft'), literal('status', 'review')],
    invoice: [literal('approved', false), fromContext('ownerId', 'id'), fromContext('department', 'department'), fromContext('region', 'region')],
    comment: [literal('hidden', false), fromContext('authorId', 'id')],
    report: [literal('confidential', false), fromContext('department', 'department'), fromContext('region', 'region')],
    profile: [fromContext('userId', 'id'), fromContext('department', 'department'), literal('active', true)],
};

// mulberry32: small seeded PRNG so the generated policy is identical on every run.
function prng(seed: number) {
    return () => {
        seed = (seed + 0x6D2B79F5) | 0;
        let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

function generatePermissions(seed = 20261018): Map<string, Array<AnyPermission>> {
    const random = prng(seed);
    const pick = <T>(items: ReadonlyArray<T>): T => items[Math.floor(random() * items.length)] as T;

    const pairs = Object.keys(schema.resources).flatMap((resource) => schema.actions.map((action) => ({ resource, action })));
    const houseRule = new Map(pairs.map(({ resource, action }) => [
        `${action}|${resource}`,
        // reading articles and comments is open to everyone who can read at all
        action === 'read' && (resource === 'article' || resource === 'comment') ? true : pick(GUARDS[resource]!),
    ]));

    const permissionsByRole = new Map<string, Array<AnyPermission>>();
    for (const role of ROLES) {
        const permissions: Array<AnyPermission> = [];
        const count = 6 + Math.floor(random() * 7); // 6-12 action/resource pairs per role
        const chosen = [...pairs].sort(() => random() - 0.5).slice(0, count);

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

function buildPolicy(permissionsByRole: Map<string, Array<AnyPermission>>) {
    const policy = new Policy(schema);
    for (const [role, permissions] of permissionsByRole) {
        policy.addRole(role, permissions as never);
    }
    return policy;
}

/**
 * Independent oracle: enumerate every concrete resource/context assignment and use the
 * runtime evaluator (what `can()` uses) instead of Z3. Conditions are equalities, so each
 * string attribute only needs the literals that appear in the policy plus two fresh values.
 */
function bruteForceFindings(permissionsByRole: Map<string, Array<AnyPermission>>): Set<string> {
    const all = [...permissionsByRole.values()].flat();
    const literals = [...new Set(all.flatMap(({ condition }) =>
        condition !== true && condition.type === 'LiteralExpression' && typeof condition.value === 'string' ? [condition.value] : []))];
    const stringDomain = ['v1', 'v2', ...literals];

    const assignments = (attributes: Record<string, string>): Array<Record<string, boolean | string>> =>
        Object.entries(attributes).reduce<Array<Record<string, boolean | string>>>(
            (partials, [name, type]) => partials.flatMap((partial) =>
                (type === 'boolean' ? [true, false] : stringDomain).map((value) => ({ ...partial, [name]: value }))),
            [{}],
        );

    const findings = new Set<string>();
    for (const [resource, attributes] of Object.entries(schema.resources)) {
        const worlds = assignments(attributes).flatMap((resourceValue) =>
            assignments(schema.context).map((contextValue) => ({ resourceValue, contextValue })));

        for (const action of schema.actions) {
            const invariants = new Map<string, AnyCondition>();
            for (const permission of all) {
                if (permission.action === action && permission.resource === resource && permission.condition !== true) {
                    invariants.set(conditionKey(permission.condition), permission.condition);
                }
            }

            for (const [role, permissions] of permissionsByRole) {
                const relevant = permissions.filter((p) => p.action === action && p.resource === resource);
                for (const [key, invariant] of invariants) {
                    const bypass = worlds.some(({ resourceValue, contextValue }) =>
                        relevant.some((p) => evaluateCondition(p.condition, resourceValue, contextValue))
                        && !evaluateCondition(invariant, resourceValue, contextValue));
                    if (bypass) {
                        findings.add(`${role}|${action}|${resource}|${key}`);
                    }
                }
            }
        }
    }
    return findings;
}

describe('stress: 50 roles, hundreds of permissions', () => {
    const permissionsByRole = generatePermissions();
    const permissionCount = [...permissionsByRole.values()].reduce((sum, permissions) => sum + permissions.length, 0);

    it('generates the intended scale', () => {
        expect(permissionsByRole.size).toEqual(50);
        expect(permissionCount).toBeGreaterThanOrEqual(400);
    });

    it('finds exactly the bypasses a brute-force search over concrete values finds', async () => {
        const policy = buildPolicy(permissionsByRole);

        const started = performance.now();
        const findings = await policy.findBypasses();
        const elapsed = performance.now() - started;

        const expected = bruteForceFindings(permissionsByRole);
        console.log(`[stress] ${permissionsByRole.size} roles, ${permissionCount} permissions -> ${findings.length} findings in ${elapsed.toFixed(0)}ms`);

        expect(expected.size).toBeGreaterThan(0);
        expect(findings.map((finding) => finding.id)).toEqual([...expected].sort());
    }, 120_000);

    it('verifies end to end: stub, approve, pass, then catch a new bypass', async () => {
        const exceptionsFile = join(mkdtempSync(join(tmpdir(), 'thuja-stress-')), 'thuja.exceptions.json');
        const policy = buildPolicy(permissionsByRole);

        // 1. update mode writes a stub per finding and still fails until they're approved
        const stubbed = await policy.verifyNoUnapprovedBypasses({ exceptionsFile, update: true }).then(() => undefined, (e: unknown) => e);
        expect(stubbed).toBeInstanceOf(ThujaVerificationError);
        expect(new Set((stubbed as ThujaVerificationError).problems.map((problem) => problem.kind))).toEqual(new Set(['incomplete']));

        // 2. a reviewer approves every one
        const file: ExceptionsFile = JSON.parse(readFileSync(exceptionsFile, 'utf8'));
        for (const entry of Object.values(file.exceptions)) {
            Object.assign(entry, { reason: 'Reviewed in stress test', approvedBy: 'stress-test', approvedAt: '2026-10-18' });
        }
        writeFileSync(exceptionsFile, JSON.stringify(file));

        const { findings } = await policy.verifyNoUnapprovedBypasses({ exceptionsFile, update: false });
        expect(findings.length).toEqual(Object.keys(file.exceptions).length);

        // 3. someone grants one more unconditional permission on a guarded action
        const [role, permissions] = [...permissionsByRole].find(([, permissions]) =>
            !permissions.some((p) => p.action === 'delete' && p.resource === 'invoice'))!;
        const changed = new Map(permissionsByRole).set(role, [...permissions, { action: 'delete', resource: 'invoice', condition: true }]);

        const caught = await buildPolicy(changed).verifyNoUnapprovedBypasses({ exceptionsFile, update: false }).then(() => undefined, (e: unknown) => e);
        expect(caught).toBeInstanceOf(ThujaVerificationError);
        const problems = (caught as ThujaVerificationError).problems;
        expect(problems.length).toBeGreaterThan(0);
        expect(problems.every((problem) => problem.kind === 'unapproved' && problem.id.startsWith(`${role}|delete|invoice|`))).toBe(true);
    }, 120_000);
});
