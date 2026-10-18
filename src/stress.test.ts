import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ThujaVerificationError } from './errors.js';
import { scanPolicy } from './scan.js';
import {
    bruteForceFindings,
    buildPolicy,
    countPermissions,
    enumerator,
    generateAtomicPermissions,
    generateCompoundPermissions,
    generateInvariants,
    schema,
} from './testing/stressPolicy.js';
import type { ExceptionsFile } from './verify.js';

// Large, deterministic policies: 50 roles (10 departments x 5 levels), 5 resource types,
// 8 actions, several hundred permissions. Most permissions follow one "house rule" per
// action/resource; some deliberately don't, and the scan has to find exactly those.
// Z3's answer is checked against a brute-force oracle that never touches Z3.

describe('stress: 50 roles, atomic conditions', () => {
    const permissionsByRole = generateAtomicPermissions();
    const permissionCount = countPermissions(permissionsByRole);

    it('generates the intended scale', () => {
        expect(permissionsByRole.size).toEqual(50);
        expect(permissionCount).toBeGreaterThanOrEqual(400);
    });

    it('finds exactly the bypasses a brute-force search over concrete values finds', async () => {
        const started = performance.now();
        const { findings, stats } = await scanPolicy(buildPolicy(permissionsByRole));
        const elapsed = performance.now() - started;

        const expected = bruteForceFindings(permissionsByRole);
        console.log(`[stress:atomic] ${permissionsByRole.size} roles, ${permissionCount} permissions -> ${findings.length} findings in ${elapsed.toFixed(0)}ms`, stats);

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

describe('stress: 50 roles, compound And/Or/Not conditions', () => {
    const { permissionsByRole, variants, houseRules } = generateCompoundPermissions();
    const permissionCount = countPermissions(permissionsByRole);

    it('generates the intended scale and mix', () => {
        expect(permissionsByRole.size).toEqual(50);
        expect(permissionCount).toBeGreaterThanOrEqual(400);
        const counts = new Map<string, number>();
        variants.forEach((variant) => counts.set(variant, (counts.get(variant) ?? 0) + 1));
        for (const variant of ['exact', 'rewritten', 'split', 'stricter', 'looser', 'unconditional', 'unrelated']) {
            expect(counts.get(variant) ?? 0, variant).toBeGreaterThan(0);
        }
    });

    it('finds exactly the bypasses a brute-force search over concrete values finds', async () => {
        const started = performance.now();
        const { findings, stats } = await scanPolicy(buildPolicy(permissionsByRole));
        const elapsed = performance.now() - started;

        const oracleStarted = performance.now();
        const expected = bruteForceFindings(permissionsByRole);
        const oracleElapsed = performance.now() - oracleStarted;
        console.log(`[stress:compound] ${permissionsByRole.size} roles, ${permissionCount} permissions -> ${findings.length} findings in ${elapsed.toFixed(0)}ms (oracle ${oracleElapsed.toFixed(0)}ms)`, stats);

        expect(expected.size).toBeGreaterThan(0);
        expect(findings.map((finding) => finding.id)).toEqual([...expected].sort());
    }, 300_000);

    it('flags deviating roles and never roles that wrote the rule differently or more strictly', async () => {
        const { findings } = await scanPolicy(buildPolicy(permissionsByRole));
        const flagged = new Map(findings.map((finding) => [`${finding.role}|${finding.action}|${finding.resource}`, finding]));
        const { truthTable } = enumerator(permissionsByRole);

        for (const [grant, variant] of variants) {
            if (variant === 'exact' || variant === 'rewritten' || variant === 'split' || variant === 'stricter') {
                expect(flagged.has(grant), `${grant} (${variant}) should not be flagged`).toBe(false);
            }
            // ...unless the generator happened to produce a house rule that always holds, e.g.
            // `(!(active==true) || active==true)`: then unconditional access *is* the rule
            const [, action, resource] = grant.split('|') as [string, string, string];
            const rule = houseRules.get(`${action}|${resource}`)!;
            if (variant === 'unconditional' && truthTable(rule, resource).includes('0')) {
                expect(flagged.has(grant), `${grant} (unconditional) should be flagged`).toBe(true);
            }
        }
    }, 300_000);
});

describe('stress: 50 roles, compound conditions, declared invariants and allowlists', () => {
    const { permissionsByRole, variants, houseRules } = generateCompoundPermissions();
    const { invariants, styles } = generateInvariants(permissionsByRole, houseRules);
    const governedSchema = { ...schema, invariants };

    it('declares a mix of invariant styles', () => {
        const counts = new Map<string, number>();
        styles.forEach((style) => counts.set(style, (counts.get(style) ?? 0) + 1));
        for (const style of ['exact', 'looser', 'stricter', 'allowlist']) {
            expect(counts.get(style) ?? 0, style).toBeGreaterThan(0);
        }
    });

    it('finds exactly what a brute-force search finds', async () => {
        const started = performance.now();
        const { findings, stats, vacuousInvariants } = await scanPolicy(buildPolicy(permissionsByRole, governedSchema));
        const elapsed = performance.now() - started;

        const expected = bruteForceFindings(permissionsByRole, governedSchema);
        const kinds = new Map<string, number>();
        findings.forEach((finding) => kinds.set(finding.kind, (kinds.get(finding.kind) ?? 0) + 1));
        console.log(`[stress:invariants] ${invariants.length} invariants -> ${findings.length} findings in ${elapsed.toFixed(0)}ms`, Object.fromEntries(kinds), stats);

        expect(findings.map((finding) => finding.id)).toEqual([...expected].sort());
        // the generator sometimes builds an invariant from a house rule that always holds
        const { truthTable } = enumerator(permissionsByRole, governedSchema);
        const alwaysHolds = invariants
            .filter((invariant) => invariant.requires !== undefined && invariant.onlyRoles === undefined && !truthTable(invariant.requires, invariant.resource).includes('0'))
            .map((invariant) => invariant.name).sort();
        expect(vacuousInvariants).toEqual(alwaysHolds);
        for (const kind of ['invariant', 'not-allowed', 'inferred', 'loose-invariant']) {
            expect(kinds.get(kind) ?? 0, kind).toBeGreaterThan(0);
        }
    }, 300_000);

    it('catches roles that follow the majority when the declared rule is stricter', async () => {
        const { findings } = await scanPolicy(buildPolicy(permissionsByRole, governedSchema));
        const flagged = new Set(findings.filter((finding) => finding.kind === 'invariant').map((finding) => `${finding.role}|${finding.action}|${finding.resource}`));

        // inference alone never flags a role that writes the house rule exactly
        const caught = [...variants].filter(([grant, variant]) => {
            const [, action, resource] = grant.split('|');
            return variant === 'exact' && styles.get(`${action}|${resource}`) === 'stricter' && flagged.has(grant);
        });
        expect(caught.length).toBeGreaterThan(0);
    }, 300_000);

    it('never calls an exactly declared house rule loose', async () => {
        const { findings } = await scanPolicy(buildPolicy(permissionsByRole, governedSchema));
        const loose = findings.filter((finding) => finding.kind === 'loose-invariant' && styles.get(`${finding.action}|${finding.resource}`) === 'exact');

        expect(loose).toEqual([]);
    }, 300_000);
});
