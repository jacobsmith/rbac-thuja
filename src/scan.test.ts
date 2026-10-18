import { describe, expect, it } from 'vitest';
import { cmsSchema, createCmsPolicy } from './examples/cms.js';
import { Policy } from './policy.js';
import { defineSchema } from './schema.js';
import { inferRules, permissionsFingerprint, scanPolicy } from './scan.js';

describe('inferRules', () => {
    it('groups every non-trivial condition by action and resource', async () => {
        const groups = [...(await inferRules(createCmsPolicy())).values()]
            .map((group) => [group.action, group.resource, [...group.conditions.keys()]]);

        expect(groups).toEqual([
            ['edit', 'article', ['published==false']],
            ['unpublish', 'article', ['published==true']],
        ]);
    });
});

describe('findBypasses', () => {
    it('flags exactly the compliance_officer edit bypass in the CMS policy', async () => {
        const findings = await createCmsPolicy().findBypasses();

        expect(findings.map((finding) => finding.id)).toEqual([
            'compliance_officer|edit|article|inferred:published==false',
        ]);
        expect(findings[0]?.fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/);
    });

    it('flags only the unusual role, not the roles following the common rule', async () => {
        const policy = new Policy(cmsSchema);
        const unpublishedOnly = { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' } as const;
        policy.addRole('writer', [{ action: 'edit', resource: 'article', condition: unpublishedOnly }]);
        policy.addRole('editor', [{ action: 'edit', resource: 'article', condition: unpublishedOnly }]);
        policy.addRole('publisher', [
            { action: 'edit', resource: 'article', condition: { property: 'authorId', operator: 'eq', contextProperty: 'id', type: 'ContextExpression' } },
        ]);

        const ids = (await policy.findBypasses()).map((finding) => finding.id);

        // publisher's ownership check is the odd one out: it's flagged for skipping the
        // common rule, and writer/editor are not flagged for skipping publisher's rule
        expect(ids).toEqual(['publisher|edit|article|inferred:published==false']);
    });

    it('has no rule for an action most roles may do unconditionally', async () => {
        const policy = new Policy(cmsSchema);
        policy.addRole('writer', [{ action: 'create', resource: 'article', condition: true }]);
        policy.addRole('editor', [{ action: 'create', resource: 'article', condition: true }]);
        policy.addRole('publisher', [
            { action: 'create', resource: 'article', condition: { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' } },
        ]);

        expect((await inferRules(policy)).size).toEqual(0);
        expect(await policy.findBypasses()).toEqual([]);
    });

    it('flags both sides of a tie, since neither is clearly the unusual one', async () => {
        const policy = new Policy(cmsSchema);
        policy.addRole('writer', [
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: true, type: 'LiteralExpression' } },
        ]);
        policy.addRole('editor', [
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' } },
        ]);

        const ids = (await policy.findBypasses()).map((finding) => finding.id);

        // each role edits in the state the other one forbids
        expect(ids).toEqual([
            'editor|edit|article|inferred:published==true',
            'writer|edit|article|inferred:published==false',
        ]);
    });

    it('flags ownership bypasses through context expressions', async () => {
        const policy = new Policy(cmsSchema);
        policy.addRole('writer', [
            { action: 'edit', resource: 'article', condition: { property: 'authorId', operator: 'eq', contextProperty: 'id', type: 'ContextExpression' } },
        ]);
        policy.addRole('compliance_officer', [
            { action: 'edit', resource: 'article', condition: true },
        ]);

        const ids = (await policy.findBypasses()).map((finding) => finding.id);

        expect(ids).toEqual(['compliance_officer|edit|article|inferred:authorId==context.id']);
    });

    it('reports nothing for a consistent policy and does not lock its roles', async () => {
        const policy = new Policy(cmsSchema);
        policy.addRole('writer', [
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' } },
        ]);

        expect(await policy.findBypasses()).toEqual([]);
        expect(() => policy.addRole('editor', [])).not.toThrow();
    });
});

describe('findBypasses with compound conditions', () => {
    const unpublished = { type: 'LiteralExpression', property: 'published', operator: 'eq', value: false } as const;
    const published = { type: 'LiteralExpression', property: 'published', operator: 'eq', value: true } as const;
    const owner = { type: 'ContextExpression', property: 'authorId', operator: 'eq', contextProperty: 'id' } as const;
    const ownDraft = { type: 'And', conditions: [unpublished, owner] } as const;
    type Role = 'writer' | 'editor' | 'publisher' | 'compliance_officer';

    function policyWith(roles: Partial<Record<Role, Array<unknown>>>) {
        const policy = new Policy(cmsSchema);
        for (const [role, permissions] of Object.entries(roles)) {
            policy.addRole(role as Role, permissions as never);
        }
        return policy;
    }
    const edit = (condition: unknown) => ({ action: 'edit', resource: 'article', condition });
    const ids = async (policy: ReturnType<typeof policyWith>) => (await policy.findBypasses()).map((finding) => finding.id);

    it('flags a role that skips part of a compound rule', async () => {
        const policy = policyWith({
            writer: [edit(ownDraft)],
            editor: [edit(ownDraft)],
            publisher: [edit(unpublished)], // drops the ownership check
        });

        expect(await ids(policy)).toEqual(['publisher|edit|article|inferred:(authorId==context.id && published==false)']);
    });

    it('does not flag a stricter role', async () => {
        const policy = policyWith({
            writer: [edit(unpublished)],
            editor: [edit(unpublished)],
            publisher: [edit(ownDraft)], // unpublished AND owner implies unpublished
        });

        expect(await ids(policy)).toEqual([]);
    });

    it('treats logically equivalent spellings as the same rule (De Morgan, via Z3)', async () => {
        const policy = policyWith({
            writer: [edit(ownDraft)],
            editor: [edit({ type: 'Not', condition: { type: 'Or', conditions: [published, { type: 'Not', condition: owner }] } })],
            publisher: [edit(unpublished)],
        });

        // writer and editor are one vote each for the same rule, named after the first spelling
        expect(await ids(policy)).toEqual(['publisher|edit|article|inferred:(authorId==context.id && published==false)']);
    });

    it('treats a rule split across several permissions as their Or', async () => {
        const either = { type: 'Or', conditions: [unpublished, owner] } as const;
        const policy = policyWith({
            writer: [edit(either)],
            editor: [edit(unpublished), edit(owner)],
            publisher: [edit(unpublished)],
        });

        expect(await ids(policy)).toEqual([]);
    });

    it('treats a rule that never holds as "nobody may do this"', async () => {
        const never = { type: 'And', conditions: [published, unpublished] } as const;
        const policy = policyWith({
            writer: [edit(never)],
            editor: [edit(never)],
            publisher: [edit(owner)],
        });

        expect(await ids(policy)).toEqual(['publisher|edit|article|inferred:(published==false && published==true)']);
    });

    it('treats a rule that always holds as no rule', async () => {
        const always = { type: 'Or', conditions: [published, unpublished] } as const;
        const policy = policyWith({
            writer: [edit(always)],
            editor: [edit(always)],
            publisher: [edit(owner)],
        });

        expect(await ids(policy)).toEqual([]);
    });

    it('reports how much work the scan did', async () => {
        const policy = policyWith({
            writer: [edit(ownDraft)],
            editor: [edit({ type: 'And', conditions: [owner, unpublished] })],
            publisher: [edit(unpublished)],
            compliance_officer: [edit(true)],
        });

        const { stats } = await scanPolicy(policy);

        // writer/editor normalize to the same key and are skipped; publisher and compliance_officer are checked
        expect(stats).toMatchObject({ pairs: 1, declaredPairs: 0, solverChecks: 2, skippedChecks: 2 });
    });
});

describe('declared invariants', () => {
    const unpublished = { type: 'LiteralExpression', property: 'published', operator: 'eq', value: false } as const;
    const owner = { type: 'ContextExpression', property: 'authorId', operator: 'eq', contextProperty: 'id' } as const;
    const ownDraft = { type: 'And', conditions: [unpublished, owner] } as const;
    const base = { ...cmsSchema };
    const edit = (condition: unknown) => ({ action: 'edit', resource: 'article', condition }) as never;
    const scan = async (invariants: Array<unknown>, roles: Record<string, Array<never>>) => {
        const policy = new Policy(defineSchema({ ...base, invariants: invariants as never }));
        for (const [role, permissions] of Object.entries(roles)) {
            policy.addRole(role as never, permissions);
        }
        return scanPolicy(policy);
    };
    const ids = async (...args: Parameters<typeof scan>) => (await scan(...args)).findings.map((finding) => [finding.kind, finding.id]);

    it('flags every role that breaks a declared rule, even when most roles do', async () => {
        // inference alone would call (unpublished || owner) the rule and flag nothing
        const loose = { type: 'Or', conditions: [unpublished, owner] };
        expect(await ids(
            [{ name: 'own-drafts', action: 'edit', resource: 'article', requires: ownDraft }],
            { writer: [edit(loose)], editor: [edit(loose)], publisher: [edit(ownDraft)] },
        )).toEqual([
            ['invariant', 'editor|edit|article|invariant:own-drafts'],
            ['invariant', 'writer|edit|article|invariant:own-drafts'],
        ]);
    });

    it('replaces inference for the pair it covers', async () => {
        // compliance_officer deviates from the majority, but the declared rule is satisfied by everyone
        const result = await scan(
            [{ name: 'anything-goes', action: 'edit', resource: 'article', requires: { type: 'Or', conditions: [unpublished, { type: 'Not', condition: unpublished }, owner] } }],
            { writer: [edit(unpublished)], editor: [edit(unpublished)], compliance_officer: [edit(true)] },
        );

        expect(result.findings.filter((finding) => finding.kind === 'inferred')).toEqual([]);
        expect(result.stats.declaredPairs).toEqual(1);
    });

    it('flags a declared rule that is looser than what most roles require', async () => {
        expect(await ids(
            [{ name: 'unpublished-only', action: 'edit', resource: 'article', requires: unpublished }],
            { writer: [edit(ownDraft)], editor: [edit(ownDraft)], publisher: [edit(unpublished)] },
        )).toEqual([
            ['loose-invariant', 'invariant:unpublished-only|edit|article|inferred:(authorId==context.id && published==false)'],
        ]);
    });

    it('checks the combination when several invariants cover the same pair', async () => {
        const result = await scan(
            [
                { name: 'unpublished-only', action: 'edit', resource: 'article', requires: unpublished },
                { name: 'owner-only', action: 'edit', resource: 'article', requires: owner },
            ],
            { writer: [edit(ownDraft)], editor: [edit(ownDraft)], publisher: [edit(unpublished)] },
        );

        // together they equal the majority rule, so neither is loose; publisher breaks owner-only
        expect(result.findings.map((finding) => finding.id)).toEqual(['publisher|edit|article|invariant:owner-only']);
    });

    it('flags roles outside an allowlist, and still applies requires to listed roles', async () => {
        const result = await scan(
            [{ name: 'publishers-edit-drafts', action: 'edit', resource: 'article', onlyRoles: ['publisher', 'editor'], requires: unpublished }],
            { writer: [edit(unpublished)], editor: [edit(true)], publisher: [edit(unpublished)] },
        );

        expect(result.findings.map((finding) => [finding.kind, finding.id])).toEqual([
            ['invariant', 'editor|edit|article|invariant:publishers-edit-drafts'],
            ['not-allowed', 'writer|edit|article|invariant:publishers-edit-drafts'],
        ]);
    });

    it('does not flag an unlisted role whose permission can never apply', async () => {
        const never = { type: 'And', conditions: [unpublished, { type: 'Not', condition: unpublished }] };
        const result = await scan(
            [{ name: 'only-publisher', action: 'edit', resource: 'article', onlyRoles: ['publisher'] }],
            { writer: [edit(never)], publisher: [edit(true)] },
        );

        expect(result.findings.filter((finding) => finding.kind === 'not-allowed')).toEqual([]);
    });

    it('keeps inferring conditions where an invariant is only an allowlist, without double-reporting', async () => {
        expect(await ids(
            [{ name: 'no-compliance', action: 'edit', resource: 'article', onlyRoles: ['writer', 'editor', 'publisher'] }],
            { writer: [edit(unpublished)], editor: [edit(unpublished)], publisher: [edit(true)], compliance_officer: [edit(true)] },
        )).toEqual([
            ['not-allowed', 'compliance_officer|edit|article|invariant:no-compliance'],
            ['inferred', 'publisher|edit|article|inferred:published==false'],
        ]);
    });

    it('covers every listed action', async () => {
        const result = await scan(
            [{ name: 'only-publisher', action: ['publish', 'unpublish'], resource: 'article', onlyRoles: ['publisher'] }],
            {
                publisher: [{ action: 'publish', resource: 'article', condition: true } as never],
                writer: [{ action: 'publish', resource: 'article', condition: true } as never, { action: 'unpublish', resource: 'article', condition: true } as never],
            },
        );

        expect(result.findings.map((finding) => finding.id)).toEqual([
            'writer|publish|article|invariant:only-publisher',
            'writer|unpublish|article|invariant:only-publisher',
        ]);
    });

    it('reports invariants that can never catch anything', async () => {
        const result = await scan(
            [
                { name: 'always', action: 'edit', resource: 'article', requires: { type: 'Or', conditions: [unpublished, { type: 'Not', condition: unpublished }] } },
                { name: 'always-but-allowlisted', action: 'edit', resource: 'article', onlyRoles: ['writer'], requires: true },
                { name: 'real', action: 'edit', resource: 'article', requires: unpublished },
            ],
            { writer: [edit(unpublished)] },
        );

        expect(result.vacuousInvariants).toEqual(['always']);
    });

    it('changes the fingerprint when the invariant changes', async () => {
        const roles = { writer: [edit(true)] };
        const [before] = (await scan([{ name: 'rule', action: 'edit', resource: 'article', requires: unpublished }], roles)).findings;
        const [after] = (await scan([{ name: 'rule', action: 'edit', resource: 'article', requires: ownDraft }], roles)).findings;

        expect(before?.id).toEqual(after?.id);
        expect(before?.fingerprint).not.toEqual(after?.fingerprint);
    });
});

describe('permissionsFingerprint', () => {
    it('depends only on the role\'s permissions for that action and resource', () => {
        const base = createCmsPolicy();
        const fingerprint = permissionsFingerprint(base, 'compliance_officer', 'edit', 'article');

        const withUnrelatedChange = createCmsPolicy();
        withUnrelatedChange.addRole('compliance_officer', [
            { action: 'edit', resource: 'article', condition: true },
            { action: 'create', resource: 'article', condition: true },
        ]);
        expect(permissionsFingerprint(withUnrelatedChange, 'compliance_officer', 'edit', 'article')).toEqual(fingerprint);

        const withRelevantChange = createCmsPolicy();
        withRelevantChange.addRole('compliance_officer', [
            { action: 'edit', resource: 'article', condition: { property: 'authorId', operator: 'eq', contextProperty: 'id', type: 'ContextExpression' } },
        ]);
        expect(permissionsFingerprint(withRelevantChange, 'compliance_officer', 'edit', 'article')).not.toEqual(fingerprint);
    });
});
