import { describe, expect, it } from 'vitest';
import { cmsSchema, createCmsPolicy } from './examples/cms.js';
import { Policy } from './policy.js';
import { inferInvariants, permissionsFingerprint, scanPolicy } from './scan.js';

describe('inferInvariants', () => {
    it('groups every non-trivial condition by action and resource', async () => {
        const groups = [...(await inferInvariants(createCmsPolicy())).values()]
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
            'compliance_officer|edit|article|published==false',
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
        expect(ids).toEqual(['publisher|edit|article|published==false']);
    });

    it('has no rule for an action most roles may do unconditionally', async () => {
        const policy = new Policy(cmsSchema);
        policy.addRole('writer', [{ action: 'create', resource: 'article', condition: true }]);
        policy.addRole('editor', [{ action: 'create', resource: 'article', condition: true }]);
        policy.addRole('publisher', [
            { action: 'create', resource: 'article', condition: { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' } },
        ]);

        expect((await inferInvariants(policy)).size).toEqual(0);
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
            'editor|edit|article|published==true',
            'writer|edit|article|published==false',
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

        expect(ids).toEqual(['compliance_officer|edit|article|authorId==context.id']);
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

        expect(await ids(policy)).toEqual(['publisher|edit|article|(authorId==context.id && published==false)']);
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
        expect(await ids(policy)).toEqual(['publisher|edit|article|(authorId==context.id && published==false)']);
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

        expect(await ids(policy)).toEqual(['publisher|edit|article|(published==false && published==true)']);
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
        expect(stats).toMatchObject({ groups: 1, solverChecks: 2, skippedChecks: 2 });
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
