import { describe, expect, it } from 'vitest';
import { cmsSchema, createCmsPolicy } from './examples/cms.js';
import { Policy } from './policy.js';
import { inferInvariants, permissionsFingerprint } from './scan.js';

describe('inferInvariants', () => {
    it('groups every non-trivial condition by action and resource', () => {
        const groups = [...inferInvariants(createCmsPolicy()).values()]
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

    it('flags a role whose condition contradicts the inferred invariant, not just `true`', async () => {
        const policy = new Policy<typeof cmsSchema, 'writer' | 'editor'>(cmsSchema);
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
        const policy = new Policy<typeof cmsSchema, 'writer' | 'compliance_officer'>(cmsSchema);
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
        const policy = new Policy<typeof cmsSchema, 'writer' | 'editor'>(cmsSchema);
        policy.addRole('writer', [
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' } },
        ]);

        expect(await policy.findBypasses()).toEqual([]);
        expect(() => policy.addRole('editor', [])).not.toThrow();
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
