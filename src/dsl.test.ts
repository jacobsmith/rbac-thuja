import { describe, expect, it } from 'vitest';
import { conditionKey } from './conditions.js';
import { contextOf, definePolicy, describeRole } from './dsl.js';
import { cmsSchema, createCmsPolicy, createGovernedCmsPolicy } from './examples/cms.js';
import { createCmsPolicyByResource, createCmsPolicyChained, createGovernedCmsPolicyByResource } from './examples/cmsResources.js';
import type { Policy } from './policy.js';
import type { PolicySchema } from './schema.js';

/** Each role's permissions as sorted `action resource condition-key` lines. */
function permissionTable<S extends PolicySchema>(policy: Policy<S>) {
    return Object.fromEntries(policy.getRoles().map((role) => [role,
        policy.getPermissions(role).map((p) => `${p.action} ${p.resource} ${conditionKey(p.condition)}`).sort()]));
}

describe('definePolicy (resource-centric)', () => {
    it('builds exactly the same permissions as the role-centric CMS policy, in both styles', () => {
        const expected = permissionTable(createCmsPolicy());

        expect(permissionTable(createCmsPolicyByResource())).toEqual(expected);
        expect(permissionTable(createCmsPolicyChained())).toEqual(expected);
    });

    it('produces identical findings and fingerprints, so existing exceptions files keep working', async () => {
        const [byRole, byResource] = await Promise.all([createCmsPolicy().findBypasses(), createCmsPolicyByResource().findBypasses()]);
        expect(byResource).toEqual(byRole);

        const [governedByRole, governedByResource] = await Promise.all([createGovernedCmsPolicy().findBypasses(), createGovernedCmsPolicyByResource().findBypasses()]);
        expect(governedByResource).toEqual(governedByRole);
    });

    it('passes verification against the existing exceptions files', async () => {
        await createCmsPolicyByResource().verifyNoUnapprovedBypasses({ exceptionsFile: 'src/examples/cms.thuja.exceptions.json' });
        await createGovernedCmsPolicyByResource().verifyNoUnapprovedBypasses({ exceptionsFile: 'src/examples/governedCms.thuja.exceptions.json' });
    });

    it('compiles shorthand, context references and combinators to plain conditions', () => {
        const policy = definePolicy(cmsSchema, ({ resource, ctx }) => {
            resource('article', (article, { any, not, all, raw }) => {
                article.edit({
                    writer: { published: false, authorId: ctx.id },
                    editor: not({ authorId: ctx.id }),
                    publisher: any({ published: false }, all({ published: true }, { authorId: ctx.id })),
                    compliance_officer: raw({ type: 'LiteralExpression', property: 'published', operator: 'eq', value: true }),
                });
            });
        });

        expect(describeRole(policy, 'writer')).toEqual(['edit article when (authorId==context.id && published==false)']);
        expect(describeRole(policy, 'editor')).toEqual(['edit article when !(authorId==context.id)']);
        expect(describeRole(policy, 'publisher')).toEqual(['edit article when ((authorId==context.id && published==true) || published==false)']);
        expect(describeRole(policy, 'compliance_officer')).toEqual(['edit article when published==true']);
    });

    it('evaluates the compiled conditions at runtime', () => {
        const policy = definePolicy(cmsSchema, ({ resource, ctx }) => {
            resource('article', (article) => article.edit({ writer: { published: false, authorId: ctx.id } }));
        });
        policy.assignRole('alice', 'writer');

        expect(policy.can('alice', 'edit', { $type: 'article', published: false, authorId: 'alice' }, { id: 'alice' })).toBe(true);
        expect(policy.can('alice', 'edit', { $type: 'article', published: false, authorId: 'bob' }, { id: 'alice' })).toBe(false);
    });

    it('collects a role\'s grants across resources and calls', () => {
        const policy = definePolicy(cmsSchema, ({ resource }) => {
            resource('article', (article) => {
                article.create(['writer']);
                article.edit({ writer: { published: false } });
            });
            resource('article').can('publish', ['writer'], { published: false });
        });

        expect(describeRole(policy, 'writer')).toEqual([
            'create article',
            'edit article when published==false',
            'publish article when published==false',
        ]);
    });

    it('throws on a second grant for the same role, action and resource', () => {
        expect(() => definePolicy(cmsSchema, ({ resource }) => {
            resource('article', (article) => article.edit({ writer: { published: false } }));
            resource('article', (article) => article.edit({ writer: true })); // would silently widen the first
        })).toThrow(/"writer" is granted edit on article more than once; combine the conditions with any/);

        expect(() => definePolicy(cmsSchema, ({ resource }) => {
            resource('article').can('edit', ['writer', 'editor'], { published: false }).can('edit', ['editor']);
        })).toThrow(/"editor" is granted edit on article more than once/);
    });

    it('supports shared conditions defined outside the policy, including context references', () => {
        const ctx = contextOf(cmsSchema);
        const draft = { published: false };
        const ownDraft = { ...draft, authorId: ctx.id };

        const policy = definePolicy(cmsSchema, ({ resource }) => {
            resource('article', (article, { any }) => {
                article.edit({ writer: ownDraft, editor: draft, publisher: any(ownDraft, { published: true }) });
            });
        });

        expect(describeRole(policy, 'writer')).toEqual(['edit article when (authorId==context.id && published==false)']);
        expect(describeRole(policy, 'editor')).toEqual(['edit article when published==false']);
        expect(describeRole(policy, 'publisher')).toEqual(['edit article when ((authorId==context.id && published==false) || published==true)']);
    });

    it('rejects mistakes the types would catch, for JavaScript consumers', () => {
        expect(() => definePolicy(cmsSchema, ({ resource }) => resource('page' as never))).toThrow(/Unknown resource "page"/);
        expect(() => definePolicy(cmsSchema, ({ resource }) => resource('article', (a) => a.edit({ writer: {} })))).toThrow(/empty attribute object would allow everything/);
        expect(() => definePolicy(cmsSchema, ({ resource }) => resource('article', (a) => a.edit({ writer: false as never })))).toThrow(/expected true/);
        expect(() => definePolicy(cmsSchema, ({ resource }) => resource('article', (a) => a.edit({ admin: true } as never)))).toThrow(/Unknown role "admin"/);
    });
});

describe('describeRole', () => {
    it('gives the role-centric view of a resource-centric policy', () => {
        expect(describeRole(createCmsPolicyByResource(), 'writer')).toEqual(['create article', 'edit article when published==false']);
        expect(describeRole(createCmsPolicyByResource(), 'publisher')).toEqual(['publish article', 'unpublish article when published==true']);
    });
});
