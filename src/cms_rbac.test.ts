import { describe, expect, it } from 'vitest';
import { init } from 'z3-solver';
import { CmsRbac } from './cms_rbac';

describe('roles', () => {
    it('default to false', async () => {
        type CMSRole = 'writer' | 'publisher' | 'editor' | 'compliance_officer';

        const rbac = new CmsRbac<CMSRole>();
        rbac.addRole('writer', [
            { action: 'create', resource: 'article', condition: true },
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: true } },
        ]);
        rbac.addRole('editor', [
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false } }
        ]);
        rbac.addRole('publisher', [
            { action: 'publish', resource: 'article', condition: true },
            { action: 'unpublish', resource: 'article', condition: { property: 'published', operator: 'eq', value: true } }
        ]);
        rbac.addRole('compliance_officer', [
            { action: 'edit', resource: 'article', condition: true },
        ])

        rbac.assignRole('alice', 'writer');

        expect(rbac.can('alice', 'publish')).toEqual(false);
    });

    it('evaluates non-conditionals correctly', async () => {
        type CMSRole = 'writer' | 'publisher' | 'editor' | 'compliance_officer';

        const rbac = new CmsRbac<CMSRole>();
        rbac.addRole('writer', [
            { action: 'create', resource: 'article', condition: true },
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: true } },
        ]);
        rbac.addRole('editor', [
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false } }
        ]);
        rbac.addRole('publisher', [
            { action: 'publish', resource: 'article', condition: true },
            { action: 'unpublish', resource: 'article', condition: { property: 'published', operator: 'eq', value: true } }
        ]);
        rbac.addRole('compliance_officer', [
            { action: 'edit', resource: 'article', condition: true },
        ])

        rbac.assignRole('alice', 'writer');
        expect(rbac.can('alice', 'create')).toEqual(true);
    });

    it('evaluates conditionals correctly', async () => {
        type CMSRole = 'writer' | 'publisher' | 'editor' | 'compliance_officer';

        const rbac = new CmsRbac<CMSRole>();
        rbac.addRole('writer', [
            { action: 'create', resource: 'article', condition: true },
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false } },
        ]);
        rbac.addRole('editor', [
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false } }
        ]);
        rbac.addRole('publisher', [
            { action: 'publish', resource: 'article', condition: true },
            { action: 'unpublish', resource: 'article', condition: { property: 'published', operator: 'eq', value: true } }
        ]);
        rbac.addRole('compliance_officer', [
            { action: 'edit', resource: 'article', condition: true },
        ])

        const publishedBlog = { name: 'article' as const, published: true }
        const unpublishedBlog = { name: 'article' as const, published: false }

        rbac.assignRole('alice', 'writer');
        expect(rbac.can('alice', 'edit', publishedBlog)).toEqual(false);
        expect(rbac.can('alice', 'edit', unpublishedBlog)).toEqual(true);
    });
});
