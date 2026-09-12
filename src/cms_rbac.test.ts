import { describe, expect, it } from 'vitest';
import { init } from 'z3-solver';
import { CmsRbac } from './cms_rbac';

describe('roles', () => {
    it('default to false', async () => {
        type CMSRole = 'writer' | 'publisher' | 'editor';

        const rbac = new CmsRbac<CMSRole>();
        rbac.addRole('writer', [
            { action: 'create', resource: 'article' },
            { action: 'edit', resource: 'article', condition: (resource) => { return !!resource && !resource.published } },
        ]);
        rbac.addRole('editor', [
            { action: 'edit', resource: 'article', condition: (resource) => { return !!resource && !resource.published } },
        ]);
        rbac.addRole('publisher', [
            { action: 'publish', resource: 'article' },
            { action: 'unpublish', resource: 'article', condition: (resource) => { return !!resource && resource.published } }
        ]);

        rbac.assignRole('alice', 'writer');

        expect(rbac.can('alice', 'publish')).toEqual(false);
    });

    it('evaluates non-conditionals correctly', async () => {
        type CMSRole = 'writer' | 'publisher' | 'editor';

        const rbac = new CmsRbac<CMSRole>();
        rbac.addRole('writer', [
            { action: 'create', resource: 'article' },
            { action: 'edit', resource: 'article', condition: (resource) => { return !!resource && !resource.published } },
        ]);
        rbac.addRole('editor', [
            { action: 'edit', resource: 'article', condition: (resource) => { return !!resource && !resource.published } },
        ]);
        rbac.addRole('publisher', [
            { action: 'publish', resource: 'article' },
            { action: 'unpublish', resource: 'article', condition: (resource) => { return !!resource && resource.published } }
        ]);

        rbac.assignRole('alice', 'writer');
        expect(rbac.can('alice', 'create')).toEqual(true);
    });

    it('evaluates conditionals correctly', async () => {
        type CMSRole = 'writer' | 'publisher' | 'editor';

        const rbac = new CmsRbac<CMSRole>();
        rbac.addRole('writer', [
            { action: 'create', resource: 'article' },
            { action: 'edit', resource: 'article', condition: (resource) => { return !!resource && !resource.published } },
        ]);
        rbac.addRole('editor', [
            { action: 'edit', resource: 'article', condition: (resource) => { return !!resource && !resource.published } },
        ]);
        rbac.addRole('publisher', [
            { action: 'publish', resource: 'article' },
            { action: 'unpublish', resource: 'article', condition: (resource) => { return !!resource && resource.published } }
        ]);

        const publishedBlog = { name: 'article' as const, published: true }
        const unpublishedBlog = { name: 'article' as const, published: false }

        rbac.assignRole('alice', 'writer');
        expect(rbac.can('alice', 'edit', publishedBlog)).toEqual(false);
        expect(rbac.can('alice', 'edit', unpublishedBlog)).toEqual(true);
    });
});
