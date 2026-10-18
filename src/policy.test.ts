import { describe, expect, it } from 'vitest';
import { cmsSchema, createCmsPolicy } from './examples/cms.js';
import { ImmutableRolesError } from './errors.js';
import { Policy } from './policy.js';
import { defineSchema } from './schema.js';

describe('roles', () => {
    it('default to false', () => {
        const policy = createCmsPolicy();
        policy.assignRole('alice', 'writer');

        expect(policy.can('alice', 'publish')).toEqual(false);
        expect(policy.can('nobody', 'create')).toEqual(false);
    });

    it('evaluates non-conditionals correctly', () => {
        const policy = createCmsPolicy();
        policy.assignRole('alice', 'writer');

        expect(policy.can('alice', 'create')).toEqual(true);
    });

    it('evaluates conditionals correctly', () => {
        const policy = createCmsPolicy();
        policy.assignRole('alice', 'writer');

        expect(policy.can('alice', 'edit', { $type: 'article', published: true })).toEqual(false);
        expect(policy.can('alice', 'edit', { $type: 'article', published: false })).toEqual(true);
    });

    it('allows multiple roles', () => {
        const policy = createCmsPolicy();
        policy.assignRole('alice', 'writer');
        policy.assignRole('alice', 'publisher');

        expect(policy.can('alice', 'create')).toEqual(true);
        expect(policy.can('alice', 'edit', { $type: 'article', published: true })).toEqual(false);
        expect(policy.can('alice', 'publish', { $type: 'article', published: false })).toEqual(true);
    });

    it('can one-hot encode bit vectors for each role, in sorted order', () => {
        const policy = createCmsPolicy();

        expect(policy.getRoleBitVectors().map((rbv) => [rbv.name, rbv.vector.join('')])).toEqual([
            ['compliance_officer', '1000'],
            ['editor', '0100'],
            ['publisher', '0010'],
            ['writer', '0001'],
        ]);
    });

    it('refuses new roles once bit vectors have been handed out', () => {
        const policy = createCmsPolicy();
        policy.getRoleBitVectors();

        expect(() => policy.addRole('writer', [])).toThrow(ImmutableRolesError);
    });

    it('restricts editing to the resource author via a context expression', () => {
        const policy = new Policy(cmsSchema);
        policy.addRole('writer', [
            { action: 'edit', resource: 'article', condition: { property: 'authorId', operator: 'eq', contextProperty: 'id', type: 'ContextExpression' } }
        ]);
        policy.assignRole('alice', 'writer');

        const ownArticle = { $type: 'article' as const, published: true, authorId: 'alice' };
        const othersArticle = { $type: 'article' as const, published: true, authorId: 'bob' };

        expect(policy.can('alice', 'edit', ownArticle, { id: 'alice' })).toEqual(true);
        expect(policy.can('alice', 'edit', othersArticle, { id: 'alice' })).toEqual(false);
    });

    it('fails closed when a compared attribute is missing on both sides', () => {
        const policy = new Policy(cmsSchema);
        policy.addRole('writer', [
            { action: 'edit', resource: 'article', condition: { property: 'authorId', operator: 'eq', contextProperty: 'id', type: 'ContextExpression' } }
        ]);
        policy.assignRole('alice', 'writer');

        // undefined == undefined must not count as "is the author"
        expect(policy.can('alice', 'edit', { $type: 'article', published: false }, {})).toEqual(false);
    });

    it('only applies a permission to the resource type it names', () => {
        const schema = defineSchema({
            actions: ['edit'],
            resources: {
                article: { locked: 'boolean' },
                comment: { locked: 'boolean' },
            },
            context: {},
        });
        const policy = new Policy(schema);
        policy.addRole('moderator', [
            { action: 'edit', resource: 'comment', condition: { property: 'locked', operator: 'eq', value: false, type: 'LiteralExpression' } },
        ]);
        policy.assignRole('mo', 'moderator');

        expect(policy.can('mo', 'edit', { $type: 'comment', locked: false })).toEqual(true);
        expect(policy.can('mo', 'edit', { $type: 'article', locked: false })).toEqual(false);
    });

    it('compares string literals', () => {
        const schema = defineSchema({
            actions: ['edit'],
            resources: { article: { status: 'string' } },
            context: {},
        });
        const policy = new Policy(schema);
        policy.addRole('writer', [
            { action: 'edit', resource: 'article', condition: { property: 'status', operator: 'eq', value: 'draft', type: 'LiteralExpression' } },
        ]);
        policy.assignRole('alice', 'writer');

        expect(policy.can('alice', 'edit', { $type: 'article', status: 'draft' })).toEqual(true);
        expect(policy.can('alice', 'edit', { $type: 'article', status: 'live' })).toEqual(false);
    });
});

describe('compound conditions', () => {
    it('grants editing your own drafts, or anything as a reviewer', () => {
        const policy = new Policy(cmsSchema);
        policy.addRole('writer', [{
            action: 'edit', resource: 'article', condition: {
                type: 'Or', conditions: [
                    { type: 'And', conditions: [
                        { type: 'LiteralExpression', property: 'published', operator: 'eq', value: false },
                        { type: 'ContextExpression', property: 'authorId', operator: 'eq', contextProperty: 'id' },
                    ] },
                    { type: 'Not', condition: { type: 'LiteralExpression', property: 'published', operator: 'eq', value: true } },
                ],
            },
        }]);
        policy.addRole('editor', [{
            action: 'edit', resource: 'article', condition: {
                type: 'Not', condition: { type: 'ContextExpression', property: 'authorId', operator: 'eq', contextProperty: 'id' },
            },
        }]);
        policy.assignRole('alice', 'writer');
        policy.assignRole('erin', 'editor');

        expect(policy.can('alice', 'edit', { $type: 'article', published: false, authorId: 'alice' }, { id: 'alice' })).toBe(true);
        expect(policy.can('alice', 'edit', { $type: 'article', published: true, authorId: 'alice' }, { id: 'alice' })).toBe(false);
        // editors may edit other people's articles, but not when ownership can't be established
        expect(policy.can('erin', 'edit', { $type: 'article', published: true, authorId: 'alice' }, { id: 'erin' })).toBe(true);
        expect(policy.can('erin', 'edit', { $type: 'article', published: true, authorId: 'erin' }, { id: 'erin' })).toBe(false);
        expect(policy.can('erin', 'edit', { $type: 'article', published: true }, { id: 'erin' })).toBe(false);
    });

    it('validates nested conditions at runtime', () => {
        const policy = new Policy(cmsSchema);
        const addUntyped = (condition: unknown) => policy.addRole('writer', [{ action: 'edit', resource: 'article', condition } as never]);

        expect(() => addUntyped({ type: 'And', conditions: [{ type: 'Not', condition: { type: 'LiteralExpression', property: 'nope', operator: 'eq', value: true } }] }))
            .toThrow(/unknown attribute "nope"/);
        expect(() => addUntyped({ type: 'Or' })).toThrow(/needs a "conditions" array/);
        expect(() => addUntyped({ type: 'Not' })).toThrow(/needs a "condition"/);
        expect(() => addUntyped({ type: 'Xor', conditions: [] })).toThrow(/unknown condition type "Xor"/);
    });
});

describe('validation', () => {
    it('rejects a resource attribute named "$type"', () => {
        expect(() => defineSchema({ actions: [], resources: { article: { $type: 'string' } }, context: {} }))
            .toThrow(/reserved attribute "\$type"/);
    });

    it('rejects duplicate declared roles', () => {
        expect(() => defineSchema({ roles: ['writer', 'writer'], actions: [], resources: {}, context: {} }))
            .toThrow(/duplicate roles/);
    });

    it('rejects roles the schema does not declare at runtime', () => {
        const policy = new Policy(cmsSchema);
        const untypedRole = 'wirter' as never;

        expect(() => policy.addRole(untypedRole, [])).toThrow(/Unknown role "wirter"/);
        expect(() => policy.assignRole('alice', untypedRole)).toThrow(/Unknown role "wirter"/);
    });

    it('accepts any role when the schema declares none', () => {
        const schema = defineSchema({ actions: ['edit'], resources: { article: {} }, context: {} });
        const policy = new Policy(schema);
        const roleFromDatabase: string = 'whatever';

        expect(() => policy.addRole(roleFromDatabase, [{ action: 'edit', resource: 'article', condition: true }])).not.toThrow();
    });

    it('rejects permissions that do not match the schema at runtime', () => {
        const policy = new Policy(cmsSchema);
        const addUntyped = (permission: unknown) => policy.addRole('writer', [permission as never]);

        expect(() => addUntyped({ action: 'delete', resource: 'article', condition: true })).toThrow(/unknown action/);
        expect(() => addUntyped({ action: 'edit', resource: 'page', condition: true })).toThrow(/unknown resource/);
        expect(() => addUntyped({ action: 'edit', resource: 'article', condition: { type: 'LiteralExpression', property: 'nope', operator: 'eq', value: true } })).toThrow(/unknown attribute/);
        expect(() => addUntyped({ action: 'edit', resource: 'article', condition: { type: 'LiteralExpression', property: 'published', operator: 'eq', value: 'yes' } })).toThrow(/is a boolean/);
        expect(() => addUntyped({ action: 'edit', resource: 'article', condition: { type: 'ContextExpression', property: 'published', operator: 'eq', contextProperty: 'id' } })).toThrow(/cannot compare/);
    });
});
