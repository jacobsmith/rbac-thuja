import { describe, expect, it } from 'vitest';
import { cmsPermissions, cmsSchema, createCmsPolicy } from './examples/cms.js';
import { Policy } from './policy.js';
import { defineSchema, type PolicySchema } from './schema.js';

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

    it('restricts editing to the resource author via a context expression', () => {
        const policy = new Policy(cmsSchema, {
            writer: [
            { action: 'edit', resource: 'article', condition: { property: 'authorId', operator: 'eq', contextProperty: 'id', type: 'ContextExpression' } }
        ],
        });
        policy.assignRole('alice', 'writer');

        const ownArticle = { $type: 'article' as const, published: true, authorId: 'alice' };
        const othersArticle = { $type: 'article' as const, published: true, authorId: 'bob' };

        expect(policy.can('alice', 'edit', ownArticle, { id: 'alice' })).toEqual(true);
        expect(policy.can('alice', 'edit', othersArticle, { id: 'alice' })).toEqual(false);
    });

    it('fails closed when a compared attribute is missing on both sides', () => {
        const policy = new Policy(cmsSchema, {
            writer: [
            { action: 'edit', resource: 'article', condition: { property: 'authorId', operator: 'eq', contextProperty: 'id', type: 'ContextExpression' } }
        ],
        });
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
        const policy = new Policy(schema, {
            moderator: [
            { action: 'edit', resource: 'comment', condition: { property: 'locked', operator: 'eq', value: false, type: 'LiteralExpression' } },
        ],
        });
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
        const policy = new Policy(schema, {
            writer: [
            { action: 'edit', resource: 'article', condition: { property: 'status', operator: 'eq', value: 'draft', type: 'LiteralExpression' } },
        ],
        });
        policy.assignRole('alice', 'writer');

        expect(policy.can('alice', 'edit', { $type: 'article', status: 'draft' })).toEqual(true);
        expect(policy.can('alice', 'edit', { $type: 'article', status: 'live' })).toEqual(false);
    });
});

describe('compound conditions', () => {
    it('grants editing your own drafts, or anything as a reviewer', () => {
        const policy = new Policy(cmsSchema, {
            writer: [{
            action: 'edit', resource: 'article', condition: {
                type: 'Or', conditions: [
                    { type: 'And', conditions: [
                        { type: 'LiteralExpression', property: 'published', operator: 'eq', value: false },
                        { type: 'ContextExpression', property: 'authorId', operator: 'eq', contextProperty: 'id' },
                    ] },
                    { type: 'Not', condition: { type: 'LiteralExpression', property: 'published', operator: 'eq', value: true } },
                ],
            },
        }],
            editor: [{
            action: 'edit', resource: 'article', condition: {
                type: 'Not', condition: { type: 'ContextExpression', property: 'authorId', operator: 'eq', contextProperty: 'id' },
            },
        }],
        });
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
        const addUntyped = (condition: unknown) => new Policy(cmsSchema, { writer: [{ action: 'edit', resource: 'article', condition } as never] });

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

    it('validates declared invariants at runtime', () => {
        const withInvariant = (invariant: unknown) => () => defineSchema({ ...cmsSchema, invariants: [invariant] as never });

        expect(withInvariant({ action: 'edit', resource: 'article', onlyRoles: ['writer'] })).toThrow(/needs a name/);
        expect(withInvariant({ name: 'x', action: 'delete', resource: 'article', onlyRoles: ['writer'] })).toThrow(/unknown action "delete"/);
        expect(withInvariant({ name: 'x', action: [], resource: 'article', onlyRoles: ['writer'] })).toThrow(/at least one action/);
        expect(withInvariant({ name: 'x', action: 'edit', resource: 'page', onlyRoles: ['writer'] })).toThrow(/unknown resource "page"/);
        expect(withInvariant({ name: 'x', action: 'edit', resource: 'article' })).toThrow(/needs "requires", "onlyRoles", or both/);
        expect(withInvariant({ name: 'x', action: 'edit', resource: 'article', onlyRoles: ['admin'] })).toThrow(/unknown role "admin"/);
        expect(withInvariant({ name: 'x', action: 'edit', resource: 'article', requires: { type: 'Not', condition: { type: 'LiteralExpression', property: 'nope', operator: 'eq', value: true } } }))
            .toThrow(/unknown attribute "nope"/);
        expect(() => defineSchema({ ...cmsSchema, invariants: [
            { name: 'dup', action: 'edit', resource: 'article', onlyRoles: ['writer'] },
            { name: 'dup', action: 'publish', resource: 'article', onlyRoles: ['writer'] },
        ] })).toThrow(/invariant "dup" more than once/);
    });

    it('builds from a schema and permissions loaded as data, e.g. from a database', () => {
        // JSON round trip: nothing about a policy depends on code
        const schema = JSON.parse(JSON.stringify(cmsSchema)) as PolicySchema;
        const permissions = JSON.parse(JSON.stringify(cmsPermissions));

        const policy = new Policy(schema, permissions);
        policy.assignRole('alice', 'writer');

        expect(policy.can('alice', 'edit', { $type: 'article', published: false })).toBe(true);
        expect(policy.can('alice', 'edit', { $type: 'article', published: true })).toBe(false);
        expect(() => new Policy(schema, { ...permissions, admin: [] })).toThrow(/Unknown role "admin"/);
    });

    it('rejects duplicate declared roles', () => {
        expect(() => defineSchema({ roles: ['writer', 'writer'], actions: [], resources: {}, context: {} }))
            .toThrow(/duplicate roles/);
    });

    it('rejects roles the schema does not declare at runtime', () => {
        const untypedRole = 'wirter' as never;

        expect(() => new Policy(cmsSchema, { [untypedRole]: [] })).toThrow(/Unknown role "wirter"/);
        expect(() => new Policy(cmsSchema).assignRole('alice', untypedRole)).toThrow(/Unknown role "wirter"/);
    });

    it('accepts any role when the schema declares none', () => {
        const schema = defineSchema({ actions: ['edit'], resources: { article: {} }, context: {} });
        const roleFromDatabase: string = 'whatever';

        expect(() => new Policy(schema, { [roleFromDatabase]: [{ action: 'edit', resource: 'article', condition: true }] })).not.toThrow();
    });

    it('rejects permissions that do not match the schema at runtime', () => {
        const addUntyped = (permission: unknown) => new Policy(cmsSchema, { writer: [permission as never] });

        expect(() => addUntyped({ action: 'delete', resource: 'article', condition: true })).toThrow(/unknown action/);
        expect(() => addUntyped({ action: 'edit', resource: 'page', condition: true })).toThrow(/unknown resource/);
        expect(() => addUntyped({ action: 'edit', resource: 'article', condition: { type: 'LiteralExpression', property: 'nope', operator: 'eq', value: true } })).toThrow(/unknown attribute/);
        expect(() => addUntyped({ action: 'edit', resource: 'article', condition: { type: 'LiteralExpression', property: 'published', operator: 'eq', value: 'yes' } })).toThrow(/is a boolean/);
        expect(() => addUntyped({ action: 'edit', resource: 'article', condition: { type: 'ContextExpression', property: 'published', operator: 'eq', contextProperty: 'id' } })).toThrow(/cannot compare/);
    });
});
