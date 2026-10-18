import { describe, expect, it } from 'vitest';
import { cmsPermissions, cmsSchema, createCmsPolicy } from './examples/cms.js';
import { Policy } from './policy.js';
import { contextIs, defineSchema, type PolicySchema } from './schema.js';

describe('roles', () => {
    it('default to false', () => {
        const policy = createCmsPolicy();
        const alice = { roles: ['writer'] } as const;

        expect(policy.can(alice, 'publish')).toEqual(false);
        expect(policy.can({ roles: [] }, 'create')).toEqual(false);
    });

    it('evaluates non-conditionals correctly', () => {
        const policy = createCmsPolicy();
        const alice = { roles: ['writer'] } as const;

        expect(policy.can(alice, 'create')).toEqual(true);
    });

    it('evaluates conditionals correctly', () => {
        const policy = createCmsPolicy();
        const alice = { roles: ['writer'] } as const;

        expect(policy.can(alice, 'edit', { $type: 'article', published: true })).toEqual(false);
        expect(policy.can(alice, 'edit', { $type: 'article', published: false })).toEqual(true);
    });

    it('allows multiple roles', () => {
        const policy = createCmsPolicy();
        const alice = { roles: ['writer', 'publisher'] } as const;

        expect(policy.can(alice, 'create')).toEqual(true);
        expect(policy.can(alice, 'edit', { $type: 'article', published: true })).toEqual(false);
        expect(policy.can(alice, 'publish', { $type: 'article', published: false })).toEqual(true);
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
        const alice = { roles: ['writer'], id: 'alice' } as const;

        const ownArticle = { $type: 'article' as const, published: true, authorId: 'alice' };
        const othersArticle = { $type: 'article' as const, published: true, authorId: 'bob' };

        expect(policy.can(alice, 'edit', ownArticle)).toEqual(true);
        expect(policy.can(alice, 'edit', othersArticle)).toEqual(false);
    });

    it('fails closed when a compared attribute is missing on both sides', () => {
        const policy = new Policy(cmsSchema, {
            writer: [
            { action: 'edit', resource: 'article', condition: { property: 'authorId', operator: 'eq', contextProperty: 'id', type: 'ContextExpression' } }
        ],
        });
        const alice = { roles: ['writer'] } as const;

        // undefined == undefined must not count as "is the author"
        expect(policy.can(alice, 'edit', { $type: 'article', published: false })).toEqual(false);
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
        const mo = { roles: ['moderator'] } as const;

        expect(policy.can(mo, 'edit', { $type: 'comment', locked: false })).toEqual(true);
        expect(policy.can(mo, 'edit', { $type: 'article', locked: false })).toEqual(false);
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
        const alice = { roles: ['writer'] } as const;

        expect(policy.can(alice, 'edit', { $type: 'article', status: 'draft' })).toEqual(true);
        expect(policy.can(alice, 'edit', { $type: 'article', status: 'live' })).toEqual(false);
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
        const alice = { roles: ['writer'], id: 'alice' } as const;
        const erin = { roles: ['editor'], id: 'erin' } as const;

        expect(policy.can(alice, 'edit', { $type: 'article', published: false, authorId: 'alice' })).toBe(true);
        expect(policy.can(alice, 'edit', { $type: 'article', published: true, authorId: 'alice' })).toBe(false);
        // editors may edit other people's articles, but not when ownership can't be established
        expect(policy.can(erin, 'edit', { $type: 'article', published: true, authorId: 'alice' })).toBe(true);
        expect(policy.can(erin, 'edit', { $type: 'article', published: true, authorId: 'erin' })).toBe(false);
        expect(policy.can(erin, 'edit', { $type: 'article', published: true })).toBe(false);
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

describe('guards and context-only conditions', () => {
    const schema = defineSchema({
        roles: ['visitor', 'writer'],
        actions: ['read', 'edit'],
        resources: { article: { published: 'boolean', authorId: 'string' } },
        context: { id: 'string', authenticated: 'boolean' },
        public: [{ action: 'read', resource: 'article' }],
        guards: [{ name: 'authenticated', requires: contextIs('authenticated', true), except: 'public' }],
    });
    const policy = new Policy(schema, {
        visitor: [{ action: 'read', resource: 'article', condition: { type: 'LiteralExpression', property: 'published', operator: 'eq', value: true } }],
        writer: [
            { action: 'read', resource: 'article', condition: true },
            { action: 'edit', resource: 'article', condition: true }, // the guard still applies
        ],
    });
    const live = { $type: 'article', published: true, authorId: 'alice' } as const;

    it('lets anyone with a role act on a public pair, signed in or not', () => {
        expect(policy.can({ roles: ['visitor'], authenticated: false }, 'read', live)).toBe(true);
        expect(policy.can({ roles: ['visitor'] }, 'read', live)).toBe(true);
    });

    it('enforces the guard on every other grant, even unconditional ones', () => {
        expect(policy.can({ roles: ['writer'], authenticated: true }, 'edit', live)).toBe(true);
        expect(policy.can({ roles: ['writer'], authenticated: false }, 'edit', live)).toBe(false);
        expect(policy.can({ roles: ['writer'] }, 'edit', live)).toBe(false); // unknown: fail closed
    });

    it('supports permissions that depend only on the actor', () => {
        const mfaSchema = defineSchema({ ...schema, guards: [], context: { id: 'string', authenticated: 'boolean', mfa: 'boolean' } });
        const strict = new Policy(mfaSchema, {
            writer: [{ action: 'edit', resource: 'article', condition: { type: 'ContextLiteralExpression', contextProperty: 'mfa', operator: 'eq', value: true } }],
        });

        expect(strict.can({ roles: ['writer'], mfa: true }, 'edit', live)).toBe(true);
        expect(strict.can({ roles: ['writer'], mfa: true }, 'edit')).toBe(true); // no resource attributes needed
        expect(strict.can({ roles: ['writer'], mfa: false }, 'edit', live)).toBe(false);
    });

    it('validates guards, public entries and context at runtime', () => {
        const base = { roles: ['writer'], actions: ['edit'], resources: { article: { published: 'boolean' } }, context: { authenticated: 'boolean' } } as const;
        const make = (extra: object) => () => defineSchema({ ...base, ...extra } as never);

        expect(make({ guards: [{ name: 'g', requires: { type: 'LiteralExpression', property: 'published', operator: 'eq', value: true } }] }))
            .toThrow(/guards can only reference context.*unknown attribute "published"/);
        expect(make({ guards: [{ name: 'g', requires: contextIs('nope', true) }] })).toThrow(/unknown context attribute "nope"/);
        expect(make({ guards: [{ name: 'g', requires: contextIs('authenticated', 'yes') }] })).toThrow(/is a boolean/);
        expect(make({ guards: [{ name: 'g', requires: true, except: 'private' }] })).toThrow(/"except" can only be 'public'/);
        expect(make({ guards: [{ name: 'g', requires: true }, { name: 'g', requires: true }] })).toThrow(/guard "g" more than once/);
        expect(make({ public: [{ action: 'delete', resource: 'article' }] })).toThrow(/Public entry: unknown action "delete"/);
        expect(make({ context: { roles: 'string' } })).toThrow(/reserved attribute "roles"/);
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
        const alice = { roles: ['writer'] } as const;

        expect(policy.can(alice, 'edit', { $type: 'article', published: false })).toBe(true);
        expect(policy.can(alice, 'edit', { $type: 'article', published: true })).toBe(false);
        expect(() => new Policy(schema, { ...permissions, admin: [] })).toThrow(/Unknown role "admin"/);
    });

    it('rejects duplicate declared roles', () => {
        expect(() => defineSchema({ roles: ['writer', 'writer'], actions: [], resources: {}, context: {} }))
            .toThrow(/duplicate roles/);
    });

    it('rejects roles the schema does not declare at runtime', () => {
        const untypedRole = 'wirter' as never;

        expect(() => new Policy(cmsSchema, { [untypedRole]: [] })).toThrow(/Unknown role "wirter"/);
        // at request time an unknown role just grants nothing, rather than throwing
        expect(new Policy(cmsSchema, cmsPermissions).can({ roles: [untypedRole] }, 'create')).toBe(false);
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
