import { Policy, type PermissionsByRole } from "../policy.js";
import { defineSchema, type RoleName } from "../schema.js";

export const cmsSchema = defineSchema({
    roles: ['writer', 'editor', 'publisher', 'compliance_officer'],
    actions: ['create', 'edit', 'publish', 'unpublish'],
    resources: {
        article: { published: 'boolean', authorId: 'string' },
    },
    context: { id: 'string' },
});

export type CMSRole = RoleName<typeof cmsSchema>;

// The raw data form: what definePolicy (see cmsResources.ts) compiles to, and what a
// database, config file or another DSL could produce directly.
export const cmsPermissions: PermissionsByRole<typeof cmsSchema> = {
    writer: [
        { action: 'create', resource: 'article', condition: true },
        { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' } },
    ],
    editor: [
        { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' } },
    ],
    publisher: [
        { action: 'publish', resource: 'article', condition: true },
        { action: 'unpublish', resource: 'article', condition: { property: 'published', operator: 'eq', value: true, type: 'LiteralExpression' } },
    ],
    // Deliberate bypass: edits regardless of publication state.
    compliance_officer: [
        { action: 'edit', resource: 'article', condition: true },
    ],
};

export function createCmsPolicy() {
    return new Policy(cmsSchema, cmsPermissions);
}

// The same CMS with its rules declared up front: Thuja enforces these instead of
// inferring rules from what most roles do.
export const governedCmsSchema = defineSchema({
    ...cmsSchema,
    invariants: [
        {
            name: 'edit-unpublished-only',
            action: 'edit',
            resource: 'article',
            requires: { type: 'LiteralExpression', property: 'published', operator: 'eq', value: false },
        },
        {
            name: 'only-publishers-publish',
            action: ['publish', 'unpublish'],
            resource: 'article',
            onlyRoles: ['publisher'],
        },
    ],
});

export function createGovernedCmsPolicy() {
    return new Policy(governedCmsSchema, cmsPermissions);
}
