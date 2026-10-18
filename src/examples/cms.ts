import { Policy } from "../policy.js";
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

export function createCmsPolicy() {
    const policy = new Policy(cmsSchema);
    policy.addRole('writer', [
        { action: 'create', resource: 'article', condition: true },
        { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' } },
    ]);
    policy.addRole('editor', [
        { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' } },
    ]);
    policy.addRole('publisher', [
        { action: 'publish', resource: 'article', condition: true },
        { action: 'unpublish', resource: 'article', condition: { property: 'published', operator: 'eq', value: true, type: 'LiteralExpression' } },
    ]);
    // Deliberate bypass: edits regardless of publication state.
    policy.addRole('compliance_officer', [
        { action: 'edit', resource: 'article', condition: true },
    ]);
    return policy;
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
    const policy = new Policy(governedCmsSchema);
    const plain = createCmsPolicy();
    for (const role of plain.getRoles()) {
        policy.addRole(role, plain.getPermissions(role) as never);
    }
    return policy;
}
