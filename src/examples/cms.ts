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
