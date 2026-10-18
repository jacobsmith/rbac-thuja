// The CMS policy written resource-centrically: the primary way to write a Thuja policy.
// It compiles to exactly the permissions in cms.ts.

import { definePolicy } from "../dsl.js";
import { cmsSchema, governedCmsSchema } from "./cms.js";

// Shared conditions are plain values: define them once, reuse them anywhere.
const draft = { published: false };
const live = { published: true };

export function createCmsPolicyByResource() {
    return definePolicy(cmsSchema, ({ resource }) => {
        resource('article', (article) => {
            article.create(['writer']);
            article.edit({
                writer: draft,
                editor: draft,
                compliance_officer: true, // deliberate bypass: edits regardless of publication state
            });
            article.publish(['publisher']);
            article.unpublish({ publisher: live });
        });
    });
}

// The same policy in the chained style.
export function createCmsPolicyChained() {
    return definePolicy(cmsSchema, ({ resource }) => {
        resource('article')
            .can('create', ['writer'])
            .can('edit', ['writer', 'editor'], draft)
            .can('edit', ['compliance_officer'])
            .can('publish', ['publisher'])
            .can('unpublish', ['publisher'], live);
    });
}

// With the schema's declared invariants (see governedCmsSchema): the grants live here, the
// rules that check them live in the schema.
export function createGovernedCmsPolicyByResource() {
    return definePolicy(governedCmsSchema, ({ resource }) => {
        resource('article', (article) => {
            article.create(['writer']);
            article.edit({ writer: draft, editor: draft, compliance_officer: true });
            article.publish(['publisher']);
            article.unpublish({ publisher: live });
        });
    });
}
