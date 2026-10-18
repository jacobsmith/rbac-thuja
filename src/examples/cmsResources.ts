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
            article.read({ writer: live, editor: live, publisher: live, compliance_officer: live });
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
            .can('read', ['writer', 'editor', 'publisher', 'compliance_officer'], live)
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
            article.read({ writer: live, editor: live, publisher: live, compliance_officer: live }); // public: no sign-in needed
            article.edit({ writer: draft, editor: draft, compliance_officer: true }); // guarded: signed-in users only
            article.publish(['publisher']);
            article.unpublish({ publisher: live });
        });
    });
}
