// The CMS policy from cms.ts, written resource-centrically. Both build the same permissions.

import { definePolicy } from "../dsl.js";
import { cmsSchema, governedCmsSchema } from "./cms.js";

export function createCmsPolicyByResource() {
    return definePolicy(cmsSchema, ({ resource }) => {
        resource('article', (article) => {
            article.create(['writer']);
            article.edit({
                writer: { published: false },
                editor: { published: false },
                compliance_officer: true, // deliberate bypass: edits regardless of publication state
            });
            article.publish(['publisher']);
            article.unpublish({ publisher: { published: true } });
        });
    });
}

// The same policy in the chained style.
export function createCmsPolicyChained() {
    return definePolicy(cmsSchema, ({ resource }) => {
        resource('article')
            .can('create', ['writer'])
            .can('edit', ['writer', 'editor'], { published: false })
            .can('edit', ['compliance_officer'])
            .can('publish', ['publisher'])
            .can('unpublish', ['publisher'], { published: true });
    });
}

// With the schema's declared invariants (see governedCmsSchema): the grants live here, the
// rules that check them live in the schema.
export function createGovernedCmsPolicyByResource() {
    return definePolicy(governedCmsSchema, ({ resource }) => {
        resource('article', (article) => {
            article.create(['writer']);
            article.edit({
                writer: { published: false },
                editor: { published: false },
                compliance_officer: true,
            });
            article.publish(['publisher']);
            article.unpublish({ publisher: { published: true } });
        });
    });
}
