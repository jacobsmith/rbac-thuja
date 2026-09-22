import { describe, expect, it } from 'vitest';
import { init } from 'z3-solver';
import { CmsRbac } from './cms_rbac';
import { EncodableToZ3 } from './EncodableToZ3';

describe('EncodableToZ3', () => {
    it('can encode conditions', async () => {
        type CMSRole = 'writer' | 'publisher' | 'editor' | 'compliance_officer';

        const rbac = new CmsRbac<CMSRole>();
        rbac.addRole('writer', [
            { action: 'create', resource: 'article', condition: true },
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false } },
        ]);

        const { Context } = await init();
        const context = new Context('main');
        const encodableToZ3 = new EncodableToZ3(rbac, context);

        const published = context.Bool.const('published');
        // I don't quite understand the "context" within z3 and how that works
        const encodedCondition = encodableToZ3.encodeCondition({ operator: 'eq', property: 'published', value: false }, published);
        
        const solver = new context.Solver();
        solver.add(encodedCondition.neq(context.Not(published))); // refutation

        const response = await solver.check();

        expect(response).toEqual('unsat');


   });
});