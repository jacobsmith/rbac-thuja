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
    
   it('can encode all conditions', async () => {
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
        const encodedConditions = encodableToZ3.getEncodedConditions(published);
        
        const solver = new context.Solver();
        for (const condition of encodedConditions) {
            solver.add(condition.neq(context.Not(published))); // refutation
        }

        const response = await solver.check();

        console.log('ahhh, ', response);

        expect(response).toEqual('unsat');


   });

   it('finds a role combination that can edit a published article', async () => {
        type CMSRole = 'writer' | 'publisher' | 'editor' | 'compliance_officer';

        const rbac = new CmsRbac<CMSRole>();
        rbac.addRole('writer', [
            { action: 'create', resource: 'article', condition: true },
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false } },
        ]);
        rbac.addRole('editor', [
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false } }
        ]);
        rbac.addRole('publisher', [
            { action: 'publish', resource: 'article', condition: true },
            { action: 'unpublish', resource: 'article', condition: { property: 'published', operator: 'eq', value: true } }
        ]);
        rbac.addRole('compliance_officer', [
            { action: 'edit', resource: 'article', condition: true },
        ]);

        const { Context } = await init();
        const context = new Context('main');
        const encodableToZ3 = new EncodableToZ3(rbac, context);

        const published = context.Bool.const('published');
        const formula = encodableToZ3.anyRoleCanDo('edit', published);

        const solver = new context.Solver();
        solver.add(formula);
        solver.add(published.eq(true)); // pin: we only care about published articles

        const response = await solver.check();
        expect(response).toEqual('sat');

        // decode which role(s) the model's roleSet actually includes
        const model = solver.model();
        const roleBitVectors = rbac.getRoleBitVectors();
        const impliedRoles = roleBitVectors
            .filter((rbv) => {
                const mask = encodableToZ3.vectorToMask(rbv.vector);
                const membership = encodableToZ3.holdsRole(mask);
                return model.eval(membership).toString() === 'true';
            })
            .map((rbv) => rbv.name);

        console.log('role(s) that satisfy the violation:', impliedRoles);
        expect(impliedRoles).toContain('compliance_officer');
   });
});