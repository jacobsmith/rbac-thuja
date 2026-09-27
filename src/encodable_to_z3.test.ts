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
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' } },
        ]);

        const { Context } = await init();
        const context = new Context('main');
        const encodableToZ3 = new EncodableToZ3(rbac, context);

        const published = context.Bool.const('published');
        const resource = { published, authorId: context.String.const('authorId') };
        const rbacContext = { id: context.String.const('id') };
        const encodedCondition = encodableToZ3.encodeCondition({ operator: 'eq', property: 'published', value: false, type: 'LiteralExpression' }, resource, rbacContext);

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
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' } },
        ]);

        const { Context } = await init();
        const context = new Context('main');
        const encodableToZ3 = new EncodableToZ3(rbac, context);

        const published = context.Bool.const('published');
        const resource = { published, authorId: context.String.const('authorId') };
        const rbacContext = { id: context.String.const('id') };
        const encodedConditions = encodableToZ3.getEncodedConditions(resource, rbacContext);
        
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
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' } },
        ]);
        rbac.addRole('editor', [
            { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' } }
        ]);
        rbac.addRole('publisher', [
            { action: 'publish', resource: 'article', condition: true },
            { action: 'unpublish', resource: 'article', condition: { property: 'published', operator: 'eq', value: true, type: 'LiteralExpression' } }
        ]);
        rbac.addRole('compliance_officer', [
            { action: 'edit', resource: 'article', condition: true },
        ]);

        const { Context } = await init();
        const context = new Context('main');
        const encodableToZ3 = new EncodableToZ3(rbac, context);

        const published = context.Bool.const('published');
        const resource = { published, authorId: context.String.const('authorId') };
        const rbacContext = { id: context.String.const('id') };
        const formula = encodableToZ3.anyRoleCanDo('edit', resource, rbacContext);

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

   it('encodes a context expression as equality between two symbolic strings', async () => {
        type CMSRole = 'writer';

        const rbac = new CmsRbac<CMSRole>();
        rbac.addRole('writer', [
            { action: 'edit', resource: 'article', condition: { property: 'authorId', operator: 'eq', contextProperty: 'id', type: 'ContextExpression' } }
        ]);

        const { Context } = await init();
        const context = new Context('main');
        const encodableToZ3 = new EncodableToZ3(rbac, context);

        const authorId = context.String.const('authorId');
        const actorId = context.String.const('actorId');

        const condition = { property: 'authorId', operator: 'eq', contextProperty: 'id', type: 'ContextExpression' } as const;
        const resource = { authorId, published: context.Bool.const('published') };
        const encoded = encodableToZ3.encodeCondition(condition, resource, { id: actorId });

        const solver = new context.Solver();
        solver.add(encoded.neq(authorId.eq(actorId))); // refutation: encoded formula should always agree with the hand-written equivalent

        const response = await solver.check();
        expect(response).toEqual('unsat');
   });
});