import { describe, expect, it } from 'vitest';
import { init, type Context } from 'z3-solver';
import { cmsSchema, createCmsPolicy } from './examples/cms.js';
import { Policy } from './policy.js';
import { PolicyEncoder } from './PolicyEncoder.js';
import type { Bool, Seq } from 'z3-solver';

async function z3Context(): Promise<Context> {
    const { Context } = await init();
    return new Context('main');
}

describe('PolicyEncoder', () => {
    it('creates a symbolic constant per schema attribute', async () => {
        const context = await z3Context();
        const encoder = new PolicyEncoder(createCmsPolicy(), context);

        const symbols = encoder.symbolsFor('article');

        expect(Object.keys(symbols.resource).sort()).toEqual(['authorId', 'published']);
        expect(Object.keys(symbols.context)).toEqual(['id']);
        expect(() => encoder.symbolsFor('page')).toThrow(/Unknown resource/);
    });

    it('can encode a literal condition', async () => {
        const context = await z3Context();
        const encoder = new PolicyEncoder(createCmsPolicy(), context);
        const symbols = encoder.symbolsFor('article');
        const published = symbols.resource['published'] as Bool;

        const encoded = encoder.encodeCondition({ operator: 'eq', property: 'published', value: false, type: 'LiteralExpression' }, symbols);

        const solver = new context.Solver();
        solver.add(encoded.neq(context.Not(published))); // refutation
        expect(await solver.check()).toEqual('unsat');
    });

    it('can encode a string literal condition', async () => {
        const context = await z3Context();
        const encoder = new PolicyEncoder(createCmsPolicy(), context);
        const symbols = encoder.symbolsFor('article');
        const authorId = symbols.resource['authorId'] as Seq;

        const encoded = encoder.encodeCondition({ operator: 'eq', property: 'authorId', value: 'alice', type: 'LiteralExpression' }, symbols);

        const solver = new context.Solver();
        solver.add(encoded.neq(authorId.eq(context.String.val('alice')))); // refutation
        expect(await solver.check()).toEqual('unsat');
    });

    it('encodes a context expression as equality between two symbolic strings', async () => {
        const context = await z3Context();
        const encoder = new PolicyEncoder(createCmsPolicy(), context);
        const symbols = encoder.symbolsFor('article');
        const authorId = symbols.resource['authorId'] as Seq;
        const actorId = symbols.context['id'] as Seq;

        const encoded = encoder.encodeCondition({ property: 'authorId', operator: 'eq', contextProperty: 'id', type: 'ContextExpression' }, symbols);

        const solver = new context.Solver();
        solver.add(encoded.neq(authorId.eq(actorId))); // refutation: encoded formula should always agree with the hand-written equivalent
        expect(await solver.check()).toEqual('unsat');
    });

    it('finds a role combination that can edit a published article', async () => {
        const policy = createCmsPolicy();
        const context = await z3Context();
        const encoder = new PolicyEncoder(policy, context);
        const symbols = encoder.symbolsFor('article');
        const published = symbols.resource['published'] as Bool;

        const solver = new context.Solver();
        solver.add(encoder.anyRoleCanDo('edit', 'article', symbols));
        solver.add(published.eq(true)); // pin: we only care about published articles
        expect(await solver.check()).toEqual('sat');

        // decode which role(s) the model's roleSet actually includes
        const model = solver.model();
        const impliedRoles = policy.getRoleBitVectors()
            .filter((rbv) => model.eval(encoder.holdsRole(encoder.vectorToMask(rbv.vector))).toString() === 'true')
            .map((rbv) => rbv.name);

        expect(impliedRoles).toContain('compliance_officer');
    });

    it('finds a role combination that can edit an article they do not own', async () => {
        // writer is ownership-gated; compliance_officer is an unconditional carve-out that
        // never checks ownership. That's the bypass we expect Z3 to find.
        const policy = new Policy(cmsSchema, {
            writer: [
            { action: 'edit', resource: 'article', condition: { property: 'authorId', operator: 'eq', contextProperty: 'id', type: 'ContextExpression' } }
        ],
            compliance_officer: [
            { action: 'edit', resource: 'article', condition: true },
        ],
        });

        const context = await z3Context();
        const encoder = new PolicyEncoder(policy, context);
        const symbols = encoder.symbolsFor('article');
        const authorId = symbols.resource['authorId'] as Seq;
        const actorId = symbols.context['id'] as Seq;

        const solver = new context.Solver();
        solver.add(encoder.anyRoleCanDo('edit', 'article', symbols));
        solver.add(authorId.neq(actorId)); // pin: the dangerous case -- the actor is NOT the article's author
        expect(await solver.check()).toEqual('sat');

        const model = solver.model();
        const impliedRoles = policy.getRoleBitVectors()
            .filter((rbv) => model.eval(encoder.holdsRole(encoder.vectorToMask(rbv.vector))).toString() === 'true')
            .map((rbv) => rbv.name);

        expect(impliedRoles).toContain('compliance_officer');
    });

    it('treats a role with no matching permission as unable to act', async () => {
        const context = await z3Context();
        const encoder = new PolicyEncoder(createCmsPolicy(), context);
        const symbols = encoder.symbolsFor('article');

        const solver = new context.Solver();
        solver.add(encoder.roleCanDo('publisher', 'edit', 'article', symbols));
        expect(await solver.check()).toEqual('unsat');
    });

    it('encodes And/Or/Not to the equivalent Z3 formula', async () => {
        const context = await z3Context();
        const encoder = new PolicyEncoder(createCmsPolicy(), context);
        const symbols = encoder.symbolsFor('article');
        const published = symbols.resource['published'] as Bool;
        const authorId = symbols.resource['authorId'] as Seq;
        const actorId = symbols.context['id'] as Seq;

        const encoded = encoder.encodeCondition({
            type: 'Or', conditions: [
                { type: 'And', conditions: [
                    { type: 'LiteralExpression', property: 'published', operator: 'eq', value: false },
                    { type: 'ContextExpression', property: 'authorId', operator: 'eq', contextProperty: 'id' },
                ] },
                { type: 'Not', condition: { type: 'LiteralExpression', property: 'authorId', operator: 'eq', value: 'bob' } },
            ],
        }, symbols);
        const handWritten = context.Or(context.And(context.Not(published), authorId.eq(actorId)), context.Not(authorId.eq(context.String.val('bob'))));

        const solver = new context.Solver();
        solver.add(encoded.neq(handWritten)); // refutation
        expect(await solver.check()).toEqual('unsat');
    });

    it('encodes empty And as true and empty Or as false', async () => {
        const context = await z3Context();
        const encoder = new PolicyEncoder(createCmsPolicy(), context);
        const symbols = encoder.symbolsFor('article');

        const solver = new context.Solver();
        solver.add(context.Not(encoder.encodeCondition({ type: 'And', conditions: [] }, symbols)));
        expect(await solver.check()).toEqual('unsat');

        const solver2 = new context.Solver();
        solver2.add(encoder.encodeCondition({ type: 'Or', conditions: [] }, symbols));
        expect(await solver2.check()).toEqual('unsat');
    });

    it('encodes a context-only condition', async () => {
        const context = await z3Context();
        const encoder = new PolicyEncoder(createCmsPolicy(), context);
        const symbols = encoder.symbolsFor('article');
        const actorId = symbols.context['id'] as Seq;

        const encoded = encoder.encodeCondition({ type: 'ContextLiteralExpression', contextProperty: 'id', operator: 'eq', value: 'alice' }, symbols);

        const solver = new context.Solver();
        solver.add(encoded.neq(actorId.eq(context.String.val('alice')))); // refutation
        expect(await solver.check()).toEqual('unsat');
    });
});
