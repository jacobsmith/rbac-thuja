import { describe, expect, it } from 'vitest';
import { conditionKey, evaluateCondition, normalizeCondition } from './conditions.js';
import type { AnyCondition } from './schema.js';

const published = (value: boolean): AnyCondition => ({ type: 'LiteralExpression', property: 'published', operator: 'eq', value });
const owner: AnyCondition = { type: 'ContextExpression', property: 'authorId', operator: 'eq', contextProperty: 'id' };
const draft: AnyCondition = { type: 'LiteralExpression', property: 'status', operator: 'eq', value: 'draft' };
const and = (...conditions: Array<AnyCondition>): AnyCondition => ({ type: 'And', conditions });
const or = (...conditions: Array<AnyCondition>): AnyCondition => ({ type: 'Or', conditions });
const not = (condition: AnyCondition): AnyCondition => ({ type: 'Not', condition });

describe('conditionKey', () => {
    it('keeps atomic keys unchanged, so existing exceptions files stay valid', () => {
        expect(conditionKey(true)).toEqual('true');
        expect(conditionKey(published(false))).toEqual('published==false');
        expect(conditionKey(owner)).toEqual('authorId==context.id');
        expect(conditionKey(draft)).toEqual('status=="draft"');
    });

    it('renders compound conditions', () => {
        expect(conditionKey(and(published(false), not(owner)))).toEqual('(!(authorId==context.id) && published==false)');
        expect(conditionKey(not(or(owner, draft)))).toEqual('!(authorId==context.id || status=="draft")');
    });

    it('gives trivially different spellings the same key', () => {
        const key = conditionKey(and(published(false), or(owner, draft)));

        expect(conditionKey(and(or(draft, owner), published(false)))).toEqual(key); // order
        expect(conditionKey(and(published(false), and(or(owner, draft))))).toEqual(key); // nesting
        expect(conditionKey(and(published(false), published(false), or(owner, draft)))).toEqual(key); // duplicates
        expect(conditionKey(and(not(not(published(false))), or(owner, draft)))).toEqual(key); // double negation
        expect(conditionKey(and(true, published(false), or(owner, draft)))).toEqual(key); // identity
    });
});

describe('normalizeCondition', () => {
    it('absorbs and collapses constants', () => {
        expect(normalizeCondition(or(owner, true))).toEqual(true);
        expect(normalizeCondition(and())).toEqual(true);
        expect(conditionKey(or())).toEqual('false');
        expect(conditionKey(and(owner, or()))).toEqual('false');
        expect(normalizeCondition(not(or()))).toEqual(true);
        expect(conditionKey(not(true))).toEqual('false');
        expect(normalizeCondition(and(owner))).toEqual(owner);
    });

    it('does not apply De Morgan (Z3 decides semantic equivalence)', () => {
        expect(conditionKey(not(and(owner, draft)))).not.toEqual(conditionKey(or(not(owner), not(draft))));
    });
});

describe('evaluateCondition', () => {
    const article = { published: false, authorId: 'alice', status: 'draft' };

    it('evaluates And/Or/Not', () => {
        expect(evaluateCondition(and(published(false), owner), article, { id: 'alice' })).toBe(true);
        expect(evaluateCondition(and(published(false), owner), article, { id: 'bob' })).toBe(false);
        expect(evaluateCondition(or(published(true), owner), article, { id: 'alice' })).toBe(true);
        expect(evaluateCondition(not(owner), article, { id: 'bob' })).toBe(true);
        expect(evaluateCondition(and(), article, {})).toBe(true);
        expect(evaluateCondition(or(), article, {})).toBe(false);
    });

    it('fails closed under negation when an attribute is missing', () => {
        // `published` is unknown, so "not published" is unknown too: deny
        expect(evaluateCondition(not(published(true)), { authorId: 'alice' }, {})).toBe(false);
        expect(evaluateCondition(not(owner), { published: false }, { id: 'alice' })).toBe(false);
        expect(evaluateCondition(not(owner), article, {})).toBe(false);
    });

    it('uses three-valued logic: a definite answer wins over an unknown one', () => {
        const noPublished = { authorId: 'alice' };
        expect(evaluateCondition(or(published(true), owner), noPublished, { id: 'alice' })).toBe(true); // unknown || true
        expect(evaluateCondition(and(published(true), owner), noPublished, { id: 'bob' })).toBe(false); // unknown && false
        expect(evaluateCondition(and(published(true), owner), noPublished, { id: 'alice' })).toBe(false); // unknown && true: deny
        expect(evaluateCondition(not(and(published(true), owner)), noPublished, { id: 'bob' })).toBe(true); // !(unknown && false)
    });
});
