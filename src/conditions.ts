import type { AnyCondition, AnyPermission, Attributes, PolicySchema } from "./schema.js";

/** The canonical never-true condition (an empty `Or`); there is no `false` literal. */
export const NEVER: AnyCondition = { type: 'Or', conditions: [] };

/**
 * Syntactic normal form, so trivially different spellings of a condition share an
 * identity: nested And/Or are flattened, children deduplicated and sorted, double
 * negation removed, `true` absorbed, and single-child And/Or unwrapped.
 * It doesn't decide semantic equivalence; the scan uses Z3 for that.
 */
export function normalizeCondition(condition: AnyCondition): AnyCondition {
    if (condition === true) {
        return true;
    }

    switch (condition.type) {
        case 'LiteralExpression':
        case 'ContextExpression': {
            return condition;
        }
        case 'Not': {
            const inner = normalizeCondition(condition.condition);
            if (inner !== true && inner.type === 'Not') {
                return inner.condition;
            }
            if (inner === true) {
                return NEVER;
            }
            if (isNever(inner)) {
                return true;
            }
            return { type: 'Not', condition: inner };
        }
        case 'And':
        case 'Or': {
            const isAnd = condition.type === 'And';
            const children = new Map<string, AnyCondition>();

            for (const child of condition.conditions.map(normalizeCondition)) {
                // the identity element (true for And, never for Or) drops out...
                if (isAnd ? child === true : isNever(child)) {
                    continue;
                }
                // ...and the absorbing element decides the whole expression
                if (isAnd ? isNever(child) : child === true) {
                    return isAnd ? NEVER : true;
                }
                const grandchildren = child !== true && child.type === condition.type ? child.conditions : [child];
                for (const grandchild of grandchildren) {
                    children.set(renderKey(grandchild), grandchild);
                }
            }

            const sorted = [...children.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, child]) => child);
            if (sorted.length === 0) {
                return isAnd ? true : NEVER;
            }
            if (sorted.length === 1) {
                return sorted[0] as AnyCondition;
            }
            return { type: condition.type, conditions: sorted };
        }
    }
}

function isNever(condition: AnyCondition): boolean {
    return condition !== true && condition.type === 'Or' && condition.conditions.length === 0;
}

/**
 * Stable, human-readable identity for a condition, e.g. `published==false`,
 * `authorId==context.id` or `(!(archived==true) && published==false)`. Used in finding ids
 * and fingerprints, so changing this format invalidates every consumer's exceptions file.
 */
export function conditionKey(condition: AnyCondition): string {
    return renderKey(normalizeCondition(condition));
}

function renderKey(condition: AnyCondition): string {
    if (condition === true) {
        return 'true';
    }

    switch (condition.type) {
        case 'LiteralExpression': {
            return `${condition.property}==${JSON.stringify(condition.value)}`;
        }
        case 'ContextExpression': {
            return `${condition.property}==context.${condition.contextProperty}`;
        }
        case 'Not': {
            const inner = renderKey(condition.condition);
            return inner.startsWith('(') ? `!${inner}` : `!(${inner})`;
        }
        case 'And':
        case 'Or': {
            if (condition.conditions.length === 0) {
                return condition.type === 'And' ? 'true' : 'false';
            }
            return `(${condition.conditions.map(renderKey).join(condition.type === 'And' ? ' && ' : ' || ')})`;
        }
    }
}

/**
 * Runtime evaluation. Fails closed: only a definite `true` grants.
 *
 * A comparison involving a missing resource/context attribute is *unknown* rather than
 * false, and unknown propagates through And/Or/Not with Kleene's three-valued logic.
 * Otherwise `Not(published == true)` would grant on a resource with no `published`.
 */
export function evaluateCondition(
    condition: AnyCondition,
    resource: Readonly<Record<string, unknown>> | undefined,
    context: Readonly<Record<string, unknown>> | undefined,
): boolean {
    return evaluate(condition, resource, context) === true;
}

type Truth = boolean | undefined; // undefined = unknown

function evaluate(
    condition: AnyCondition,
    resource: Readonly<Record<string, unknown>> | undefined,
    context: Readonly<Record<string, unknown>> | undefined,
): Truth {
    if (condition === true) {
        return true;
    }

    switch (condition.type) {
        case 'LiteralExpression': {
            const resourceValue = resource?.[condition.property];
            return resourceValue === undefined ? undefined : resourceValue === condition.value;
        }
        case 'ContextExpression': {
            const resourceValue = resource?.[condition.property];
            const contextValue = context?.[condition.contextProperty];
            return resourceValue === undefined || contextValue === undefined ? undefined : resourceValue === contextValue;
        }
        case 'Not': {
            const inner = evaluate(condition.condition, resource, context);
            return inner === undefined ? undefined : !inner;
        }
        case 'And': {
            let result: Truth = true;
            for (const child of condition.conditions) {
                const value = evaluate(child, resource, context);
                if (value === false) {
                    return false;
                }
                if (value === undefined) {
                    result = undefined;
                }
            }
            return result;
        }
        case 'Or': {
            let result: Truth = false;
            for (const child of condition.conditions) {
                const value = evaluate(child, resource, context);
                if (value === true) {
                    return true;
                }
                if (value === undefined) {
                    result = undefined;
                }
            }
            return result;
        }
    }
}

/** Runtime check for consumers not using TypeScript (or casting around it). */
export function validatePermission(schema: PolicySchema, role: string, permission: AnyPermission) {
    const where = `Role "${role}" permission (${permission.action} on ${permission.resource})`;

    if (!schema.actions.includes(permission.action)) {
        throw new Error(`${where}: unknown action "${permission.action}".`);
    }
    const attributes = schema.resources[permission.resource];
    if (!attributes) {
        throw new Error(`${where}: unknown resource "${permission.resource}".`);
    }

    validateCondition(schema, attributes, permission.condition, where);
}

function validateCondition(schema: PolicySchema, attributes: Attributes, condition: AnyCondition, where: string) {
    if (condition === true) {
        return;
    }

    switch (condition.type) {
        case 'And':
        case 'Or': {
            if (!Array.isArray(condition.conditions)) {
                throw new Error(`${where}: ${condition.type} needs a "conditions" array.`);
            }
            condition.conditions.forEach((child) => validateCondition(schema, attributes, child, where));
            return;
        }
        case 'Not': {
            if (condition.condition === undefined) {
                throw new Error(`${where}: Not needs a "condition".`);
            }
            validateCondition(schema, attributes, condition.condition, where);
            return;
        }
        case 'LiteralExpression':
        case 'ContextExpression': {
            break;
        }
        default: {
            throw new Error(`${where}: unknown condition type ${JSON.stringify((condition as { type: unknown }).type)}.`);
        }
    }

    const attributeType = attributes[condition.property];
    if (!attributeType) {
        throw new Error(`${where}: unknown attribute "${condition.property}".`);
    }

    switch (condition.type) {
        case 'LiteralExpression': {
            if (typeof condition.value !== attributeType) {
                throw new Error(`${where}: "${condition.property}" is a ${attributeType}, got ${JSON.stringify(condition.value)}.`);
            }
            return;
        }
        case 'ContextExpression': {
            const contextType = schema.context[condition.contextProperty];
            if (contextType !== attributeType) {
                throw new Error(`${where}: cannot compare ${attributeType} "${condition.property}" with context "${condition.contextProperty}".`);
            }
            return;
        }
    }
}
