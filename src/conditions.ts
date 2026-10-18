import type { AnyCondition, AnyPermission, PolicySchema } from "./schema.js";

/**
 * Stable, human-readable identity for a condition, e.g. `published==false` or
 * `authorId==context.id`. Used in finding ids and fingerprints, so changing this
 * format invalidates every consumer's exceptions file.
 */
export function conditionKey(condition: AnyCondition): string {
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
    }
}

/**
 * Runtime evaluation. Fails closed: an attribute missing from the resource or
 * context never satisfies a condition.
 */
export function evaluateCondition(
    condition: AnyCondition,
    resource: Readonly<Record<string, unknown>> | undefined,
    context: Readonly<Record<string, unknown>> | undefined,
): boolean {
    if (condition === true) {
        return true;
    }
    if (!resource) {
        return false;
    }

    const resourceValue = resource[condition.property];
    if (resourceValue === undefined) {
        return false;
    }

    switch (condition.type) {
        case 'LiteralExpression': {
            return resourceValue === condition.value;
        }
        case 'ContextExpression': {
            const contextValue = context?.[condition.contextProperty];
            return contextValue !== undefined && resourceValue === contextValue;
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

    const condition = permission.condition;
    if (condition === true) {
        return;
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
