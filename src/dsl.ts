// Resource-centric way to write a policy: grants are grouped by resource and action, so every
// role's condition for "edit article" sits side by side, the way the scan analyzes them.
// Everything compiles to the plain condition objects the rest of Thuja uses.

import { conditionKey } from "./conditions.js";
import { Policy } from "./policy.js";
import type {
    Action,
    AnyCondition,
    AnyPermission,
    AttributeType,
    AttributeValue,
    Condition,
    PolicySchema,
    ResourceName,
    RoleName,
} from "./schema.js";

/** Stands for "the acting user's <property>" inside a condition, e.g. `ctx.id`. */
export type ContextRef<T extends AttributeType = AttributeType, K extends string = string> = {
    readonly kind: 'context',
    readonly property: K,
    readonly valueType: T,
};

export type ContextRefs<S extends PolicySchema> = {
    readonly [K in keyof S['context'] & string]: ContextRef<S['context'][K], K>
};

type ResourceAttributes<S extends PolicySchema, R extends ResourceName<S>> = S['resources'][R];

/**
 * `{ published: false, authorId: ctx.id }`: every listed attribute must equal its value
 * (a literal, or a context attribute of the same type).
 */
export type Shorthand<S extends PolicySchema, R extends ResourceName<S>> = {
    readonly [P in keyof ResourceAttributes<S, R> & string]?:
        | AttributeValue<ResourceAttributes<S, R>[P]>
        | ContextRef<ResourceAttributes<S, R>[P]>
};

/** A condition built with `any`, `all`, `not` or `raw`. */
export class Expr {
    readonly condition: AnyCondition;

    constructor(condition: AnyCondition) {
        this.condition = condition;
    }
}

export type ConditionInput<S extends PolicySchema, R extends ResourceName<S>> = true | Shorthand<S, R> | Expr;

/** Roles that may act unconditionally, or each role's condition. */
export type Grants<S extends PolicySchema, R extends ResourceName<S>> =
    | ReadonlyArray<RoleName<S>>
    | { readonly [Role in RoleName<S>]?: ConditionInput<S, R> };

export type ResourceBuilder<S extends PolicySchema, R extends ResourceName<S>> = {
    /** `article.edit({ writer: { published: false }, editor: true })` or `article.edit(['editor'])`. */
    readonly [A in Action<S>]: (grants: Grants<S, R>) => ResourceBuilder<S, R>
} & {
    /** Chainable form: `article.can('edit', ['writer'], { published: false })`. */
    can(action: Action<S>, roles: ReadonlyArray<RoleName<S>>, condition?: ConditionInput<S, R>): ResourceBuilder<S, R>,
};

/** Condition combinators typed for one resource. */
export type Operators<S extends PolicySchema, R extends ResourceName<S>> = {
    any(...conditions: Array<ConditionInput<S, R>>): Expr,
    all(...conditions: Array<ConditionInput<S, R>>): Expr,
    not(condition: ConditionInput<S, R>): Expr,
    /** Escape hatch for a hand-written condition object. */
    raw(condition: Condition<S['resources'][R], S['context']>): Expr,
    ctx: ContextRefs<S>,
};

export type PolicyDefinition<S extends PolicySchema> = {
    resource<R extends ResourceName<S>>(name: R, body?: (resource: ResourceBuilder<S, R>, operators: Operators<S, R>) => void): ResourceBuilder<S, R>,
    ctx: ContextRefs<S>,
};

/**
 * Builds a Policy from resource-centric declarations:
 *
 * ```ts
 * definePolicy(schema, ({ resource, ctx }) => {
 *   resource('article', (article) => {
 *     article.edit({ writer: { published: false, authorId: ctx.id }, editor: true });
 *     article.publish(['publisher']);
 *   });
 * });
 * ```
 */
export function definePolicy<S extends PolicySchema>(schema: S, define: (definition: PolicyDefinition<S>) => void): Policy<S> {
    const permissionsByRole = new Map<string, Array<AnyPermission>>();
    const ctx = contextRefs(schema);

    const grant = (role: string, action: string, resource: string, input: unknown) => {
        const permissions = permissionsByRole.get(role) ?? [];
        permissions.push({ action, resource, condition: compile(input, resource, `${role} ${action} ${resource}`) });
        permissionsByRole.set(role, permissions);
    };

    const resource = (name: string, body?: (resource: never, operators: never) => void) => {
        if (!schema.resources[name]) {
            throw new Error(`Unknown resource "${name}".`);
        }
        const builder: Record<string, unknown> = {};
        builder['can'] = (action: string, roles: ReadonlyArray<string>, condition: unknown = true) => {
            roles.forEach((role) => grant(role, action, name, condition));
            return builder;
        };
        for (const action of schema.actions) {
            builder[action] = (grants: ReadonlyArray<string> | Record<string, unknown>) => {
                if (Array.isArray(grants)) {
                    grants.forEach((role) => grant(role, action, name, true));
                } else {
                    Object.entries(grants).forEach(([role, input]) => input !== undefined && grant(role, action, name, input));
                }
                return builder;
            };
        }
        body?.(builder as never, operators(ctx, name) as never);
        return builder;
    };

    define({ resource, ctx } as unknown as PolicyDefinition<S>);

    const policy = new Policy(schema);
    for (const [role, permissions] of permissionsByRole) {
        policy.addRole(role as RoleName<S>, permissions as never);
    }
    return policy;
}

function contextRefs(schema: PolicySchema): Record<string, ContextRef> {
    return Object.fromEntries(Object.entries(schema.context).map(([property, valueType]) =>
        [property, Object.freeze({ kind: 'context' as const, property, valueType })]));
}

function operators(ctx: Record<string, ContextRef>, resource: string) {
    const compileAll = (inputs: Array<unknown>) => inputs.map((input) => compile(input, resource, 'condition'));
    return {
        any: (...inputs: Array<unknown>) => new Expr({ type: 'Or', conditions: compileAll(inputs) }),
        all: (...inputs: Array<unknown>) => new Expr({ type: 'And', conditions: compileAll(inputs) }),
        not: (input: unknown) => new Expr({ type: 'Not', condition: compile(input, resource, 'condition') }),
        raw: (condition: AnyCondition) => new Expr(condition),
        ctx,
    };
}

function isContextRef(value: unknown): value is ContextRef {
    return typeof value === 'object' && value !== null && (value as ContextRef).kind === 'context';
}

/** Shorthand, `true` or an Expr, compiled to a plain condition. */
function compile(input: unknown, resource: string, where: string): AnyCondition {
    if (input === true) {
        return true;
    }
    if (input instanceof Expr) {
        return input.condition;
    }
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
        throw new Error(`${where}: expected true, an attribute object, or any/all/not(...); got ${JSON.stringify(input)}.`);
    }

    const equalities: Array<AnyCondition> = Object.entries(input)
        .filter(([, value]) => value !== undefined)
        .map(([property, value]) => isContextRef(value)
            ? { type: 'ContextExpression', property, operator: 'eq', contextProperty: value.property }
            : { type: 'LiteralExpression', property, operator: 'eq', value: value as boolean | string });

    if (equalities.length === 0) {
        throw new Error(`${where}: an empty attribute object would allow everything; use true if that's intended.`);
    }
    return equalities.length === 1 ? equalities[0]! : { type: 'And', conditions: equalities };
}

/**
 * The role-centric view of a policy, generated: one line per action/resource the role can
 * act on, e.g. `edit article when published==false`.
 */
export function describeRole<S extends PolicySchema>(policy: Policy<S>, role: RoleName<S>): Array<string> {
    const byPair = new Map<string, Array<AnyCondition>>();
    for (const permission of policy.getPermissions(role)) {
        const pair = `${permission.action} ${permission.resource}`;
        byPair.set(pair, [...(byPair.get(pair) ?? []), permission.condition]);
    }
    return [...byPair].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([pair, conditions]) => {
        const key = conditionKey({ type: 'Or', conditions });
        return key === 'true' ? pair : `${pair} when ${key}`;
    });
}
