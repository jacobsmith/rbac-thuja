import { validateActionResource, validateGuard, validateInvariant } from "./conditions.js";

// A consumer describes the shape of their authorization domain once; every other
// type (permissions, conditions, runtime resource/context values) and the Z3
// encoding are derived from it.

export type AttributeType = 'boolean' | 'string';
export type AttributeValue<T extends AttributeType> = T extends 'boolean' ? boolean : string;
export type Attributes = { readonly [attribute: string]: AttributeType };

export interface PolicySchema {
    /** Optional: declaring roles types them and rejects unknown ones; omit for runtime-defined roles. */
    readonly roles?: readonly string[];
    readonly actions: readonly string[];
    readonly resources: { readonly [resource: string]: Attributes };
    readonly context: Attributes;
    /**
     * Rules the policy must obey, checked by `verifyNoUnapprovedBypasses`. Where an invariant
     * declares `requires` for an action/resource, it replaces the rule Thuja would otherwise
     * infer from what most roles do.
     */
    readonly invariants?: ReadonlyArray<AnyInvariant>;
    /** Action/resource pairs that are public: exempt from guards declared with `except: 'public'`. */
    readonly public?: ReadonlyArray<AnyActionResource>;
    /**
     * Conditions on the context (the acting user and request) that every grant must also meet,
     * enforced by `can()` and assumed by the scan, e.g. "non-public actions need an
     * authenticated user". They can only reference context, since they span resources.
     */
    readonly guards?: ReadonlyArray<AnyGuard>;
}

// `$type` on a runtime resource value identifies its resource type, so it can't
// also be an attribute.
const RESERVED_RESOURCE_ATTRIBUTES = ['$type'];
// `roles` on the actor passed to `can()` lists its roles, so it can't also be a context attribute.
const RESERVED_CONTEXT_ATTRIBUTES = ['roles'];

/**
 * Identity function that preserves literal types, so
 * `defineSchema({ actions: ['edit'], ... })` infers `'edit'` rather than `string`.
 */
export function defineSchema<const S extends PolicySchema>(schema: S & {
    readonly invariants?: ReadonlyArray<Invariant<S>>,
    readonly public?: ReadonlyArray<ActionResource<S>>,
    readonly guards?: ReadonlyArray<Guard<S>>,
}): S {
    validateSchema(schema);
    return schema;
}

export function validateSchema(schema: PolicySchema) {
    if (schema.roles && new Set(schema.roles).size !== schema.roles.length) {
        throw new Error("Schema declares duplicate roles.");
    }
    for (const [resource, attributes] of Object.entries(schema.resources)) {
        for (const reserved of RESERVED_RESOURCE_ATTRIBUTES) {
            if (reserved in attributes) {
                throw new Error(`Resource "${resource}" declares reserved attribute "${reserved}".`);
            }
        }
    }

    for (const reserved of RESERVED_CONTEXT_ATTRIBUTES) {
        if (reserved in schema.context) {
            throw new Error(`Context declares reserved attribute "${reserved}".`);
        }
    }

    for (const pair of schema.public ?? []) {
        validateActionResource(schema, pair, 'Public entry');
    }

    const guardNames = new Set<string>();
    for (const guard of schema.guards ?? []) {
        if (!guard.name) {
            throw new Error('Every guard needs a name.');
        }
        if (guardNames.has(guard.name)) {
            throw new Error(`Schema declares guard "${guard.name}" more than once.`);
        }
        guardNames.add(guard.name);
        validateGuard(schema, guard);
    }

    const names = new Set<string>();
    for (const invariant of schema.invariants ?? []) {
        if (!invariant.name) {
            throw new Error('Every invariant needs a name.');
        }
        if (names.has(invariant.name)) {
            throw new Error(`Schema declares invariant "${invariant.name}" more than once.`);
        }
        names.add(invariant.name);
        validateInvariant(schema, invariant);
    }
}

export type RoleName<S extends PolicySchema> = S extends { readonly roles: readonly (infer R extends string)[] } ? R : string;
export type Action<S extends PolicySchema> = S['actions'][number];
export type ResourceName<S extends PolicySchema> = keyof S['resources'] & string;

type KeysOfType<A extends Attributes, T extends AttributeType> = {
    [K in keyof A & string]: A[K] extends T ? K : never
}[keyof A & string];

export type LiteralExpression<A extends Attributes> = {
    [P in keyof A & string]: { type: 'LiteralExpression', property: P, operator: 'eq', value: AttributeValue<A[P]> }
}[keyof A & string];

// A context property can only be compared against a resource attribute of the same type.
export type ContextExpression<A extends Attributes, C extends Attributes> = {
    [P in keyof A & string]: { type: 'ContextExpression', property: P, operator: 'eq', contextProperty: KeysOfType<C, A[P]> }
}[keyof A & string];

export type AtomicCondition<A extends Attributes, C extends Attributes> = LiteralExpression<A> | ContextExpression<A, C>;

/** A condition on the context alone, e.g. `context.authenticated == true`. */
export type ContextLiteralExpression<C extends Attributes> = {
    [K in keyof C & string]: { type: 'ContextLiteralExpression', contextProperty: K, operator: 'eq', value: AttributeValue<C[K]> }
}[keyof C & string];

/** `contextIs('authenticated', true)`: shorthand for a context-only condition, usable in a schema. */
export function contextIs<const K extends string, const V extends boolean | string>(contextProperty: K, value: V) {
    return { type: 'ContextLiteralExpression', contextProperty, operator: 'eq', value } as const;
}

// Compound conditions nest arbitrarily. An empty `And` is always true and an empty `Or`
// is never true, matching the usual logical identities.
export type AndCondition<A extends Attributes, C extends Attributes> = { type: 'And', conditions: ReadonlyArray<Condition<A, C>> };
export type OrCondition<A extends Attributes, C extends Attributes> = { type: 'Or', conditions: ReadonlyArray<Condition<A, C>> };
export type NotCondition<A extends Attributes, C extends Attributes> = { type: 'Not', condition: Condition<A, C> };

export type Condition<A extends Attributes, C extends Attributes> =
    | true
    | AtomicCondition<A, C>
    | ContextLiteralExpression<C>
    | AndCondition<A, C>
    | OrCondition<A, C>
    | NotCondition<A, C>;

export type Permission<S extends PolicySchema> = {
    [R in ResourceName<S>]: { action: Action<S>, resource: R, condition: Condition<S['resources'][R], S['context']> }
}[ResourceName<S>];

export type ResourceValue<S extends PolicySchema> = {
    [R in ResourceName<S>]: { $type: R } & { [P in keyof S['resources'][R]]?: AttributeValue<S['resources'][R][P]> }
}[ResourceName<S>];

export type ContextValue<S extends PolicySchema> = {
    [P in keyof S['context']]?: AttributeValue<S['context'][P]>
};

/** The acting user passed to `can()`: its roles plus the schema's context attributes. */
export type Actor<S extends PolicySchema> = { readonly roles: ReadonlyArray<RoleName<S>> } & ContextValue<S>;

// Schema-agnostic shapes used internally once the consumer's types have done their job.
export type AnyAtomicCondition =
    | { type: 'LiteralExpression', property: string, operator: 'eq', value: boolean | string }
    | { type: 'ContextExpression', property: string, operator: 'eq', contextProperty: string }
    | { type: 'ContextLiteralExpression', contextProperty: string, operator: 'eq', value: boolean | string };
export type AnyCondition =
    | true
    | AnyAtomicCondition
    | { type: 'And', conditions: ReadonlyArray<AnyCondition> }
    | { type: 'Or', conditions: ReadonlyArray<AnyCondition> }
    | { type: 'Not', condition: AnyCondition };
export type AnyPermission = { action: string, resource: string, condition: AnyCondition };

/**
 * A declared rule for one resource and one or more actions. `requires` is a condition any
 * role must satisfy to act; `onlyRoles` limits which roles may act at all. At least one is
 * needed; with both, listed roles must also satisfy `requires`.
 */
export type Invariant<S extends PolicySchema> = {
    [R in ResourceName<S>]: {
        readonly name: string,
        readonly action: Action<S> | ReadonlyArray<Action<S>>,
        readonly resource: R,
        readonly requires?: Condition<S['resources'][R], S['context']>,
        readonly onlyRoles?: ReadonlyArray<RoleName<S>>,
    }
}[ResourceName<S>];

/** One or more actions on one resource. */
export type ActionResource<S extends PolicySchema> = {
    [R in ResourceName<S>]: { readonly action: Action<S> | ReadonlyArray<Action<S>>, readonly resource: R }
}[ResourceName<S>];

export type AnyActionResource = { readonly action: string | ReadonlyArray<string>, readonly resource: string };

export type Guard<S extends PolicySchema> = {
    readonly name: string,
    /** Context-only: guards span resources, so they can't reference resource attributes. */
    readonly requires: Condition<{}, S['context']>,
    /** `'public'` exempts the schema's public action/resource pairs. */
    readonly except?: 'public',
};

export type AnyGuard = { readonly name: string, readonly requires: AnyCondition, readonly except?: 'public' };

export type AnyInvariant = {
    readonly name: string,
    readonly action: string | ReadonlyArray<string>,
    readonly resource: string,
    readonly requires?: AnyCondition,
    readonly onlyRoles?: ReadonlyArray<string>,
};
