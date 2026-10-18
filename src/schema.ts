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
}

// `$type` on a runtime resource value identifies its resource type, so it can't
// also be an attribute.
const RESERVED_RESOURCE_ATTRIBUTES = ['$type'];

/**
 * Identity function that preserves literal types, so
 * `defineSchema({ actions: ['edit'], ... })` infers `'edit'` rather than `string`.
 */
export function defineSchema<const S extends PolicySchema>(schema: S): S {
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

export type Condition<A extends Attributes, C extends Attributes> = true | LiteralExpression<A> | ContextExpression<A, C>;

export type Permission<S extends PolicySchema> = {
    [R in ResourceName<S>]: { action: Action<S>, resource: R, condition: Condition<S['resources'][R], S['context']> }
}[ResourceName<S>];

export type ResourceValue<S extends PolicySchema> = {
    [R in ResourceName<S>]: { $type: R } & { [P in keyof S['resources'][R]]?: AttributeValue<S['resources'][R][P]> }
}[ResourceName<S>];

export type ContextValue<S extends PolicySchema> = {
    [P in keyof S['context']]?: AttributeValue<S['context'][P]>
};

// Schema-agnostic shapes used internally once the consumer's types have done their job.
export type AnyCondition =
    | true
    | { type: 'LiteralExpression', property: string, operator: 'eq', value: boolean | string }
    | { type: 'ContextExpression', property: string, operator: 'eq', contextProperty: string };
export type AnyPermission = { action: string, resource: string, condition: AnyCondition };
