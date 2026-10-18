import type { Context, Bool, BitVecNum, BitVec, Seq } from "z3-solver";
import type { RbacBitVector } from "./policy.js";
import type { AnyCondition, AnyPermission, Attributes, PolicySchema } from "./schema.js";

export type Z3Attribute = Bool | Seq;
export type Z3Attributes = Record<string, Z3Attribute>;
export type Z3Symbols = { resource: Z3Attributes, context: Z3Attributes };

/** The subset of `Policy` the encoder needs; keeps it independent of Policy's generics. */
export interface EncodablePolicy<Role extends string = string> {
    readonly schema: PolicySchema;
    getRoles(): Array<Role>;
    getPermissions(role: Role): ReadonlyArray<AnyPermission>;
    getRoleBitVectors(): Array<RbacBitVector<Role>>;
}

export class PolicyEncoder<Role extends string = string> {
    private policy: EncodablePolicy<Role>;
    private z3Context: Context;
    private roleSetConst: BitVec | undefined; // abstract; not concrete

    public constructor(policy: EncodablePolicy<Role>, context: Context) {
        this.policy = policy;
        this.z3Context = context;
    }

    // Created lazily: building it locks the policy's roles, which per-role queries don't need.
    private get roleSet(): BitVec {
        this.roleSetConst ??= this.z3Context.BitVec.const('roleSet', this.policy.getRoleBitVectors().length);
        return this.roleSetConst;
    }

    /** Fresh symbolic constants for every attribute of `resource` and of the context. */
    public symbolsFor(resource: string): Z3Symbols {
        const attributes = this.policy.schema.resources[resource];
        if (!attributes) {
            throw new Error(`Unknown resource "${resource}".`);
        }
        return {
            resource: this.attributeConsts(resource, attributes),
            context: this.attributeConsts('context', this.policy.schema.context),
        };
    }

    private attributeConsts(prefix: string, attributes: Attributes): Z3Attributes {
        const consts: Z3Attributes = {};
        for (const [name, type] of Object.entries(attributes)) {
            const constName = `${prefix}.${name}`;
            consts[name] = type === 'boolean'
                ? this.z3Context.Bool.const(constName)
                : this.z3Context.String.const(constName);
        }
        return consts;
    }

    public encodeCondition(condition: AnyCondition, symbols: Z3Symbols): Bool {
        if (condition === true) {
            return this.z3Context.Bool.val(true);
        }

        switch (condition.type) {
            case 'And': {
                const children = condition.conditions.map((child) => this.encodeCondition(child, symbols));
                return children.length === 0 ? this.z3Context.Bool.val(true) : this.z3Context.And(...children);
            }
            case 'Or': {
                const children = condition.conditions.map((child) => this.encodeCondition(child, symbols));
                return children.length === 0 ? this.z3Context.Bool.val(false) : this.z3Context.Or(...children);
            }
            case 'Not': {
                return this.z3Context.Not(this.encodeCondition(condition.condition, symbols));
            }
            case 'ContextLiteralExpression': {
                const contextAttribute = symbols.context[condition.contextProperty];
                if (!contextAttribute) {
                    throw new Error(`No symbol for context attribute "${condition.contextProperty}".`);
                }
                const value = typeof condition.value === 'string' ? this.z3Context.String.val(condition.value) : condition.value;
                return contextAttribute.eq(value);
            }
        }

        const resourceAttribute = symbols.resource[condition.property];
        if (!resourceAttribute) {
            throw new Error(`No symbol for resource attribute "${condition.property}".`);
        }

        switch (condition.type) {
            case 'LiteralExpression': {
                switch (condition.operator) {
                    case 'eq': {
                        const value = typeof condition.value === 'string'
                            ? this.z3Context.String.val(condition.value)
                            : condition.value;
                        return resourceAttribute.eq(value);
                    }
                }
            }
            case 'ContextExpression': {
                const contextAttribute = symbols.context[condition.contextProperty];
                if (!contextAttribute) {
                    throw new Error(`No symbol for context attribute "${condition.contextProperty}".`);
                }
                switch (condition.operator) {
                    case 'eq': {
                        return resourceAttribute.eq(contextAttribute);
                    }
                }
            }
        }
    }

    public holdsRole(mask: BitVecNum): Bool {
        return this.roleSet.and(mask).eq(mask);
    }

    public vectorToMask(vector: Array<0 | 1>): BitVecNum {
        const mask = parseInt(vector.join(''), 2);
        return this.z3Context.BitVec.val(mask, vector.length);
    }

    /** Whether `role` grants `action` on `resource`, symbolic in the resource/context attributes. */
    public roleCanDo(role: Role, action: string, resource: string, symbols: Z3Symbols): Bool {
        const encodedConditions = this.policy.getPermissions(role)
            .filter((permission) => permission.action === action && permission.resource === resource)
            .map((permission) => this.encodeCondition(permission.condition, symbols));

        if (encodedConditions.length === 0) {
            return this.z3Context.Bool.val(false);
        }
        return this.z3Context.Or(...encodedConditions);
    }

    /** Whether any role in the symbolic `roleSet` grants `action` on `resource`. */
    public anyRoleCanDo(action: string, resource: string, symbols: Z3Symbols): Bool {
        const perRole = this.policy.getRoleBitVectors().map((rbv) => {
            const mask = this.vectorToMask(rbv.vector);
            return this.z3Context.And(
                this.holdsRole(mask),
                this.roleCanDo(rbv.name, action, resource, symbols)
            );
        });

        if (perRole.length === 0) {
            return this.z3Context.Bool.val(false);
        }
        return this.z3Context.Or(...perRole);
    }
}
