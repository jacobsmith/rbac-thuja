import { evaluateCondition, guardsFor, validatePermission } from "./conditions.js";
import { validateSchema, type Action, type AnyPermission, type Actor, type Permission, type PolicySchema, type ResourceValue, type RoleName } from "./schema.js";
// Type-only: the scan/verify modules (and Z3 behind them) are loaded on demand so
// apps that only call `can()` never pay for them.
import type { Finding } from "./scan.js";
import type { VerificationReport, VerifyOptions } from "./verify.js";

export class RbacBitVector<Role> {
    public name: Role;
    public vector: Array<0 | 1>;

    constructor(name: Role, len: number, index: number) {
        const initialVector = new Array(len).fill(0) as Array<0 | 1>;
        initialVector[index] = 1;
        this.name = name;
        this.vector = initialVector;
    }
}

/**
 * Each role's permissions, as plain data. This is Thuja's raw format: `definePolicy` compiles
 * to it, and anything else (another DSL, a database, a config file) can produce it too.
 * Several permissions for the same role/action/resource mean any of them grants.
 */
export type PermissionsByRole<S extends PolicySchema> = {
    readonly [Role in RoleName<S>]?: ReadonlyArray<Permission<S>>
};

export class Policy<S extends PolicySchema> {
    public readonly schema: S;
    private rolePermissions: Map<RoleName<S>, ReadonlyArray<AnyPermission>> = new Map();

    /** Roles and their permissions are fixed once the policy is built. */
    constructor(schema: S, permissions: PermissionsByRole<S> = {}) {
        validateSchema(schema);
        this.schema = schema;

        for (const [role, rolePermissions] of Object.entries(permissions) as Array<[RoleName<S>, ReadonlyArray<AnyPermission> | undefined]>) {
            if (rolePermissions === undefined) {
                continue;
            }
            this.assertDeclaredRole(role);
            rolePermissions.forEach((permission) => validatePermission(this.schema, role, permission));
            this.rolePermissions.set(role, [...rolePermissions]);
        }
    }

    private assertDeclaredRole(role: string) {
        if (this.schema.roles && !this.schema.roles.includes(role)) {
            throw new Error(`Unknown role "${role}"; the schema declares: ${this.schema.roles.join(", ")}.`);
        }
    }

    /** Roles in a stable (sorted) order. */
    getRoles(): Array<RoleName<S>> {
        return [...this.rolePermissions.keys()].sort();
    }

    getPermissions(role: RoleName<S>): ReadonlyArray<AnyPermission> {
        return this.rolePermissions.get(role) ?? [];
    }

    /**
     * Whether `actor` (its roles plus the schema's context attributes) may perform `action`.
     *
     * Without a resource, only permissions whose condition needs no resource attributes can
     * grant (for any resource type). With one, permissions must target that resource type and
     * their condition must hold. Either way, the schema's guards for that action/resource must
     * hold too. Roles the policy doesn't know grant nothing.
     */
    can(actor: Actor<S>, action: Action<S>, resource?: ResourceValue<S>): boolean {
        const resourceRecord = resource as Readonly<Record<string, unknown>> | undefined;
        const context = actor as unknown as Readonly<Record<string, unknown>>;

        return actor.roles.some((role) => this.getPermissions(role).some((permission) =>
            permission.action === action
            && (resource === undefined || permission.resource === resource.$type)
            && guardsFor(this.schema, permission.action, permission.resource).every((guard) => evaluateCondition(guard.requires, resourceRecord, context))
            && evaluateCondition(permission.condition, resourceRecord, context)
        ));
    }

    getRoleBitVectors(): Array<RbacBitVector<RoleName<S>>> {
        const roles = this.getRoles();

        return roles.map((role, i) => new RbacBitVector<RoleName<S>>(role, roles.length, i));
    }

    /**
     * Every role that grants an action even when a condition other roles in this policy
     * place on that same action/resource does not hold.
     */
    async findBypasses(): Promise<Array<Finding>> {
        const { findBypasses } = await import("./scan.js");
        return findBypasses(this);
    }

    /**
     * Fails (throws `ThujaVerificationError`) unless every bypass `findBypasses()`
     * reports is approved, unchanged and unexpired in the exceptions file, and every
     * exception still corresponds to a bypass. Set `THUJA_UPDATE=1` to rewrite the
     * file with stubs for a human to fill in.
     */
    async verifyNoUnapprovedBypasses(options: VerifyOptions): Promise<VerificationReport> {
        const { verifyNoUnapprovedBypasses } = await import("./verify.js");
        return verifyNoUnapprovedBypasses(this, options);
    }
}
