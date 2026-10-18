import { evaluateCondition, validatePermission } from "./conditions.js";
import { validateSchema, type Action, type AnyPermission, type ContextValue, type Permission, type PolicySchema, type ResourceValue, type RoleName } from "./schema.js";
// Type-only: the scan/verify modules (and Z3 behind them) are loaded on demand so
// apps that only call `can()` never pay for them.
import type { Finding } from "./scan.js";
import type { VerificationReport, VerifyOptions } from "./verify.js";

export type UserId = string;

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
    private userRoles: Map<UserId, Array<RoleName<S>>> = new Map();

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

    assignRole(user: UserId, role: RoleName<S>) {
        this.assertDeclaredRole(role);
        const existingRoles = this.userRoles.get(user);
        if (existingRoles) {
            this.userRoles.set(user, [...existingRoles, role]);
            return;
        }
        this.userRoles.set(user, [role]);
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
     * Without a resource, only unconditional permissions can grant (for any resource type).
     * With one, permissions must target that resource type and their condition must hold.
     */
    can(user: UserId, action: Action<S>, resource?: ResourceValue<S>, context?: ContextValue<S>): boolean {
        const roles = this.userRoles.get(user) ?? [];
        const resourceRecord = resource as Readonly<Record<string, unknown>> | undefined;
        const contextRecord = context as Readonly<Record<string, unknown>> | undefined;

        return roles.some((role) => this.getPermissions(role).some((permission) =>
            permission.action === action
            && (resource === undefined || permission.resource === resource.$type)
            && evaluateCondition(permission.condition, resourceRecord, contextRecord)
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
