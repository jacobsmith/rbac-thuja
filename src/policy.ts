import { evaluateCondition, validatePermission } from "./conditions.js";
import { ImmutableRolesError } from "./errors.js";
import { validateSchema, type Action, type AnyPermission, type ContextValue, type Permission, type PolicySchema, type ResourceValue } from "./schema.js";
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

export class Policy<S extends PolicySchema, Role extends string = string> {
    public readonly schema: S;
    private rolePermissions: Map<Role, Array<AnyPermission>> = new Map();
    private userRoles: Map<UserId, Array<Role>> = new Map();
    private roleBitVectorsAccessed = false;

    constructor(schema: S) {
        validateSchema(schema);
        this.schema = schema;
    }

    addRole(role: Role, permissions: Array<Permission<S>>) {
        if (this.roleBitVectorsAccessed) {
            throw new ImmutableRolesError();
        }
        // Permission<S> is a mapped type TS can't relate to AnyPermission while S is generic.
        const anyPermissions = permissions as unknown as Array<AnyPermission>;
        anyPermissions.forEach((permission) => validatePermission(this.schema, role, permission));
        this.rolePermissions.set(role, anyPermissions);
    }

    assignRole(user: UserId, role: Role) {
        const existingRoles = this.userRoles.get(user);
        if (existingRoles) {
            this.userRoles.set(user, [...existingRoles, role]);
            return;
        }
        this.userRoles.set(user, [role]);
    }

    /** Roles in a stable (sorted) order. */
    getRoles(): Array<Role> {
        return [...this.rolePermissions.keys()].sort();
    }

    getPermissions(role: Role): ReadonlyArray<AnyPermission> {
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

    getRoleBitVectors(): Array<RbacBitVector<Role>> {
        const roles = this.getRoles();
        this.roleBitVectorsAccessed = true;

        return roles.map((role, i) => new RbacBitVector<Role>(role, roles.length, i));
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
