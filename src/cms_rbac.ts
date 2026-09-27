
import { Encodable, type RbacAction, type RbacBooleanExpression, type RbacPermission, type RbacPermissions, type Resource, type userId } from "./encoder";

class ImmutableRolesError extends Error {
    constructor() {
        super("Roles have already been accessed for validation; additional Roles cannot be assigned within this Rbac instance.");
        this.name = this.constructor.name;
    }
}

export class CmsRbac<Role> extends Encodable<Role> {

    addRole(role: Role, permissions: RbacPermissions) {
        if (this.roleBitVectorsAccessed) {
            throw new ImmutableRolesError();
        }
        this.roles.set(role, permissions);
    }

    assignRole(name: string, role: Role) {
        const existingRoles = this.userRoles.get(name);
        if (existingRoles) {
            this.userRoles.set(name, [...existingRoles, role]);
            return;
        }
        this.userRoles.set(name, [role]);
    }

    can(user: userId, action: RbacAction, resource?: Resource): boolean {
        const userRoles = this.userRoles.get(user);
        if (!userRoles) { return false; }
        if (userRoles.length == 0) { return false; }

        const permissions: Array<RbacPermission> = [];
        userRoles.forEach((userRole) => {
            const rolePermissions = this.roles.get(userRole);
            if (rolePermissions) {
                // add each one at a time so we don't have nested arrays
                rolePermissions.forEach((rp) => permissions.push(rp));
            }
        })

        if (permissions.length == 0) { return false; }

        const permissionsForAction = permissions.filter((p) => p.action == action);
        if (permissionsForAction.length == 0) { return false; }

        return permissionsForAction.some((permission) => {
            if (permission.condition == true) {
                return true;
            } 

            if (!resource) {
                return false;
            }

            switch (permission.condition.type) {
                case 'LiteralExpression': {
                    return this.canLiteralExpression(permission.condition, resource);
                }
                case 'ContextExpression': {
                    throw new Error('ContextExpression conditions are not yet supported by can()');
                }
            }


        });
    }

    private canLiteralExpression(condition: RbacBooleanExpression, resource: Resource): boolean {
            switch (condition.operator) {
                case 'eq': {
                    if (resource[condition.property] == condition.value) {
                        return true;
                    }
                }
                default: {
                    return false;
                }
            }

    }
}

type CMSRole = 'writer' | 'publisher' | 'editor' | 'compliance_officer';

const rbac = new CmsRbac<CMSRole>();
rbac.addRole('writer', [
    { action: 'create', resource: 'article', condition: true },
    { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' }},
]);
rbac.addRole('editor', [
    { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false, type: 'LiteralExpression' }}
]);
rbac.addRole('publisher', [
    { action: 'publish', resource: 'article', condition: true },
    { action: 'unpublish', resource: 'article', condition: { property: 'published', operator: 'eq', value: true, type: 'LiteralExpression' }}
]);
rbac.addRole('compliance_officer', [
    { action: 'edit', resource: 'article', condition: true },
])