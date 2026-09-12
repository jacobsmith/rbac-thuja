type Resource = { name: 'article', published: boolean }


type RbacAction = 'create'| 'edit'| 'publish'| 'unpublish';


type RbacBooleanExpression = { property: keyof Resource, operator: 'eq', value: true | false }
type RbacCondition = true | RbacBooleanExpression
type RbacPermission = { action: RbacAction, resource: Resource['name'], condition: RbacCondition };
type RbacPermissions = Array<RbacPermission>;

type userId = string;

export class CmsRbac<Role> {
    private roles: Map<Role, RbacPermissions> = new Map();
    private userRoles: Map<userId, Role> = new Map();

    addRole(role: Role, permissions: RbacPermissions) {
        this.roles.set(role, permissions);
    }

    assignRole(name: string, role: Role) {
        this.userRoles.set(name, role);
    }

    can(user: userId, action: RbacAction, resource?: Resource): boolean {
        const userRole = this.userRoles.get(user);
        if (!userRole) { return false; }

        const permissions = this.roles.get(userRole);
        if (!permissions) { return false; }

        const permission = permissions.find((p) => p.action == action);
        if (!permission) { return false; }

        if (permission.condition == true) {
            return true;
        } 

        if (!resource) {
            return false;
        }

        switch (permission.condition.operator) {
            case 'eq': {
                if (resource[permission.condition.property] == permission.condition.value) {
                    return true;
                }
            }
        }

        return false;
    }
}

type CMSRole = 'writer' | 'publisher' | 'editor' | 'compliance_officer';

const rbac = new CmsRbac<CMSRole>();
rbac.addRole('writer', [
    { action: 'create', resource: 'article', condition: true },
    { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false }},
]);
rbac.addRole('editor', [
    { action: 'edit', resource: 'article', condition: { property: 'published', operator: 'eq', value: false }}
]);
rbac.addRole('publisher', [
    { action: 'publish', resource: 'article', condition: true },
    { action: 'unpublish', resource: 'article', condition: { property: 'published', operator: 'eq', value: true }}
]);
rbac.addRole('compliance_officer', [
    { action: 'edit', resource: 'article', condition: true },
])