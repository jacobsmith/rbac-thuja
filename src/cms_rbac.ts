type Resource = { name: 'article', published: boolean }


type RbacAction = 'create'| 'edit'| 'publish'| 'unpublish';

type RbacPermission = { action: RbacAction, resource: Resource['name'], condition?: (obj?: Resource) => boolean }
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

        if (!permission.condition) { 
            return true;
        }

        return permission.condition(resource);
    }
}

type CMSRole = 'writer' | 'publisher' | 'editor';

const rbac = new CmsRbac<CMSRole>();
rbac.addRole('writer', [
    { action: 'create', resource: 'article' },
    { action: 'edit', resource: 'article', condition: (resource) => { return !!resource && !resource.published }},
]);
rbac.addRole('editor', [
    { action: 'edit', resource: 'article', condition: (resource) => { return !!resource && !resource.published }},
]);
rbac.addRole('publisher', [
    { action: 'publish', resource: 'article' },
    { action: 'unpublish', resource: 'article', condition: (resource) => { return !!resource && resource.published }}
]);