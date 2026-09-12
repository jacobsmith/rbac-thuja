const RoleList = [
    'editor',
    'viewer',
    'commenter'
] as const;
type Role = typeof RoleList[number];



export class Rbac {
    private roles: Array<Role> = [];
    private userRoles: Map<string, Role> = new Map();

    addRole(role: Role) {
        this.roles.push(role);
    }

    assignRole(name: string, role: Role) {
        this.userRoles.set(name, role);
    }

    unusedRoles() {
        const assignedRoles = Array.from(this.userRoles.values());
        const unassignedRoles = RoleList.filter((val) => {
            return !assignedRoles.includes(val);
        });

        return unassignedRoles;
    }
}
