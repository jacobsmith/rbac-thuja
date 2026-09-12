type Role = 'editor' | 'viewer' | 'commenter';

class Rbac {
    private roles: Array<Role> = [];

    addRole(role: Role) {
        this.roles.push(role);
    }
}

export default Rbac;