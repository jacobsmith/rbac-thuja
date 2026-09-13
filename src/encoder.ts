export type userId = string;
export type Resource = { name: 'article', published: boolean }
export type RbacAction = 'create'| 'edit'| 'publish'| 'unpublish';
export type RbacBooleanExpression = { property: keyof Resource, operator: 'eq', value: true | false }
export type RbacCondition = true | RbacBooleanExpression
export type RbacPermission = { action: RbacAction, resource: Resource['name'], condition: RbacCondition };
export type RbacPermissions = Array<RbacPermission>;

class RbacBitVector<Role> {
    public name: Role;
    public vector: Array<0 | 1>;

    constructor(name: Role, len: number, index: number) {
        const initialVector = new Array(len).fill(0) as Array<0 | 1>;
        initialVector[index] = 1;
        this.name = name;
        this.vector = initialVector;
    }
}

export class Encoder<Role> {
    protected roles: Map<Role, RbacPermissions> = new Map();
    protected userRoles: Map<userId, Array<Role>> = new Map();
    protected roleBitVectorsAccessed = false;

    getRoleBitVectors() {
        const roles = [...this.roles.keys()].sort();
        this.roleBitVectorsAccessed = true;

        const mapping: Array<RbacBitVector<Role>> = [];
        const length = roles.length;

        for (let i = 0; i < length; i++) {
            const role = roles[i];
            if (!role) {
                throw new Error('Out of bound roles access');
            }
            mapping.push(new RbacBitVector<Role>(role, length, i));
        }

        return mapping;
    }

}