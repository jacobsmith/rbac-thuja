export type userId = string;
export type Resource = { name: 'article', published: boolean }
export type RbacAction = 'create'| 'edit'| 'publish'| 'unpublish';
export type RbacBooleanExpression = { property: keyof Resource, operator: 'eq', value: true | false }
export type RbacCondition = true | RbacBooleanExpression
export type RbacPermission = { action: RbacAction, resource: Resource['name'], condition: RbacCondition };
export type RbacPermissions = Array<RbacPermission>;

export class Encoder<Role> {
    protected roles: Map<Role, RbacPermissions> = new Map();
    protected userRoles: Map<userId, Array<Role>> = new Map();

}