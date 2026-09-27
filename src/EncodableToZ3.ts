import type { Context, Bool, BitVecNum, BitVec } from "z3-solver";
import type { Encodable, RbacAction, RbacBooleanContextExpression, RbacBooleanExpression, RbacCondition } from "./encoder";
import type { resourceToZ3Mapping } from "./resourceToZ3Mapping";
import type { contextToZ3Mapping } from "./contextToZ3Mapping";

export class EncodableToZ3<T> {
    private encodable: Encodable<T>;
    private z3Context: Context;
    private roleSet: BitVec; // abstract; not concrete

    public constructor(encodable: Encodable<T>, context: Context) {
        this.encodable = encodable;
        this.z3Context = context;
        this.roleSet = this.z3Context.BitVec.const('roleSet', this.encodable.getRoleBitVectors().length);
    }

    public getEncodedConditions(resource: resourceToZ3Mapping, context: contextToZ3Mapping) {
        const roles = this.encodable.roles.keys();

        const conditions = [];

        for (const role of roles) {
            const roleConditions = this.encodable.roles.get(role);
            if (roleConditions == undefined) {
                continue;
            }

            for (const condition of roleConditions) {
                conditions.push(this.encodeCondition(condition.condition, resource, context));
            }
        }

        return conditions;
    }

    public encodeCondition(condition: RbacCondition, resource: resourceToZ3Mapping, context: contextToZ3Mapping): Bool {
        if (condition == true) {
            return this.z3Context.Bool.val(true);
        }

        switch (condition.type) {
            case 'LiteralExpression': {
                return this.literalExpressionEncoder(condition, resource);
            }
            case 'ContextExpression': {
                return this.contextExpressionEncoder(condition, resource, context);
            }
        }
    }

    public literalExpressionEncoder (condition: RbacBooleanExpression, resource: resourceToZ3Mapping) {
        switch (condition.operator) {
            case 'eq': {
                const resourceProperty = resource[condition.property];
                if (!resourceProperty) { return this.z3Context.Bool.val(false); }
                return resourceProperty.eq(condition.value);
            }
        }
    }

    public contextExpressionEncoder(condition: RbacBooleanContextExpression, resource: resourceToZ3Mapping, context: contextToZ3Mapping): Bool {
        switch (condition.operator) {
            case 'eq': {
                const resourceProperty = resource[condition.property];
                const contextProperty = context[condition.contextProperty];
                return resourceProperty.eq(contextProperty);
            }
        }
    }

    public holdsRole(mask: BitVecNum): Bool {
        return this.roleSet.and(mask).eq(mask);
    }

    public vectorToMask(vector: Array<0 | 1>) : BitVecNum {
        const mask = parseInt(vector.join(''), 2);
        return this.z3Context.BitVec.val(mask, vector.length);   
    }


    public roleCanDo(role: T, action: RbacAction, resource: resourceToZ3Mapping, context: contextToZ3Mapping): Bool {
        const permissions = this.encodable.roles.get(role);
        if (!permissions) { return this.z3Context.Bool.val(false); }

        const conditions = permissions.filter((permission) => permission.action == action);
        const encodedConditions = conditions.map((condition) => {
            return this.encodeCondition(condition.condition, resource, context);
        });

        return this.z3Context.Or(...encodedConditions);
    }

    public anyRoleCanDo(action: RbacAction, resource: resourceToZ3Mapping, context: contextToZ3Mapping): Bool {
        const roleBitVectors = this.encodable.getRoleBitVectors();

        const perRole = roleBitVectors.map((rbv) => {
            const mask = this.vectorToMask(rbv.vector);
            return this.z3Context.And(
                this.holdsRole(mask),
                this.roleCanDo(rbv.name, action, resource, context)
            );
        });

        return this.z3Context.Or(...perRole);
    }
}

