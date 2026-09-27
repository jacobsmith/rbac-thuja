import type { Context, Bool, BitVecNum, BitVec } from "z3-solver";
import type { Encodable, RbacAction, RbacBooleanContextExpression, RbacBooleanExpression, RbacCondition } from "./encoder";

export class EncodableToZ3<T> {
    private encodable: Encodable<T>;
    private z3Context: Context;
    private roleSet: BitVec; // abstract; not concrete

    public constructor(encodable: Encodable<T>, context: Context) {
        this.encodable = encodable;
        this.z3Context = context;
        this.roleSet = this.z3Context.BitVec.const('roleSet', this.encodable.getRoleBitVectors().length);
    }

    public getEncodedConditions(published: Bool) {
        const roles = this.encodable.roles.keys();

        const conditions = [];

        for (const role of roles) {
            const roleConditions = this.encodable.roles.get(role);
            if (roleConditions == undefined) {
                continue;
            }

            for (const condition of roleConditions) {
                conditions.push(this.encodeCondition(condition.condition, published));
            }
        }

        return conditions;
    }

    public encodeCondition(condition: RbacCondition, published: Bool): Bool {
        if (condition == true) {
            return this.z3Context.Bool.val(true);
        }

        switch (condition.type) {
            case 'LiteralExpression': {
                return this.literalExpressionEncoder(condition, published);
            }
            case 'ContextExpression': {
                return this.contextExpressionEncoder(condition, published);
            }
        }
    }

    public literalExpressionEncoder (condition: RbacBooleanExpression, published: Bool) {
        switch (condition.operator) {
            case 'eq': {
                return published.eq(condition.value);
            }
        }
    }

    public contextExpressionEncoder(condition: RbacBooleanContextExpression, published: Bool): Bool {
        // todo -- write this
        return this.z3Context.Bool.val(false);
    }

    public holdsRole(mask: BitVecNum): Bool {
        return this.roleSet.and(mask).eq(mask);
    }

    public vectorToMask(vector: Array<0 | 1>) : BitVecNum {
        const mask = parseInt(vector.join(''), 2);
        return this.z3Context.BitVec.val(mask, vector.length);   
    }


    public roleCanDo(role: T, action: RbacAction, published: Bool): Bool {
        const permissions = this.encodable.roles.get(role);
        if (!permissions) { return this.z3Context.Bool.val(false); }

        const conditions = permissions.filter((permission) => permission.action == action);
        const encodedConditions = conditions.map((condition) => {
            return this.encodeCondition(condition.condition, published);
        });

        return this.z3Context.Or(...encodedConditions);
    }

    public anyRoleCanDo(action: RbacAction, published: Bool): Bool {
        const roleBitVectors = this.encodable.getRoleBitVectors();

        const perRole = roleBitVectors.map((rbv) => {
            const mask = this.vectorToMask(rbv.vector);
            return this.z3Context.And(
                this.holdsRole(mask),
                this.roleCanDo(rbv.name, action, published)
            );
        });

        return this.z3Context.Or(...perRole);
    }
}

