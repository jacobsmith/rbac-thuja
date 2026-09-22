import type { Context, Bool } from "z3-solver";
import type { Encodable, RbacCondition } from "./encoder";

export class EncodableToZ3<T> {
    private encodable: Encodable<T>;
    private z3Context: Context;
    public constructor(encodable: Encodable<T>, context: Context) {
        this.encodable = encodable;
        this.z3Context = context;
    }

    public encodeCondition(condition: RbacCondition, published: Bool): Bool {
        if (condition == true) {
            return this.z3Context.Bool.val(true);
        }

        switch (condition.operator) {
            case 'eq': {
                return published.eq(condition.value);
            }
        }
    }


}

