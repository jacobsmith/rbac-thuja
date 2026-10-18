// Nothing here may statically import z3-solver or node builtins: apps that only call
// `policy.can()` shouldn't load them. Verification pulls them in on demand.
export { Policy, type PermissionsByRole } from "./policy.js";
export { contextIs, defineSchema } from "./schema.js";
export type {
    Action,
    Actor,
    AttributeType,
    Condition,
    Invariant,
    ContextExpression,
    ContextLiteralExpression,
    ContextValue,
    Guard,
    LiteralExpression,
    Permission,
    PolicySchema,
    ResourceName,
    ResourceValue,
    RoleName,
} from "./schema.js";
export { ThujaVerificationError, type VerificationProblem, type VerificationProblemKind } from "./errors.js";
export type { Finding, FindingKind } from "./scan.js";
export type { ExceptionEntry, ExceptionsFile, VerificationReport, VerifyOptions } from "./verify.js";
export { contextOf, definePolicy, describeRole, Expr } from "./dsl.js";
export type { ConditionInput, ContextRef, ContextShorthand, Grants, Operators, PolicyDefinition, ResourceBuilder, Shorthand } from "./dsl.js";
