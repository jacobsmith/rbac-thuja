// Nothing here may statically import z3-solver or node builtins: apps that only call
// `policy.can()` shouldn't load them. Verification pulls them in on demand.
export { Policy, type UserId } from "./policy.js";
export { defineSchema } from "./schema.js";
export type {
    Action,
    AttributeType,
    Condition,
    Invariant,
    ContextExpression,
    ContextValue,
    LiteralExpression,
    Permission,
    PolicySchema,
    ResourceName,
    ResourceValue,
    RoleName,
} from "./schema.js";
export { ImmutableRolesError, ThujaVerificationError, type VerificationProblem, type VerificationProblemKind } from "./errors.js";
export type { Finding, FindingKind } from "./scan.js";
export type { ExceptionEntry, ExceptionsFile, VerificationReport, VerifyOptions } from "./verify.js";
export { definePolicy, describeRole, Expr } from "./dsl.js";
export type { ConditionInput, ContextRef, Grants, Operators, PolicyDefinition, ResourceBuilder, Shorthand } from "./dsl.js";
