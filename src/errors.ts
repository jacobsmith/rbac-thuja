export class ImmutableRolesError extends Error {
    constructor() {
        super("Roles have already been accessed for validation; additional Roles cannot be assigned within this Policy instance.");
        this.name = this.constructor.name;
    }
}

export type VerificationProblemKind = 'unapproved' | 'changed' | 'incomplete' | 'expired' | 'stale';

export type VerificationProblem = {
    kind: VerificationProblemKind,
    id: string,
    message: string,
};

export class ThujaVerificationError extends Error {
    public problems: Array<VerificationProblem>;

    constructor(message: string, problems: Array<VerificationProblem>) {
        super(message);
        this.name = this.constructor.name;
        this.problems = problems;
    }
}
