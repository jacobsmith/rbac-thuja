import type { FindingKind } from "./scan.js";

export type VerificationProblemKind = 'unapproved' | 'changed' | 'incomplete' | 'expired' | 'stale' | 'unused-role' | 'vacuous-invariant';

export type VerificationProblem = {
    kind: VerificationProblemKind,
    id: string,
    message: string,
    /** For problems about a finding: what kind of finding it is. */
    findingKind?: FindingKind,
};

export class ThujaVerificationError extends Error {
    public problems: Array<VerificationProblem>;

    constructor(message: string, problems: Array<VerificationProblem>) {
        super(message);
        this.name = this.constructor.name;
        this.problems = problems;
    }
}
