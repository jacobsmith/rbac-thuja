import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { ThujaVerificationError, type VerificationProblem } from "./errors.js";
import type { EncodablePolicy } from "./PolicyEncoder.js";
import { scanPolicy, type Finding, type FindingKind } from "./scan.js";

export const EXCEPTIONS_FILE_VERSION = 1;

export type ExceptionEntry = {
    fingerprint: string,
    reason: string,
    approvedBy: string,
    approvedAt: string,
    expires?: string,
};

export type ExceptionsFile = {
    version: typeof EXCEPTIONS_FILE_VERSION,
    exceptions: Record<string, ExceptionEntry>,
};

export type VerifyOptions = {
    /** Path to the exceptions JSON file, resolved against the current working directory. */
    exceptionsFile: string,
    /** Rewrite the exceptions file before checking. Defaults to `THUJA_UPDATE=1` in the environment. */
    update?: boolean,
    /** Clock used for `expires`; defaults to now. */
    now?: Date,
};

export type VerificationReport = {
    findings: Array<Finding>,
};

export async function verifyNoUnapprovedBypasses(policy: EncodablePolicy, options: VerifyOptions): Promise<VerificationReport> {
    const path = resolve(process.cwd(), options.exceptionsFile);
    const update = options.update ?? ['1', 'true'].includes(process.env['THUJA_UPDATE'] ?? '');
    const now = options.now ?? new Date();

    const { findings, vacuousInvariants } = await scanPolicy(policy);
    let file = readExceptionsFile(path);

    if (update) {
        file = updatedExceptionsFile(file, findings);
        writeFileSync(path, JSON.stringify(file, null, 2) + '\n');
    }

    const problems = [...checkExceptions(findings, file, now), ...checkUnusedRoles(policy), ...vacuousInvariantProblems(vacuousInvariants)];
    if (problems.length > 0) {
        throw new ThujaVerificationError(formatProblems(problems, options.exceptionsFile, update), problems);
    }

    return { findings };
}

export function readExceptionsFile(path: string): ExceptionsFile {
    if (!existsSync(path)) {
        return { version: EXCEPTIONS_FILE_VERSION, exceptions: {} };
    }

    let parsed: unknown;
    try {
        parsed = JSON.parse(readFileSync(path, 'utf8'));
    } catch (error) {
        throw new Error(`Thuja exceptions file ${path} is not valid JSON: ${(error as Error).message}`);
    }

    if (typeof parsed !== 'object' || parsed === null || !('version' in parsed) || !('exceptions' in parsed)) {
        throw new Error(`Thuja exceptions file ${path} must be an object with "version" and "exceptions".`);
    }
    if (parsed.version !== EXCEPTIONS_FILE_VERSION) {
        throw new Error(`Thuja exceptions file ${path} has version ${JSON.stringify(parsed.version)}; this version of Thuja reads version ${EXCEPTIONS_FILE_VERSION}.`);
    }

    return parsed as ExceptionsFile;
}

/**
 * New findings get blank stubs; changed findings get the new fingerprint and lose their
 * approval (the reason is kept as context for the re-review); stale exceptions are dropped.
 */
export function updatedExceptionsFile(file: ExceptionsFile, findings: Array<Finding>): ExceptionsFile {
    const exceptions: Record<string, ExceptionEntry> = {};

    for (const finding of findings) {
        const existing = file.exceptions[finding.id];
        if (existing && existing.fingerprint === finding.fingerprint) {
            exceptions[finding.id] = existing;
        } else if (existing) {
            exceptions[finding.id] = { ...existing, fingerprint: finding.fingerprint, approvedBy: '', approvedAt: '' };
        } else {
            exceptions[finding.id] = { fingerprint: finding.fingerprint, reason: '', approvedBy: '', approvedAt: '' };
        }
    }

    return { version: EXCEPTIONS_FILE_VERSION, exceptions };
}

export function checkExceptions(findings: Array<Finding>, file: ExceptionsFile, now: Date): Array<VerificationProblem> {
    const problems: Array<VerificationProblem> = [];
    const findingIds = new Set(findings.map((finding) => finding.id));

    for (const finding of findings) {
        const describe = finding.description;
        const exception = file.exceptions[finding.id];
        const about = { id: finding.id, findingKind: finding.kind };

        if (!exception) {
            problems.push({ kind: 'unapproved', ...about, message: `${describe} ${NEXT_STEP[finding.kind]}` });
        } else if (exception.fingerprint !== finding.fingerprint) {
            problems.push({ kind: 'changed', ...about, message: `${describe} What this depends on (the role's permissions or the invariant) changed since the exception was approved; re-review it.` });
        } else if (!exception.reason?.trim() || !exception.approvedBy?.trim() || !exception.approvedAt?.trim()) {
            problems.push({ kind: 'incomplete', ...about, message: `${describe} The exception needs a reason, approvedBy and approvedAt.` });
        } else if (exception.expires !== undefined) {
            const expires = new Date(exception.expires);
            if (Number.isNaN(expires.getTime())) {
                problems.push({ kind: 'incomplete', ...about, message: `${describe} The exception's expires (${JSON.stringify(exception.expires)}) is not a valid date.` });
            } else if (now >= expires) {
                problems.push({ kind: 'expired', ...about, message: `${describe} The exception expired on ${exception.expires}.` });
            }
        }
    }

    for (const id of Object.keys(file.exceptions).sort()) {
        if (!findingIds.has(id)) {
            problems.push({ kind: 'stale', id, message: 'No longer a bypass; remove this exception.' });
        }
    }

    return problems;
}

/** Declared roles nobody gave permissions to: usually a typo or a leftover. */
export function checkUnusedRoles(policy: EncodablePolicy): Array<VerificationProblem> {
    return [...(policy.schema.roles ?? [])]
        .filter((role) => policy.getPermissions(role).length === 0)
        .sort()
        .map((role) => ({
            kind: 'unused-role' as const,
            id: role,
            message: `Declared in the schema but has no permissions; give it some with addRole() or remove it from roles.`,
        }));
}

const NEXT_STEP: Record<FindingKind, string> = {
    'invariant': 'Fix the role\'s permissions or approve this.',
    'not-allowed': 'Remove the permission, add the role to onlyRoles, or approve this.',
    'inferred': 'Declare an invariant or approve this.',
    'loose-invariant': 'Tighten the invariant or approve this.',
};

const UNAPPROVED_LABELS: Record<FindingKind, string> = {
    'invariant': 'NEW BYPASS',
    'not-allowed': 'NOT ALLOWED',
    'inferred': 'NO INVARIANT',
    'loose-invariant': 'LOOSE INVARIANT',
};

/** Invariants that can never catch anything: almost certainly a mistake in the invariant. */
export function vacuousInvariantProblems(names: Array<string>): Array<VerificationProblem> {
    return names.map((name) => ({
        kind: 'vacuous-invariant' as const,
        id: `invariant:${name}`,
        message: 'Its "requires" always holds, so it can never catch anything; fix the condition or remove the invariant.',
    }));
}

// Problems that an exceptions-file update can't resolve.
const NOT_EXCEPTIONS = new Set<VerificationProblem['kind']>(['unused-role', 'vacuous-invariant']);

const LABELS: Record<VerificationProblem['kind'], string> = {
    unapproved: 'NEW BYPASS',
    changed: 'CHANGED',
    incomplete: 'NEEDS APPROVAL',
    expired: 'EXPIRED',
    stale: 'STALE',
    'unused-role': 'UNUSED ROLE',
    'vacuous-invariant': 'VACUOUS INVARIANT',
};

function formatProblems(problems: Array<VerificationProblem>, exceptionsFile: string, updated: boolean): string {
    const label = (problem: VerificationProblem) =>
        problem.kind === 'unapproved' && problem.findingKind ? UNAPPROVED_LABELS[problem.findingKind] : LABELS[problem.kind];
    const lines = problems.map((problem) => `  ✗ ${label(problem)}  ${problem.id}\n      ${problem.message}`);
    const exceptionProblems = problems.some((problem) => !NOT_EXCEPTIONS.has(problem.kind));
    const hint = !exceptionProblems ? ''
        : updated
            ? `\n\n${exceptionsFile} was updated; fill in reason, approvedBy and approvedAt for each entry above.`
            : `\n\nRun your tests with THUJA_UPDATE=1 to update ${exceptionsFile}, then fill in reason, approvedBy and approvedAt.`;

    return `Thuja found ${problems.length} permission problem(s) (exceptions file: ${exceptionsFile}):\n\n${lines.join('\n')}${hint}`;
}
