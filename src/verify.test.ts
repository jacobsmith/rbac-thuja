import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { ThujaVerificationError } from './errors.js';
import { cmsSchema, createCmsPolicy } from './examples/cms.js';
import { Policy } from './policy.js';
import { defineSchema } from './schema.js';
import { permissionsFingerprint } from './scan.js';
import type { ExceptionEntry, ExceptionsFile } from './verify.js';

const BYPASS = 'compliance_officer|edit|article|inferred:published==false';

let exceptionsFile: string;

beforeEach(() => {
    exceptionsFile = join(mkdtempSync(join(tmpdir(), 'thuja-')), 'thuja.exceptions.json');
});

function writeExceptions(exceptions: Record<string, ExceptionEntry>) {
    writeFileSync(exceptionsFile, JSON.stringify({ version: 1, exceptions }));
}

function readExceptions(): ExceptionsFile {
    return JSON.parse(readFileSync(exceptionsFile, 'utf8'));
}

function approved(overrides: Partial<ExceptionEntry> = {}): ExceptionEntry {
    return {
        fingerprint: permissionsFingerprint(createCmsPolicy(), 'compliance_officer', 'edit', 'article'),
        reason: 'Legal must amend published articles for takedowns',
        approvedBy: 'jacob',
        approvedAt: '2026-10-18',
        ...overrides,
    };
}

async function problemsOf(promise: Promise<unknown>) {
    const error = await promise.then(() => undefined, (e: unknown) => e);
    expect(error).toBeInstanceOf(ThujaVerificationError);
    return (error as ThujaVerificationError).problems.map((problem) => [problem.kind, problem.id]);
}

describe('verifyNoUnapprovedBypasses', () => {
    it('passes when every bypass is approved and unchanged', async () => {
        writeExceptions({ [BYPASS]: approved() });

        const report = await createCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile, update: false });

        expect(report.findings.map((finding) => finding.id)).toEqual([BYPASS]);
    });

    it('passes for a consistent policy with no exceptions file', async () => {
        const policy = new Policy(defineSchema({ ...cmsSchema, roles: ['writer'] }), {
            writer: [{ action: 'create', resource: 'article', condition: true }],
        });

        await expect(policy.verifyNoUnapprovedBypasses({ exceptionsFile, update: false })).resolves.toBeDefined();
    });

    it('fails on declared roles with no permissions', async () => {
        const policy = new Policy(cmsSchema, {
            writer: [{ action: 'create', resource: 'article', condition: true }],
            editor: [],
        });

        expect(await problemsOf(policy.verifyNoUnapprovedBypasses({ exceptionsFile, update: false }))).toEqual([
            ['unused-role', 'compliance_officer'],
            ['unused-role', 'editor'],
            ['unused-role', 'publisher'],
        ]);
        // nothing an exceptions-file update can fix, so no THUJA_UPDATE hint
        await expect(policy.verifyNoUnapprovedBypasses({ exceptionsFile, update: false })).rejects.toThrow(/UNUSED ROLE  editor(?![\s\S]*THUJA_UPDATE)/);
    });

    it('does not check unused roles when the schema declares none', async () => {
        const { roles: _roles, ...undeclared } = cmsSchema;
        const policy = new Policy(defineSchema(undeclared), {
            writer: [{ action: 'create', resource: 'article', condition: true }],
        });

        await expect(policy.verifyNoUnapprovedBypasses({ exceptionsFile, update: false })).resolves.toBeDefined();
    });

    it('fails on a bypass with no exception', async () => {
        expect(await problemsOf(createCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile, update: false })))
            .toEqual([['unapproved', BYPASS]]);
    });

    it('fails when the role\'s permissions changed since approval', async () => {
        writeExceptions({ [BYPASS]: approved({ fingerprint: 'sha256:old' }) });

        expect(await problemsOf(createCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile, update: false })))
            .toEqual([['changed', BYPASS]]);
    });

    it('fails when an exception is missing its approval', async () => {
        writeExceptions({ [BYPASS]: approved({ approvedBy: ' ' }) });

        expect(await problemsOf(createCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile, update: false })))
            .toEqual([['incomplete', BYPASS]]);
    });

    it('fails once an exception expires', async () => {
        writeExceptions({ [BYPASS]: approved({ expires: '2027-04-18' }) });
        const policy = createCmsPolicy();

        await expect(policy.verifyNoUnapprovedBypasses({ exceptionsFile, update: false, now: new Date('2027-04-17') })).resolves.toBeDefined();
        expect(await problemsOf(policy.verifyNoUnapprovedBypasses({ exceptionsFile, update: false, now: new Date('2027-04-18') })))
            .toEqual([['expired', BYPASS]]);
    });

    it('fails on an exception that no longer matches a bypass', async () => {
        writeExceptions({ [BYPASS]: approved(), 'writer|edit|article|inferred:published==false': approved() });

        expect(await problemsOf(createCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile, update: false })))
            .toEqual([['stale', 'writer|edit|article|inferred:published==false']]);
    });

    it('explains how to fix things in the error message', async () => {
        await expect(createCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile, update: false }))
            .rejects.toThrow(/NO INVARIANT  compliance_officer\|edit\|article\|inferred:published==false[\s\S]*THUJA_UPDATE=1/);
    });

    it('rejects an exceptions file from a different format version', async () => {
        writeFileSync(exceptionsFile, JSON.stringify({ version: 2, exceptions: {} }));

        await expect(createCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile, update: false }))
            .rejects.toThrow(/version 2/);
    });

    describe('declared invariants', () => {
        const unpublished = { type: 'LiteralExpression', property: 'published', operator: 'eq', value: false } as const;
        const owner = { type: 'ContextExpression', property: 'authorId', operator: 'eq', contextProperty: 'id' } as const;

        function governed(invariants: Array<unknown>) {
            const policy = new Policy(defineSchema({ ...cmsSchema, roles: ['writer', 'editor', 'publisher'], invariants: invariants as never }), {
                writer: [{ action: 'edit', resource: 'article', condition: { type: 'And', conditions: [unpublished, owner] } }],
                editor: [{ action: 'edit', resource: 'article', condition: { type: 'And', conditions: [unpublished, owner] } }],
                publisher: [{ action: 'edit', resource: 'article', condition: true }, { action: 'publish', resource: 'article', condition: true }],
            });
            return policy;
        }

        it('labels each kind of finding and says how to resolve it', async () => {
            const policy = governed([
                { name: 'unpublished-only', action: 'edit', resource: 'article', requires: unpublished },
                { name: 'only-editors-publish', action: 'publish', resource: 'article', onlyRoles: ['editor'] },
            ]);

            const error = await policy.verifyNoUnapprovedBypasses({ exceptionsFile, update: false }).then(() => undefined, (e: unknown) => e) as ThujaVerificationError;

            expect(error.problems.map((problem) => [problem.findingKind, problem.id])).toEqual([
                ['loose-invariant', 'invariant:unpublished-only|edit|article|inferred:(authorId==context.id && published==false)'],
                ['invariant', 'publisher|edit|article|invariant:unpublished-only'],
                ['not-allowed', 'publisher|publish|article|invariant:only-editors-publish'],
            ]);
            expect(error.message).toMatch(/LOOSE INVARIANT  invariant:unpublished-only[\s\S]*Tighten the invariant or approve this/);
            expect(error.message).toMatch(/NEW BYPASS  publisher\|edit\|article\|invariant:unpublished-only[\s\S]*Fix the role's permissions or approve this/);
            expect(error.message).toMatch(/NOT ALLOWED  publisher\|publish\|article\|invariant:only-editors-publish[\s\S]*add the role to onlyRoles/);
        });

        it('approves invariant findings through the exceptions file like any other', async () => {
            const policy = governed([{ name: 'own-drafts', action: 'edit', resource: 'article', requires: { type: 'And', conditions: [unpublished, owner] } }]);
            await policy.verifyNoUnapprovedBypasses({ exceptionsFile, update: true }).catch(() => undefined);
            const file = readExceptions();
            for (const entry of Object.values(file.exceptions)) {
                Object.assign(entry, { reason: 'Publishers fix typos in live articles', approvedBy: 'jacob', approvedAt: '2026-10-18' });
            }
            writeFileSync(exceptionsFile, JSON.stringify(file));

            const report = await policy.verifyNoUnapprovedBypasses({ exceptionsFile, update: false });

            expect(report.findings.map((finding) => finding.id)).toEqual(['publisher|edit|article|invariant:own-drafts']);
        });

        it('fails on an invariant that can never catch anything, with no exceptions-file hint', async () => {
            const policy = governed([
                { name: 'own-drafts', action: 'edit', resource: 'article', requires: { type: 'And', conditions: [unpublished, owner] } },
                { name: 'tautology', action: 'publish', resource: 'article', requires: { type: 'Or', conditions: [unpublished, { type: 'Not', condition: unpublished }] } },
            ]);
            writeExceptions({ 'publisher|edit|article|invariant:own-drafts': { ...approved(), fingerprint: (await policy.findBypasses())[0]!.fingerprint } });

            const error = await policy.verifyNoUnapprovedBypasses({ exceptionsFile, update: false }).then(() => undefined, (e: unknown) => e) as ThujaVerificationError;

            expect(error.problems.map((problem) => [problem.kind, problem.id])).toEqual([['vacuous-invariant', 'invariant:tautology']]);
            expect(error.message).not.toMatch(/THUJA_UPDATE/);
        });
    });

    describe('update mode', () => {
        it('writes blank stubs for new bypasses and still fails until they are filled in', async () => {
            expect(await problemsOf(createCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile, update: true })))
                .toEqual([['incomplete', BYPASS]]);

            const written = readExceptions();
            expect(written.version).toEqual(1);
            expect(written.exceptions[BYPASS]).toEqual({ ...approved(), reason: '', approvedBy: '', approvedAt: '' });
        });

        it('refreshes changed fingerprints, keeps the reason, and clears the approval', async () => {
            writeExceptions({ [BYPASS]: approved({ fingerprint: 'sha256:old' }) });

            expect(await problemsOf(createCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile, update: true })))
                .toEqual([['incomplete', BYPASS]]);
            expect(readExceptions().exceptions[BYPASS]).toEqual({ ...approved(), approvedBy: '', approvedAt: '' });
        });

        it('drops stale exceptions and leaves approved ones untouched', async () => {
            writeExceptions({ [BYPASS]: approved({ expires: '2099-01-01' }), 'writer|edit|article|inferred:published==false': approved() });

            await createCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile, update: true });

            expect(readExceptions().exceptions).toEqual({ [BYPASS]: approved({ expires: '2099-01-01' }) });
        });

        it('is enabled by THUJA_UPDATE=1', async () => {
            process.env['THUJA_UPDATE'] = '1';
            try {
                await createCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile }).catch(() => undefined);
            } finally {
                delete process.env['THUJA_UPDATE'];
            }

            expect(Object.keys(readExceptions().exceptions)).toEqual([BYPASS]);
        });
    });
});
