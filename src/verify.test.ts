import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { ThujaVerificationError } from './errors.js';
import { cmsSchema, createCmsPolicy } from './examples/cms.js';
import { Policy } from './policy.js';
import { permissionsFingerprint } from './scan.js';
import type { ExceptionEntry, ExceptionsFile } from './verify.js';

const BYPASS = 'compliance_officer|edit|article|published==false';

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
        const policy = new Policy(cmsSchema);
        policy.addRole('writer', [{ action: 'create', resource: 'article', condition: true }]);

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
        writeExceptions({ [BYPASS]: approved(), 'writer|edit|article|published==false': approved() });

        expect(await problemsOf(createCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile, update: false })))
            .toEqual([['stale', 'writer|edit|article|published==false']]);
    });

    it('explains how to fix things in the error message', async () => {
        await expect(createCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile, update: false }))
            .rejects.toThrow(/NEW BYPASS  compliance_officer\|edit\|article\|published==false[\s\S]*THUJA_UPDATE=1/);
    });

    it('rejects an exceptions file from a different format version', async () => {
        writeFileSync(exceptionsFile, JSON.stringify({ version: 2, exceptions: {} }));

        await expect(createCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile, update: false }))
            .rejects.toThrow(/version 2/);
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
            writeExceptions({ [BYPASS]: approved({ expires: '2099-01-01' }), 'writer|edit|article|published==false': approved() });

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
