import { it } from 'vitest';
import { createCmsPolicy } from './cms.js';

// What a consuming codebase's test looks like: one call, Thuja does the rest.
it('has no unreviewed permission bypasses', async () => {
    await createCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile: 'src/examples/cms.thuja.exceptions.json' });
});
