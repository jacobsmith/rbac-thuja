import { it } from 'vitest';
import { createCmsPolicyByResource } from './cmsResources.js';

// What a consuming codebase's test looks like: one call, Thuja does the rest.
it('has no unreviewed permission bypasses', async () => {
    await createCmsPolicyByResource().verifyNoUnapprovedBypasses({ exceptionsFile: 'src/examples/cms.thuja.exceptions.json' });
});
