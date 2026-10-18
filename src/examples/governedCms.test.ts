import { it } from 'vitest';
import { createGovernedCmsPolicyByResource } from './cmsResources.js';

// A consumer with declared invariants: the test is the same one call.
it('has no unreviewed violations of its declared invariants', async () => {
    await createGovernedCmsPolicyByResource().verifyNoUnapprovedBypasses({ exceptionsFile: 'src/examples/governedCms.thuja.exceptions.json' });
});
