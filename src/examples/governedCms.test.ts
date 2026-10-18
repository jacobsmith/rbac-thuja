import { it } from 'vitest';
import { createGovernedCmsPolicy } from './cms.js';

// A consumer with declared invariants: the test is the same one call.
it('has no unreviewed violations of its declared invariants', async () => {
    await createGovernedCmsPolicy().verifyNoUnapprovedBypasses({ exceptionsFile: 'src/examples/governedCms.thuja.exceptions.json' });
});
