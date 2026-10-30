/**
 * Real SHA-pinned original pi-ai module import check (not a DSH UI E2E).
 * Run only from a private GH Actions ephemeral path, no credentials.
 */
import * as pi from '@earendil-works/pi-ai';

const exported=Object.keys(pi);
const eligible=exported.filter(k => /^stream|^getModel|^getProvider|^complete/i.test(k));
if(!exported.includes('streamSimple')) {
  process.stdout.write('P96_ORIGINAL_PI_AI_STREAM_SIMPLE_EXPORT=UNAVAILABLE\n');
  process.stdout.write('P96_ORIGINAL_PI_AI_RELEVANT_EXPORTS='+JSON.stringify(eligible)+'\n');
  process.exitCode=2;
} else {
  process.stdout.write('P96_ORIGINAL_PI_AI_MODULE_IMPORT=PASS\n');
  process.stdout.write('P96_ORIGINAL_PI_AI_STREAM_SIMPLE_EXPORT=PASS\n');
}
