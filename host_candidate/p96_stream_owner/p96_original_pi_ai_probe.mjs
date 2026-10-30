/**
 * Exact original package runtime import, not a production model call.
 * DSH first-party code imports the named OpenAI-completions.lazy subpath:
 * the pi-ai package root does NOT export streamSimple. Never forge one.
 */
import * as pi from '@earendil-works/pi-ai';
import * as completions from '@earendil-works/pi-ai/api/openai-completions.lazy';

if (Object.keys(pi).length===0) {
  process.stdout.write('P96_ORIGINAL_PI_AI_ROOT_IMPORT=FAIL\n');
  process.exitCode=2;
} else {
  process.stdout.write('P96_ORIGINAL_PI_AI_ROOT_IMPORT=PASS\n');
}
const api=completions.openAICompletionsApi;
const entries=Object.keys(completions).filter(x=>/openAI|completions|stream/i.test(x));
const direct=typeof api?.streamSimple==='function';
const stream=typeof api?.stream==='function';
process.stdout.write('P96_ORIGINAL_COMPLETIONS_SUBMODULE_EXPORTS='+JSON.stringify(entries)+'\n');
process.stdout.write('P96_ORIGINAL_OPENAI_COMPLETIONS_API='+(api ? 'PRESENT':'MISSING')+'\n');
process.stdout.write('P96_ORIGINAL_COMPLETIONS_STREAM_SIMPLE='+(direct?'PASS':'NOT_DIRECT')+'\n');
process.stdout.write('P96_ORIGINAL_COMPLETIONS_STREAM='+(stream?'PASS':'NOT_DIRECT')+'\n');
// Neither root nor submodule import proves a DSH Cordis session or UI.
// Reject if there is no callable model adapter at all.
if(!direct && !stream)process.exitCode=2;
